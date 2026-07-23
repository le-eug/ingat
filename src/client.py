import os
import socket
import sys
import threading
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from cryptography.exceptions import InvalidTag

from crypto import x25519, hkdf, cipher, handshake
from . import wire

HOST = "127.0.0.1"
PORT = 6767
REJECT_CODE = b"REJECTED"

# Fixed, public constants for the HKDF step -- not secret. They just
# bind derived keys to this protocol/version so they can't collide with
# keys derived the same way for some unrelated purpose.
HKDF_SALT = b"ingat-x25519-hkdf-salt-v1"
HKDF_INFO = b"ingat handshake v1"

# --plaintext talks the original unencrypted, newline-delimited protocol
# (for an eavesdropping demo baseline) instead of the AES-256-GCM
# protocol below. Must match the server's mode.
PLAINTEXT_MODE = "--plaintext" in sys.argv


class Session:
    """This client's key-exchange state with its one peer.

    Mutated from the recv thread (on PEER_READY / HELLO_UNAUTH /
    PEER_LEFT) and read from the main thread (when sending a chat
    message), so all access goes through `lock`.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.peer_username: str | None = None
        self.eph_priv: bytes | None = None
        self.session_key: bytes | None = None


def start_handshake(s: socket.socket, session: Session, peer_username: str):
    """A peer is now present: generate a fresh X25519 ephemeral keypair
    for this pairing and send our half of the (unauthenticated) key
    exchange. Unauthenticated: nothing here proves the HELLO_UNAUTH we
    receive back actually came from `peer_username` rather than an
    on-path attacker -- see PROTOCOL.md and src/mitm.py.
    """
    eph_priv, eph_pub = x25519.generate_keypair()
    with session.lock:
        session.peer_username = peer_username
        session.eph_priv = eph_priv
        session.session_key = None
    print(f"\n[{peer_username} connected -- starting key exchange (unauthenticated)]")
    s.sendall(handshake.pack_hello_unauth(eph_pub))


def complete_handshake(session: Session, their_eph_pub: bytes):
    """Peer's HELLO_UNAUTH arrived: derive the AES-256-GCM session key via
    X25519 ECDH followed by HKDF-SHA256."""
    with session.lock:
        if session.eph_priv is None:
            print("\n[received HELLO_UNAUTH with no handshake in progress, ignoring]")
            return
        shared = x25519.shared_secret(session.eph_priv, their_eph_pub)
        session.session_key = hkdf.derive_key(
            shared, salt=HKDF_SALT, info=HKDF_INFO, length=cipher.KEY_LEN
        )
        peer = session.peer_username
    print(f"\n[secure channel established with {peer}]")


def handle_peer_left(session: Session):
    with session.lock:
        peer = session.peer_username
        session.peer_username = None
        session.eph_priv = None
        session.session_key = None
    print(f"\n[{peer or 'peer'} disconnected -- secure channel closed]")


def handle_payload(s: socket.socket, session: Session, payload: bytes):
    if not payload:
        return
    msg_type = payload[0]

    if msg_type == wire.MSG_TYPE_PEER_READY:
        start_handshake(s, session, wire.unpack_peer_ready(payload))

    elif msg_type == handshake.MSG_TYPE_HELLO_UNAUTH:
        # unpack_hello_unauth expects a full framed message; `payload` has
        # already had its length prefix stripped by wire.FrameBuffer, so
        # re-wrap it rather than duplicating handshake.py's parsing here.
        their_eph_pub = handshake.unpack_hello_unauth(handshake.pack_frame(payload))
        complete_handshake(session, their_eph_pub)

    elif msg_type == wire.MSG_TYPE_PEER_LEFT:
        handle_peer_left(session)

    elif msg_type == wire.MSG_TYPE_CHAT:
        nonce, ct = wire.unpack_chat(payload)
        with session.lock:
            key = session.session_key
            peer = session.peer_username
        if key is None:
            print("\n[received an encrypted message but have no session key -- dropping]")
            return
        try:
            plaintext = cipher.decrypt(key, nonce, ct)
        except InvalidTag:
            print(f"\n[message from {peer} failed authentication -- discarded]")
            return
        print(f"\n{peer}: {plaintext.decode(errors='replace')}")

    else:
        print(f"\n[unknown frame type 0x{msg_type:02x}, ignoring]")


def recv_loop_plaintext(s: socket.socket):
    while True:
        data = s.recv(4096)
        if not data:
            print("\nServer closed the connection.")
            os._exit(1)
        print(f"\n{data.decode(errors='replace')}")


def recv_loop_encrypted(s: socket.socket, session: Session):
    frames = wire.FrameBuffer()
    while True:
        data = s.recv(4096)
        if not data:
            print("\nServer closed the connection.")
            os._exit(1)
        for payload in frames.feed(data):
            handle_payload(s, session, payload)


def main():
    session = Session()  # unused in plaintext mode

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print("Connecting to server...")
        s.connect((HOST, PORT))

        # Check if connection is rejected first
        data = s.recv(4096)
        if data == REJECT_CODE:
            print("Server has reached max amt of clients. Connection rejected. ")
            sys.exit()
        print("Connected!")
        print(f"Mode: {'PLAINTEXT (unencrypted)' if PLAINTEXT_MODE else 'ENCRYPTED (AES-256-GCM)'}")

        # Prompt for username
        username = input("Enter your name: ")
        if PLAINTEXT_MODE:
            s.sendall(username.encode())
        else:
            s.sendall(wire.pack_username(username))

        print(f"Hello, {username}!")
        if PLAINTEXT_MODE:
            print("Message away! (unencrypted -- visible to anyone on the wire)\n")
            t = threading.Thread(target=recv_loop_plaintext, args=(s,), daemon=True)
        else:
            print("Waiting for a peer so a secure channel can be established...\n")
            t = threading.Thread(target=recv_loop_encrypted, args=(s, session), daemon=True)
        t.start()

        try:
            prompt_session = PromptSession[str]()
            with patch_stdout():
                while True:
                    message = prompt_session.prompt("> ")
                    if not message:
                        continue

                    if PLAINTEXT_MODE:
                        s.sendall(message.encode() + b"\n")
                        continue

                    with session.lock:
                        key = session.session_key
                    if key is None:
                        print("[no secure channel yet -- message not sent]")
                        continue
                    nonce, ct = cipher.encrypt(key, message.encode())
                    s.sendall(wire.pack_chat(nonce, ct))
        except (KeyboardInterrupt, EOFError):
            print("\nBye!")


if __name__ == "__main__":
    main()
