import socket
import selectors
import sys
from typing import TypedDict

from crypto import handshake
from . import wire


class ClientState(TypedDict):
    addr: str
    username: str
    buf: bytearray            # plaintext mode: raw bytes awaiting a newline
    frames: wire.FrameBuffer  # encrypted mode: raw bytes awaiting complete frames


HOST = "127.0.0.1"
PORT = 6767
MAX_CLIENTS = 2
ACCEPT_CODE = b"ACCEPTED"
REJECT_CODE = b"REJECTED"

# --plaintext runs the original unencrypted, newline-delimited relay --
# a baseline for an eavesdropping demo. Default is the AES-256-GCM
# relay this project is actually built around. The server and every
# client must all be started with the same mode; they speak different,
# incompatible wire formats.
PLAINTEXT_MODE = "--plaintext" in sys.argv

# Frame types the server recognizes for logging only, in encrypted mode.
# It never inspects anything past the type byte, and never decrypts CHAT
# payloads -- it is a dumb relay by design, so it cannot read message
# content even if compromised. That's the property end-to-end encryption
# is for (and exactly what --plaintext mode disables, for comparison).
_KNOWN_TYPES = {
    handshake.MSG_TYPE_HELLO_UNAUTH: "HELLO_UNAUTH",
    handshake.MSG_TYPE_HELLO_AUTH: "HELLO_AUTH",
    wire.MSG_TYPE_CHAT: "CHAT",
}


sel: selectors.BaseSelector = selectors.DefaultSelector()
clients: dict[socket.socket, ClientState] = {}


def recv_username(conn: socket.socket) -> str:
    """Blocking read of exactly one username. Only used right after
    accept(), before the socket is handed off to the non-blocking
    selector loop, so a blocking read here is fine.
    """
    if PLAINTEXT_MODE:
        data = conn.recv(4096)
        if not data:
            raise ConnectionError("client disconnected before sending username")
        return data.decode()

    buf = bytearray()
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("client disconnected before sending username")
        buf += chunk
        try:
            payload, remainder = handshake.unpack_frame(bytes(buf))
        except handshake.FrameError:
            continue
        if remainder:
            raise ConnectionError("unexpected data after username frame")
        return wire.unpack_username(payload)


def accept(server_sock: socket.socket):
    conn, addr = server_sock.accept()
    client_label = f"{addr[0]}:{addr[1]}"

    if len(clients) >= MAX_CLIENTS:
        conn.sendall(REJECT_CODE)
        print(f"Rejecting {client_label}. Not accepting any further clients.")
        conn.close()
        return

    print(f"{client_label} connected")
    conn.setblocking(True)
    conn.sendall(ACCEPT_CODE)

    try:
        username = recv_username(conn)
    except (ConnectionError, handshake.FrameError) as e:
        print(f"Dropping {client_label}: {e}")
        conn.close()
        return

    clients[conn] = {
        "addr": client_label,
        "username": username,
        "buf": bytearray(),
        "frames": wire.FrameBuffer(),
    }
    print(f"{username} ({client_label}) joined")

    if not PLAINTEXT_MODE:
        # If a peer is already connected, tell both sides so each can
        # start its X25519 handshake with the other.
        others = [c for c in clients if c is not conn]
        if others:
            peer_conn = others[0]
            peer_username = clients[peer_conn]["username"]
            conn.sendall(wire.pack_peer_ready(peer_username))
            peer_conn.sendall(wire.pack_peer_ready(username))

    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, pass_thru)


def pass_thru(conn: socket.socket):
    data = conn.recv(4096)
    if not data:
        drop(conn)
        return

    if PLAINTEXT_MODE:
        pass_thru_plaintext(conn, data)
    else:
        pass_thru_encrypted(conn, data)


def pass_thru_plaintext(conn: socket.socket, data: bytes):
    state = clients[conn]
    state["buf"] += data
    while b"\n" in state["buf"]:
        idx = state["buf"].index(b"\n")
        line = bytes(state["buf"][:idx])
        del state["buf"][:idx + 1]
        text = line.decode(errors="replace")
        print(f"{state['username']} ({state['addr']}) sends: {text}")
        for other_conn in clients:
            if other_conn is not conn:
                other_conn.sendall(f"{state['username']}: {text}".encode())


def pass_thru_encrypted(conn: socket.socket, data: bytes):
    state = clients[conn]
    for payload in state["frames"].feed(data):
        relay(conn, payload)


def relay(conn: socket.socket, payload: bytes):
    sender = clients[conn]
    msg_type = payload[0] if payload else None
    label = _KNOWN_TYPES.get(msg_type, f"0x{msg_type:02x}" if msg_type is not None else "EMPTY")

    print(f"{sender['username']} ({sender['addr']}) sends: {payload.hex()}")

    for other_conn in clients:
        if other_conn is not conn:
            other_conn.sendall(handshake.pack_frame(payload))


def drop(conn: socket.socket):
    if conn not in clients:
        return
    state = clients[conn]
    print(f"{state['username']} ({state['addr']}) disconnected")
    sel.unregister(conn)
    conn.close()
    del clients[conn]

    if not PLAINTEXT_MODE:
        # Tell any remaining peer so it discards its now-orphaned session key.
        for other_conn in clients:
            other_conn.sendall(wire.pack_peer_left())


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        server.setblocking(False)
        sel.register(server, selectors.EVENT_READ, accept)
        mode = "PLAINTEXT (unencrypted -- eavesdropping demo)" if PLAINTEXT_MODE else "ENCRYPTED (AES-256-GCM)"
        print(f"Server listening on {HOST}:{PORT} [{mode}]")

        while True:
            for key, _ in sel.select():
                callback = key.data       # accept or pass_thru
                callback(key.fileobj)


if __name__ == "__main__":
    main()
