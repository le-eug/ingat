# --- Imports ---
import socket
import selectors
from typing import TypedDict


# --- Types ---
class ClientState(TypedDict):
    addr: str
    buf: bytearray
    username: str


# --- Consts ---
HOST = "127.0.0.1"
PORT = 6767
MAX_CLIENTS = 2
ACCEPT_CODE = b"ACCEPTED"
REJECT_CODE = b"REJECTED"


# --- Globals ---
sel: selectors.BaseSelector = selectors.DefaultSelector()
clients: dict[socket.socket, ClientState] = {}


# --- Funcs ---
def accept(server_sock: socket.socket):
    conn, addr = server_sock.accept()
    client = f"{addr[0]}:{addr[1]}"

    if len(clients) == 2:
        conn.sendall(REJECT_CODE)
        print(f"Rejecting {client}. Not accepting any further clients.")
        conn.close()
        return

    print(f"{client} connected")
    conn.setblocking(True)
    conn.sendall(ACCEPT_CODE)

    # Read username
    data = conn.recv(4096)
    if not data:
        # do something
        pass
    username = data.decode()

    clients[conn] = {"addr": client, "buf": bytearray(), "username": username}

    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, pass_thru)


def pass_thru(conn: socket.socket):
    data = conn.recv(4096)
    if not data:
        drop(conn)
        return

    state = clients[conn]
    state["buf"] += data
    while b"\n" in state["buf"]:
        idx = state["buf"].index(b"\n")
        line = bytes(state["buf"][:idx])
        del state["buf"][:idx + 1]
        print(f"{clients[conn]['username']} ({clients[conn]['addr']}) sends: {line.decode(errors='replace')}")
        relay(conn, line)


def relay(conn: socket.socket, msg: bytes):
    for client in clients:
        if client is not conn:
            client.sendall(f"{clients[conn]["username"]}: {msg.decode()}".encode())


def drop(conn: socket.socket):
    if conn not in clients:
        return
    print(f"{clients[conn]['username']} ({clients[conn]['addr']}) disconnected")
    sel.unregister(conn)
    conn.close()
    del clients[conn]


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        server.setblocking(False)
        sel.register(server, selectors.EVENT_READ, accept)
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            for key, _ in sel.select():
                callback = key.data       # accept or pass_thru
                callback(key.fileobj)


if __name__ == "__main__":
    main()
