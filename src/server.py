import socket
import selectors

HOST = "127.0.0.1"
PORT = 6767

sel = selectors.DefaultSelector()
clients = {}  # sock -> {"addr": str, "buf": bytearray}


def accept(server_sock):
    conn, addr = server_sock.accept()
    conn.setblocking(False)
    client = f"{addr[0]}:{addr[1]}"
    print(f"{client} connected")
    clients[conn] = {"addr": client, "buf": bytearray()}
    sel.register(conn, selectors.EVENT_READ, read)


def read(conn):
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
        print(f"{state['addr']} sends: {line.decode(errors='replace')}")


def drop(conn):
    if conn not in clients:
        return
    print(f"{clients[conn]['addr']} disconnected")
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
                callback = key.data       # accept or read
                callback(key.fileobj)


if __name__ == "__main__":
    main()
