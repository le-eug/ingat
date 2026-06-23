import socket
import sys

HOST = "127.0.0.1"
PORT = 6767
REJECT_CODE = b"REJECTED"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    id = f"{s.getsockname()[0]}:{s.getsockname()[1]}"

    print(f"Hello, {id}!")
    print(f"Message away!\n")
    while True:
        data = s.recv(4096)

        if data == REJECT_CODE:
            print("Server has reached max amt of clients. Connection rejected. ")
            sys.exit(1)

        message = input(f"> ")
        s.sendall(message.encode() + b"\n")
