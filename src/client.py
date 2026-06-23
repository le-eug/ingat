import socket

HOST = "127.0.0.1"
PORT = 6767

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    while True:
        message = input("> ")
        s.sendall(message.encode() + b"\n")
