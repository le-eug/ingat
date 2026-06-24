import socket
import sys
import threading
from prompt_toolkit import PromptSession 
from prompt_toolkit.patch_stdout import patch_stdout 

HOST = "127.0.0.1"
PORT = 6767
REJECT_CODE = b"REJECTED"

# --- Funcs ---
def recv_loop(s: socket.socket):
    while True:
        data = s.recv(4096)
        if not data:
            print("\nServer closed the connection.")
            sys.exit()
        print(f"{data.decode()}")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # Check if connection is rejected first
        data = s.recv(4096)
        if data == REJECT_CODE:
            print("Server has reached max amt of clients. Connection rejected. ")
            sys.exit()

        # Prompt for username
        username = input(f"Enter your name: ")
        s.sendall(username.encode())

        # Begin message loop
        print(f"Hello, {username}!")
        print(f"Message away!\n")

        t = threading.Thread(target=recv_loop, args=(s,), daemon=True)
        t.start()

        try:
            session = PromptSession[str]()
            with patch_stdout():
                while True:
                    message = session.prompt("> ")
                    s.sendall(message.encode() + b"\n")
        except (KeyboardInterrupt, EOFError):
            print("\nBye!")


if __name__ == "__main__":
    main()
