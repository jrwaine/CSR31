from typing import Optional
import argparse
import sys
import time
import socket

# Secret key
key = b"nO4GJN1UuaCRYiMovNUPWkHZJ30pd0BE1iht3LRwr68"
# ports and ips to use
PORT_SERVER = 3000
PORT_CLIENT = 3001
IP_SERVER = "localhost"
IP_CLIENT = "localhost"


class SocketServer:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((IP_CLIENT, PORT_CLIENT))
        self.s.listen()
        self.conn, self.addr = self.s.accept()

    def recv_msg(self) -> bytes:
        return self.conn.recv(1024)  # type: ignore


class SocketClient:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((IP_CLIENT, PORT_CLIENT))

    def send_msg(self, b: bytes):
        return self.s.send(b)


def cript_msg(b: str) -> bytes:
    if not b.isascii():
        raise ValueError("Invalid message. Only ASCII characters allowed")
    msg = b.encode("ascii")
    # TODO:
    return msg


def decrypt_msg(b: bytes) -> str:
    # TODO: decrypt
    b_dec = b
    try:
        msg = b_dec.decode("ascii")
        return msg
    except Exception as e:
        raise ValueError(f"Error decoding bytes {b!r}. Check keys") from e


def encode_msg(b: bytes) -> bytes:
    # TODO
    ...
    return b


def decode_msg(b: bytes) -> bytes:
    # TODO
    ...
    return b


def plot_signal(b: bytes):
    ...


def run_client():
    print("running client")
    my_socket = SocketClient()
    while True:
        time.sleep(0.1)
        msg_send = "teste"
        bytes_encrypted = cript_msg(msg_send)
        bytes_encoded = encode_msg(bytes_encrypted)
        print(f"sended message {bytes_encrypted}")
        my_socket.send_msg(bytes_encoded)


def run_server():
    print("running server")
    my_socket = SocketServer()
    while True:
        time.sleep(0.1)
        bytes_encoded = my_socket.recv_msg()
        if bytes_encoded == b"":
            continue

        bytes_decoded = decode_msg(bytes_encoded)
        bytes_decript = decrypt_msg(bytes_decoded)
        print(f"received message {bytes_decript}")


def main():
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument(
        "--mode", type=str, choices=["server", "client"], help="Mode to run code"
    )

    args = args_parser.parse_args(sys.argv[1:])

    if args.mode == "server":
        run_server()
    else:
        run_client()


if __name__ == "__main__":
    main()
