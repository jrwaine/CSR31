from typing import Optional
import argparse
import sys
import time
import socket

import matplotlib.pyplot as plt

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


ZERO_TENSION = 0b01
POS_TENSION = 0b10
NEG_TENSION = 0b00


def encode_msg(b: bytes) -> bytearray:
    # TODO
    positive_1 = True
    bytes_encoded = bytearray()
    for byte in b:
        bits = [(byte >> n) & 0b1 for n in range(8)]
        for bit in bits:
            if bit == 0:
                bytes_encoded.append(ZERO_TENSION)
            else:
                bytes_encoded.append(POS_TENSION if positive_1 else NEG_TENSION)
                positive_1 = not positive_1
    return bytes_encoded


def decode_msg(b: bytes) -> bytes:
    positive_1 = True
    bytes_decoded = bytearray()
    curr_byte, n_bits = 0b0, 0
    for byte in b:
        if byte == ZERO_TENSION:
            curr_byte += 0 << n_bits
        else:
            if byte == POS_TENSION:
                if positive_1:
                    curr_byte += 0b1 << n_bits
                else:
                    raise ValueError(
                        "Decoding error. Negative tension encountered when it should be positive"
                    )
            elif byte == NEG_TENSION:
                if not positive_1:
                    curr_byte += 0b1 << n_bits
                else:
                    raise ValueError(
                        "Decoding error. Positive tension encountered when it should be negative"
                    )
            positive_1 = not positive_1

        n_bits += 1
        if n_bits == 8:
            bytes_decoded.append(curr_byte)
            curr_byte, n_bits = 0b0, 0

    return bytes(bytes_decoded)


def plot_signal(b: bytes, msg: str, side: str):
    plt.cla(), plt.clf()
    b_plot = bytearray(b)
    b_plot.append(b_plot[-1])
    pos = list(range(len(b_plot)))
    plt.plot(pos, b_plot, drawstyle="steps-post")
    plt.yticks([0, 1, 2], ["-V", 0, "+V"])
    plt.title(f"signal for '{msg}'")
    plt.savefig(f"csr31/plots/{msg}_{side}.png")


def run_client():
    print("running client")
    my_socket = SocketClient()
    while True:
        time.sleep(0.1)
        msg_send = input("Input your message: ")
        bytes_encrypted = cript_msg(msg_send)
        bytes_encoded = encode_msg(bytes_encrypted)
        my_socket.send_msg(bytes_encoded)
        plot_signal(bytes_encoded, msg_send, "client")


def run_server():
    print("running server")
    my_socket = SocketServer()
    while True:
        time.sleep(0.1)
        bytes_encoded = my_socket.recv_msg()
        if bytes_encoded == b"":
            continue
        bytes_decoded = decode_msg(bytes_encoded)
        msg_decript = decrypt_msg(bytes_decoded)
        plot_signal(bytes_encoded, msg_decript, "server")
        print(f"received message {msg_decript}")


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
