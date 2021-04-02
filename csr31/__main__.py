from typing import Optional
import argparse
import sys
import time
import socket
import tkinter
import threading

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# Secret key
key = 0xFE
PORT_SERVER = 3000

ZERO_TENSION = 0b01
POS_TENSION = 0b10
NEG_TENSION = 0b00

TEST_VAL = bytes([0b010010])
ONLY_TEST = False
CRYPT = True
ENCODE = "utf-8"


class SocketServer:
    def recv_msg(self) -> bytes:
        print("receiving....")
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.s.bind(("localhost", PORT_SERVER))
            self.s.listen()
            self.conn, self.addr = self.s.accept()
            msg = self.conn.recv(1024)
            self.conn.close()
            return msg
        except:
            return b""


class SocketClient:
    def send_msg(self, b: bytes, ip: str, port: int):
        print(ip, port)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((ip, port))
        self.s.send(b)
        self.s.close()


def cript_msg(b: str) -> bytes:
    global CRYPT, ENCODE
    # if not b.isascii():
    #     raise ValueError("Invalid message. Only UTF-8 characters allowed")
    msg = b.encode(ENCODE)
    if CRYPT:
        return bytes([m ^ key for m in msg])
    return msg


def decrypt_msg(b: bytes) -> str:
    global CRYPT, ENCODE
    b_dec = b
    if CRYPT:
        b_dec = bytes([bn ^ key for bn in b])
    try:
        msg = b_dec.decode(ENCODE)
        return msg
    except Exception as e:
        raise ValueError(f"Error decoding bytes {b!r}. Check keys") from e


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


def get_byte_bits(b: int) -> str:
    return "0b" + "".join([str((b >> i) & 0b1) for i in range(7, -1, -1)])


def get_message_bits(b: bytes) -> str:
    return " ".join([get_byte_bits(byte) for byte in b])


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
    b_plot = bytearray(b)
    b_plot.append(b_plot[-1])
    pos = list(range(len(b_plot)))
    fig = Figure()
    a = fig.add_subplot()
    a.plot(pos, b_plot, drawstyle="steps-post")
    a.set_yticks([0, 1, 2])
    a.set_yticklabels(["-V", 0, "+V"])
    a.set_title(f"signal for '{msg}'")
    # fig.savefig(f"csr31/plots/{msg}_{side}.png")
    return fig


def crete_server_interface(my_socket: SocketServer):
    global PORT_SERVER, IP_SERVER
    window = tkinter.Tk()
    window.title(f"Server")
    window.geometry("720x720")

    lbl = tkinter.Label(window, text=f"Running server on port {PORT_SERVER}")
    lbl.grid(column=0, row=0, columnspan=2)

    msg_text = tkinter.Label(window, text=f"Message text:")
    msg_text.grid(column=0, row=1)
    msg_text_res = tkinter.Label(window, text=f"")
    msg_text_res.grid(column=1, row=1)

    msg_binary = tkinter.Label(window, text=f"Binary message (LSB right):")
    msg_binary.grid(column=0, row=2)
    msg_binary_res = tkinter.Label(window, text=f"")
    msg_binary_res.grid(column=1, row=2)

    msg_binary_decrypt = tkinter.Label(
        window, text=f"Binary decrypted message (LSB right):"
    )
    msg_binary_decrypt.grid(column=0, row=3)
    msg_binary_decrypt_res = tkinter.Label(window, text=f"")
    msg_binary_decrypt_res.grid(column=1, row=3)

    def draw_signal(signal: bytes, msg: str):
        figure = plot_signal(signal, msg, "server")
        canvas = FigureCanvasTkAgg(figure, window)
        canvas.get_tk_widget().grid(column=0, row=4, columnspan=2)
        canvas.draw()
        msg_box = tkinter.messagebox.showinfo(title="Info", message=f"Received '{msg}'")

    class AsyncRecvMsg(threading.Thread):
        def __init__(self, socket: SocketServer):
            super().__init__()
            self.socket = socket

        def run(self):
            response = self.socket.recv_msg()
            while response == b"":
                response = self.socket.recv_msg()
            self.msg = response

    def handle_msgs(thread=None):
        if thread is None:
            thread = AsyncRecvMsg(my_socket)
            thread.daemon = True
            thread.start()

        if thread.is_alive():
            window.after(100, handle_msgs, thread)
        else:
            try:
                bytes_encoded = thread.msg
                bytes_decoded = decode_msg(bytes_encoded)
                msg_binary_res.config(text=get_message_bits(bytes_decoded))
                try:
                    msg_decript = decrypt_msg(bytes_decoded)
                    msg_binary_decrypt_res.config(
                        text=get_message_bits(bytes(msg_decript.encode(ENCODE)))
                    )
                except:
                    msg_decript = "**unable to decript it**"
                msg_text_res.config(text=msg_decript)
                print(msg_decript)
                try:
                    draw_signal(bytes_encoded, msg_decript)
                except:
                    draw_signal(bytes_encoded, "**can't print msg**")
                print(f"received message {msg_decript}")
            except Exception as e:
                print("error", e)
            window.after(100, handle_msgs)

    window.after(100, handle_msgs)
    window.mainloop()


def crete_client_interface(my_socket: SocketClient):
    global PORT_SERVER, ONLY_TEST
    window = tkinter.Tk()
    window.title(f"Client")
    window.geometry("720x720")

    lbl = tkinter.Label(window, text="Server IP")
    lbl.grid(column=0, row=0)
    msg_ip = tkinter.Entry(window, width=30)
    msg_ip.grid(column=0, row=1)
    msg_ip.insert(0, "localhost")

    lbl = tkinter.Label(window, text="Port")
    lbl.grid(column=1, row=0)
    msg_port = tkinter.Entry(window, width=10)
    msg_port.grid(column=1, row=1)
    msg_port.insert(0, "3000")

    if not ONLY_TEST:
        lbl = tkinter.Label(window, text="Message to send")
        lbl.grid(column=2, row=0)
        msg_entry = tkinter.Entry(window, width=20)
        msg_entry.grid(column=2, row=1)

    msg_text = tkinter.Label(window, text=f"Message text:")
    msg_text.grid(column=0, row=3)
    msg_text_res = tkinter.Label(window, text=f"")
    msg_text_res.grid(column=1, row=3)

    msg_binary = tkinter.Label(window, text=f"Binary message (LSB right):")
    msg_binary.grid(column=0, row=4)
    msg_binary_res = tkinter.Label(window, text=f"")
    msg_binary_res.grid(column=1, row=4)

    msg_binary_decrypt = tkinter.Label(
        window, text=f"Binary encrypter message (LSB right):"
    )
    msg_binary_decrypt.grid(column=0, row=5)
    msg_binary_encrypt_res = tkinter.Label(window, text=f"")
    msg_binary_encrypt_res.grid(column=1, row=5)

    def send_msg():
        if not ONLY_TEST:
            msg_to_send = msg_entry.get()
            if len(msg_to_send) == 0:
                return
        else:
            msg_to_send = TEST_VAL.decode(ENCODE)

        try:
            port = int(msg_port.get())
            ip = msg_ip.get()
        except:
            tkinter.messagebox.showerror(title="Error", message=f"Exception: {str(e)}")

        try:
            # use TEST_VAL for tests
            bytes_encrypted = TEST_VAL
            bytes_encrypted = cript_msg(msg_to_send)

            msg_text_res.config(text=msg_to_send)
            msg_binary_res.config(
                text=get_message_bits(bytes(msg_to_send.encode(ENCODE)))
            )
            msg_binary_encrypt_res.config(text=get_message_bits(bytes_encrypted))
            bytes_encoded = encode_msg(bytes_encrypted)
            my_socket.send_msg(bytes_encoded, ip, port)
        except Exception as e:
            tkinter.messagebox.showerror(title="Error", message=f"Exception: {str(e)}")
        else:
            figure = plot_signal(bytes_encoded, msg_to_send, "client")
            canvas = FigureCanvasTkAgg(figure, window)
            canvas.get_tk_widget().grid(column=0, row=6, columnspan=3)
            canvas.draw()
            msg_box = tkinter.messagebox.showinfo(
                title="Info", message=f"Sended {msg_to_send}"
            )

    if not ONLY_TEST:
        btn_send = tkinter.Button(window, text="Send message", command=send_msg)
    else:
        btn_send = tkinter.Button(window, text="Send test message", command=send_msg)

    btn_send.grid(column=0, row=2)

    window.mainloop()


def run_client():
    print("running client")
    my_socket = SocketClient()
    crete_client_interface(my_socket)


def run_server():
    print("running server")
    my_socket = SocketServer()
    crete_server_interface(my_socket)


def main():
    global CRYPT, ONLY_TEST
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument(
        "-m", "--mode", type=str, choices=["server", "client"], help="Mode to run code"
    )
    args_parser.add_argument(
        "-nc", "--no-crypt", action="store_true", help="Not use cryptography"
    )
    args_parser.add_argument(
        "-t", "--test-only", action="store_true", help="Run only test value"
    )

    args = args_parser.parse_args(sys.argv[1:])
    if args.no_crypt:
        CRYPT = False
    if args.test_only:
        ONLY_TEST = True
        CRYPT = False

    if args.mode == "server":
        run_server()
    else:
        run_client()


if __name__ == "__main__":
    main()
