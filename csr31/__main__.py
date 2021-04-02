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

ZERO_TENSION = 0b01
POS_TENSION = 0b10
NEG_TENSION = 0b00


class SocketServer:
    def recv_msg(self) -> bytes:
        print("receiving....")
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.s.bind(("localhost", 3000))
            self.s.listen()
            self.conn, self.addr = self.s.accept()
            msg = self.conn.recv(1024)
            self.conn.close()
            return msg  # type: ignore
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
    if not b.isascii():
        raise ValueError("Invalid message. Only ASCII characters allowed")
    msg = b.encode("ascii")
    # TODO:
    return bytes([m ^ key for m in msg])


def decrypt_msg(b: bytes) -> str:
    # TODO: decrypt
    b_dec = bytes([bn ^ key for bn in b])
    try:
        msg = b_dec.decode("ascii")
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
    fig.savefig(f"csr31/plots/{msg}_{side}.png")
    return fig


def crete_server_interface(my_socket: SocketServer):
    global PORT_SERVER, IP_SERVER
    window = tkinter.Tk()
    window.title(f"Server")
    window.geometry("720x720")

    def draw_signal(signal: bytes, msg: str):
        figure = plot_signal(signal, msg, "server")
        canvas = FigureCanvasTkAgg(figure, window)
        canvas.get_tk_widget().grid(column=0, row=2)
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
            thread.start()

        if thread.is_alive():
            window.after(100, handle_msgs, thread)
        else:
            try:
                bytes_encoded = thread.msg
                bytes_decoded = decode_msg(bytes_encoded)
                msg_decript = decrypt_msg(bytes_decoded)
                print(msg_decript)
                draw_signal(bytes_encoded, msg_decript)
                print(f"received message {msg_decript}")
            except Exception as e:
                print("error", e)
            window.after(100, handle_msgs)

    window.after(100, handle_msgs)
    window.mainloop()


def crete_client_interface(my_socket: SocketClient):
    global PORT_SERVER
    window = tkinter.Tk()
    window.title(f"Client")
    window.geometry("720x720")

    lbl = tkinter.Label(window, text="Server IP")
    lbl.grid(column=0, row=0)
    msg_ip = tkinter.Entry(window, width=30)
    msg_ip.grid(column=0, row=1)

    lbl = tkinter.Label(window, text="Port")
    lbl.grid(column=1, row=0)
    msg_port = tkinter.Entry(window, width=10)
    msg_port.grid(column=1, row=1)

    lbl = tkinter.Label(window, text="Message to send")
    lbl.grid(column=2, row=0)
    msg_entry = tkinter.Entry(window, width=20)
    msg_entry.grid(column=2, row=1)

    def send_msg():
        msg_to_send = msg_entry.get()
        if len(msg_to_send) == 0:
            return
        try:
            port = int(msg_port.get())
            ip = msg_ip.get()
        except:
            return

        try:
            bytes_encrypted = cript_msg(msg_to_send)
            bytes_encoded = encode_msg(bytes_encrypted)
            my_socket.send_msg(bytes_encoded, ip, port)
        except Exception as e:
            tkinter.messagebox.showerror(title="Error", message=f"Exception: {str(e)}")
        else:
            figure = plot_signal(bytes_encoded, msg_to_send, "client")
            canvas = FigureCanvasTkAgg(figure, window)
            canvas.get_tk_widget().grid(column=2, row=3)
            canvas.draw()
            msg_box = tkinter.messagebox.showinfo(
                title="Info", message=f"Sended {msg_to_send}"
            )

    btn_send = tkinter.Button(window, text="Send message", command=send_msg)
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
