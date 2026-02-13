import tkinter as tk
from tkinter import scrolledtext
import socket
import threading
import json
import os

from encrypt import generate_keys, encrypt_message, decrypt_message, serialize_public_key
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1'
PORT = 8000

private_key, public_key = generate_keys()


class ChatClient(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Secure Chat Application")
        self.geometry("550x650")
        self.configure(bg="#3D3737")

        # Header
        self.header = tk.Label(self, text="Secure Chat Application", font=("Times New Roman", 18, "bold"), fg="#31c726", bg="#3D3737")
        self.header.pack(pady=(10, 5))

        # Chat area (ScrolledText)
        self.chat_text = scrolledtext.ScrolledText(self, width=60, height=25, bg="#121212", fg="#ffffff", wrap='word', state='disabled', bd=0)
        self.chat_text.pack(pady=(0, 10), padx=10, fill='both', expand=True)

        # message tags
        self.chat_text.tag_config('me', foreground='#ffffff', background="#096462", lmargin1=10, lmargin2=10, rmargin=10, spacing3=5, justify='right', font=("Times New Roman", 12))
        self.chat_text.tag_config('other', foreground='#ffffff', background='#2c2c2c', lmargin1=10, lmargin2=10, rmargin=10, spacing3=5, justify='left', font=("Times New Roman", 12))
        self.chat_text.tag_config('system', foreground='#ffffff', background='#1e1e1e', justify='center')

        # ===== Message Input & Send Button =====
        self.bottom_frame = tk.Frame(self, bg="#1e1e1e")
        self.bottom_frame.pack(fill='x', padx=10, pady=5)

        self.msg_entry = tk.Entry(self.bottom_frame, width=50, bg="#2c2c2c", fg="#ffffff", insertbackground="#ffffff")
        self.msg_entry.pack(side='left', padx=(10, 5), pady=10, ipady=4)

        self.send_button = tk.Button(self.bottom_frame, text="Send", command=self.send_message, bg="#8e44ad", fg="#ffffff", activebackground="#732d91", bd=0)
        self.send_button.pack(side='left', padx=5, pady=10)

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))

        serialized_pub = serialize_public_key(public_key)
        self.client_socket.send(serialized_pub.encode())

        self.clients_public_keys = {}

        self.running = True
        thread = threading.Thread(target=self.receive_messages)
        thread.daemon = True
        thread.start()

    def send_message(self):
        message = self.msg_entry.get()
        if message.strip() == "":
            return

        for addr, pub_key in self.clients_public_keys.items():
            try:
                encrypted_msg = encrypt_message(pub_key, message)
                self.client_socket.send(encrypted_msg)
                self.add_message_bubble(message, sender='me')
            except Exception as e:
                self.add_message_bubble(f"Error sending to {addr}: {e}", sender='system')

        self.msg_entry.delete(0, 'end')

    def receive_messages(self):
        while self.running:
            try:
                data = self.client_socket.recv(8192)
                if not data:
                    break

                try:
                    decrypted_msg = decrypt_message(private_key, data)
                    self.add_message_bubble(decrypted_msg, sender='other')
                except Exception:
                    try:
                        keys_dict = json.loads(data.decode())
                        self.update_clients_public_keys(keys_dict)
                    except:
                        pass
            except Exception as e:
                self.add_message_bubble(f"Error: {e}", sender='system')
                self.running = False
                break

    def update_clients_public_keys(self, keys_dict):
        self.clients_public_keys.clear()
        for addr, key_str in keys_dict.items():
            if addr != str(self.client_socket.getsockname()):
                pub_key = serialization.load_pem_public_key(key_str.encode())
                self.clients_public_keys[addr] = pub_key
        # keys updated silently
    def add_message_bubble(self, text, sender='other'):
        self.chat_text.configure(state='normal')
        if sender == 'me':
            display = f"You: {text}\n"
            tag = 'me'
        elif sender == 'system':
            display = f"{text}\n"
            tag = 'system'
        else:
            display = f"Other: {text}\n"
            tag = 'other'

        self.chat_text.insert('end', display, tag)
        self.chat_text.see('end')
        self.chat_text.configure(state='disabled')


    def on_closing(self):
        self.running = False
        self.client_socket.close()
        self.destroy()


if __name__ == "__main__":
    app = ChatClient()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
