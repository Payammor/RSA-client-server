import sys
import socket
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QLineEdit, QVBoxLayout, QWidget, QLabel
from threading import Thread
from RSA import generate_key_pair, exchange_keys, encrypt, decrypt

class ClientGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Secure Chat Client")
        self.setGeometry(100, 100, 600, 400)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.chat_text = QTextEdit(self)
        self.server_ip_label = QLabel("Server IP:", self)
        self.server_ip_input = QLineEdit(self)
        self.server_port_label = QLabel("Server Port:", self)
        self.server_port_input = QLineEdit(self)
        self.connect_button = QPushButton("Connect", self)
        self.message_input = QLineEdit(self)
        self.send_button = QPushButton("Send", self)

        self.connected = False

        layout = QVBoxLayout(self.central_widget)
        layout.addWidget(self.chat_text)
        layout.addWidget(self.server_ip_label)
        layout.addWidget(self.server_ip_input)
        layout.addWidget(self.server_port_label)
        layout.addWidget(self.server_port_input)
        layout.addWidget(self.connect_button)
        layout.addWidget(self.message_input)
        layout.addWidget(self.send_button)

        self.connect_button.clicked.connect(self.connect_to_server)
        self.send_button.clicked.connect(self.send_message)

        self.client_socket = None
        self.server_public_key_pem = None
        self.client_private_key_pem = None

    def connect_to_server(self):
        if not self.connected:
            server_ip = self.server_ip_input.text()
            server_port = int(self.server_port_input.text())

            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((server_ip, server_port))

                # Generate and exchange keys with the server
                self.client_private_key_pem, self.server_public_key_pem = exchange_keys(self.client_socket)

                self.connected = True
                self.chat_text.append("Connected to the server.")

                # Confirm secure connection and key exchange
                self.chat_text.append("Secure connection established.")
                self.chat_text.append("Key exchange confirmed.")

                # Start a thread for receiving messages from the server
                receive_thread = Thread(target=self.receive_messages)
                receive_thread.daemon = True
                receive_thread.start()

            except Exception as e:
                self.chat_text.append(f"Connection error: {e}")
        else:
            self.chat_text.append("Already connected to the server.")


    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    break

                # Decrypt and display the received message
                decrypted_data = decrypt(self.client_private_key_pem, data)
                self.chat_text.append(f"Server: {decrypted_data.decode()}")

            except Exception as e:
                self.chat_text.append(f"Receive error: {e}")
                break

    def send_message(self):
        if self.connected:
            message = self.message_input.text()

            if message:
                # Encrypt and send the message to the server
                encrypted_message = encrypt(self.server_public_key_pem, message)

                if encrypted_message is not None:
                    self.client_socket.sendall(encrypted_message)
                    self.chat_text.append(f"You: {message}")
                    self.message_input.clear()
                else:
                    self.chat_text.append("Encryption failed. Message not sent.")
            else:
                self.chat_text.append("Message cannot be empty.")
        else:
            self.chat_text.append("Not connected to the server. Please connect first.")


def main():
    app = QApplication(sys.argv)
    window = ClientGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
