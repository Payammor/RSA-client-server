import sys
import socket
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QVBoxLayout, QWidget, QPushButton, QLineEdit
from threading import Thread
from RSA import generate_key_pair, exchange_keys, encrypt, decrypt

class ServerGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Secure Chat Server")
        self.setGeometry(100, 100, 600, 400)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.chat_text = QTextEdit(self)
        self.message_input = QLineEdit(self)
        self.send_button = QPushButton("Send", self)

        layout = QVBoxLayout(self.central_widget)
        layout.addWidget(self.chat_text)
        layout.addWidget(self.message_input)
        layout.addWidget(self.send_button)

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', 12345))
        self.server_socket.listen(5)

        self.clients = []

        self.chat_text.append("Server is listening on port 12345...")

        self.accept_connections_thread = Thread(target=self.accept_connections)
        self.accept_connections_thread.daemon = True
        self.accept_connections_thread.start()

        self.send_button.clicked.connect(self.send_server_message)

    def accept_connections(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            self.chat_text.append(f"Accepted connection from {addr[0]}:{addr[1]}")

            # Generate and exchange keys with the client
            client_private_key_pem, client_public_key_pem = exchange_keys(client_socket)
            self.clients.append((client_socket, client_private_key_pem, client_public_key_pem))

            # Start a thread for handling client communication
            client_thread = Thread(target=self.handle_client, args=(client_socket, client_private_key_pem, client_public_key_pem))
            client_thread.daemon = True
            client_thread.start()

    def handle_client(self, client_socket, client_private_key_pem, client_public_key_pem):
        while True:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break

                # Decrypt and display the received message
                decrypted_data = decrypt(client_private_key_pem, data)
                self.chat_text.append(f"Client: {decrypted_data.decode()}")

                # Handle server messages to the client
                if decrypted_data.decode().lower() == "server":
                    self.send_server_message(client_socket)

            except Exception as e:
                self.chat_text.append(f"Receive error from client: {e}")
                break

        # Remove the client from the list when they disconnect
        self.clients.remove((client_socket, client_private_key_pem, client_public_key_pem))
        client_socket.close()

    def send_server_message(self, client_socket):
        message = self.message_input.text()
        if message:
            self.chat_text.append(f"Server: {message}")
            self.message_input.clear()

            # Encrypt and send the message to the specified client
            client_private_key_pem = next(item[1] for item in self.clients if item[0] == client_socket)
            client_public_key_pem = next(item[2] for item in self.clients if item[0] == client_socket)
            encrypted_message = encrypt(client_public_key_pem, message.encode())
            client_socket.sendall(encrypted_message)

def main():
    app = QApplication(sys.argv)
    window = ServerGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
