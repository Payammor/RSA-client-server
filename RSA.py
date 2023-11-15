from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537, # exponent used in public key
        key_size=2048, # length of key in bits
        backend=default_backend()

    )
    public_key = private_key.public_key() # generate public key from private key

    private_pem = private_key.private_bytes( # convert private key to PEM format - PEM used to store keys
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem #public and private keys returned in PEM format


def encrypt(public_key_pem, plaintext):
    try:
        # Deserialize the PEM-encoded public key into a usable key object
        public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())

        # Ensure the plaintext is bytes
        if not isinstance(plaintext, bytes):
            plaintext = plaintext.encode('utf-8')

        # Encrypt the plaintext using RSA with PKCS#1 v1.5 padding
        ciphertext = public_key.encrypt(
            plaintext,
            padding.PKCS1v15()
        )

        # Return the encrypted ciphertext as bytes
        return ciphertext

    except Exception as e:
        print(f"Encryption error: {e}")
        return None




def decrypt(private_key_pem, ciphertext):
    try:
        # Deserialize the PEM-encoded private key
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())

        # Decrypt the ciphertext using RSA with PKCS#1 v1.5 padding
        plaintext = private_key.decrypt(
            ciphertext,
            padding.PKCS1v15()
        )

        # Return the decrypted plaintext as bytes
        return plaintext

    except Exception as e:
        print(f"Decryption error: {e}")
        return None


def send_with_length(socket, data):
    # Send the length of the data first
    data_length = len(data)
    socket.sendall(data_length.to_bytes(4, 'big'))
    # Then send the data
    socket.sendall(data)

def receive_full_message(sock):
    # First receive the length of the data
    length_data = sock.recv(4)
    data_length = int.from_bytes(length_data, 'big')
    # Then receive the actual data
    return sock.recv(data_length)


def exchange_keys(client_socket):
    try:
        # Generate RSA key pair on the client side
        client_private_key_pem, client_public_key_pem = generate_key_pair()

        # Send the client's public key to the server
        send_with_length(client_socket, client_public_key_pem.encode())

        # Receive the server's public key
        server_public_key_pem = receive_full_message(client_socket)

        return client_private_key_pem, server_public_key_pem

    except Exception as e:
        print(f"Key exchange error: {e}")
        return None