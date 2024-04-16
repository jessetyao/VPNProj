import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 1025

#dummy creds
USERNAME = "username"
PASSWORD = "password"

def generate_key(password):
    backend = default_backend()
    key = password.encode()
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(key)
def authenticate(username, password):
    return username == USERNAME and password == PASSWORD

PPTP_START_SESSION_REQUEST = 1
PPTP_START_SESSION_REPLY = 2

def send_control_message(sock, message_type, data, key):
    message = f"{message_type}:{data}"
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    sock.sendall(encrypted_data)

def receive_control_message(sock, key):
    encrypted_data = sock.recv(1024)
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    data = unpadded_data.decode()
    message_type, message_data = data.split(':', 1)
    return int(message_type), message_data

def main():
    key = generate_key(PASSWORD)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((SERVER_ADDRESS, SERVER_PORT))
        sock.listen(1)
        print("Server listening on", SERVER_ADDRESS, "port", SERVER_PORT)
        conn, addr = sock.accept()
        with conn:
            print("Connected to", addr)
            if authenticate(USERNAME, PASSWORD):
                send_control_message(conn, PPTP_START_SESSION_REPLY, "...", key)
                message_type, message_data = receive_control_message(conn, key)
                if message_type == PPTP_START_SESSION_REQUEST:
                    print("Session started successfully.")
                    while True:
                        message_type, message_data = receive_control_message(conn, key)
                        print("Received:", message_data)
                        if message_data.strip() == "exit()":
                            break
                        response = input("Enter response: ")
                        send_control_message(conn, 3, response, key)
                else:
                    print("Failed to start session.")
            else:
                print("Authentication failed.")

main()
