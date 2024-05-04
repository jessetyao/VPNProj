import socket
import re
from encrypt import mppe_encrypt_128, mppe_decrypt_128

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 1025

PPTP_START_SESSION_REQUEST = 1
PPTP_START_SESSION_REPLY = 2


def parse_hex_line(line):
    hex_values = re.findall(r'[0-9a-fA-F]{2}', line)
    byte_values = bytes.fromhex(''.join(hex_values))
    return byte_values

def read_key_from_file(key_length):
    filename = "MPPE_PSKs.txt"
    line_number = {40: 0, 56: 1, 128: 2}.get(key_length)

    with open(filename, 'r') as file:
        for i, line in enumerate(file):
            if i == line_number:
                return parse_hex_line(line.strip())

def send_control_message(sock, message_type, data, key):
    message = f"{message_type}:{data}"
    encrypted_data = mppe_encrypt_128(message.encode('utf-8'), key)
    sock.sendall(encrypted_data)

def receive_control_message(sock, key):
    encrypted_data = sock.recv(1024)
    decrypted_data = mppe_decrypt_128(encrypted_data, key)
    data = decrypted_data.decode('utf-8')
    message_type, message_data = data.split(':', 1)
    return int(message_type), message_data

def main():
    key = read_key_from_file(128)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((SERVER_ADDRESS, SERVER_PORT))
        sock.listen(1)
        print("Server listening on", SERVER_ADDRESS, "port", SERVER_PORT)
        conn, addr = sock.accept()
        with conn:
            print("Connected to", addr)
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

if __name__ == '__main__':
    main()
