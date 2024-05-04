import socket
import threading
from encrypt import derive_aes_key, aes_decrypt
from dh import generate_prime, get_private_key, get_public_key

HOST, PORT = "0.0.0.0", 9090
KEY = 0x00

PRIME_LENGTH = 2048
base = 2

prime = generate_prime(PRIME_LENGTH)
server_private = get_private_key(prime)
server_public = get_public_key(server_private, prime, base)


def handle_client_connection(client_socket):
    try:
        client_socket.sendall(f"{prime},{base},{server_public}".encode())
        client_public_and_address = client_socket.recv(1024).decode()
        client_public, available_addresses = int(client_public_and_address.split(",")[0]), client_public_and_address.split(",")[1:]
        print(available_addresses)
        shared_secret = pow(client_public, server_private, prime)
        KEY = derive_aes_key(shared_secret)
        print("Key successfully generated")
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            data =  aes_decrypt(data, KEY).decode()
            if data.startswith("UPDATE_ADDRESS"):
                _, new_address = data.split(',')
                if new_address not in available_addresses:
                    print("Invalid address")
                    
                    break
                print(f"Client has updated its address to: {new_address}")
            else:
                print(f"Received: {data}")
            
            #echo the message back to the client
            #client_socket.send(data)
    finally:
        client_socket.close()

def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")
    
    try:
        while True:
            client_sock, address = server_socket.accept()
            print(f"Accepted connection from {address}")
            client_handler = threading.Thread(target=handle_client_connection, args=(client_sock,))
            client_handler.start()
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server(HOST, PORT)
