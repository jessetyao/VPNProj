import socket
from dh import get_private_key, get_public_key
from encrypt import derive_aes_key, aes_encrypt

SERVER_IP, PORT = 'localhost', 9090
KEY = 0x00

PRIME_LENGTH = 2048
base = 2



def connect_to_server(server_ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((server_ip, port))
        data = client.recv(4096).decode()
        prime, base, server_public = map(int, data.split(','))

        client_private = get_private_key(prime)
        client_public = get_public_key(client_private, prime, base)

        client.sendall(str(client_public).encode())

        shared_secret = pow(server_public, client_private, prime)
        KEY = derive_aes_key(shared_secret)
        print("Key successfully generated")
        
        try:
            while True:
                message = input("Enter message: ")
                if message.lower() == 'exit':
                    break  #Exit the loop if 'exit' is typed
                message = message.encode()
                message = aes_encrypt(message, KEY)
                client.sendall(message)
                
                #receive echo from server
                #response = client.recv(1024)
                #print(f"Server response: {response.decode()}")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == '__main__':
    connect_to_server(SERVER_IP, PORT)
