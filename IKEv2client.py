import socket, random
from dh import get_private_key, get_public_key
from encrypt import derive_aes_key, aes_encrypt

SERVER_IP, PORT = 'localhost', 9090
KEY = 0x00

PRIME_LENGTH = 2048
base = 2 #used for dh secret sharing

available_addresses = "127.0.0.1,192.168.1.100,192.168.2.100,10.0.0.100" #random set of ip addresses to emulate MOBIKE protocol
all_addresses = ["127.0.0.1","192.168.1.100","192.168.2.100","10.0.0.100", "192.168.3.100","192.168.4.101","10.1.1.101"] 
#random set of ip addresses to emulate incorrect conenction

def connect_to_server(server_ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((server_ip, port))
        data = client.recv(4096).decode()
        prime, base, server_public = map(int, data.split(','))

        client_private = get_private_key(prime)
        client_public = get_public_key(client_private, prime, base)

        client.sendall(f'{str(client_public)},{available_addresses}'.encode())

        shared_secret = pow(server_public, client_private, prime)
        KEY = derive_aes_key(shared_secret)
        print("Key successfully generated")
        
        try:
            while True:
                message = input("Enter message: ")
                if message.lower() == 'exit':
                    break  #Exit the loop if 'exit' is typed
                if message.lower() == 'switch':
                    current_address = random.choice(all_addresses)
                    print(f"New active address: {current_address}")
                    message = f"UPDATE_ADDRESS,{current_address}".encode()
                    message = aes_encrypt(message, KEY)
                    client.sendall(message)
                else:
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
