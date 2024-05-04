import socket

SERVER_IP, PORT = 'localhost', 9090

def connect_to_server(server_ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((server_ip, port))
        try:
            while True:
                message = input("Enter message: ")
                if message.lower() == 'exit':
                    break  #Exit the loop if 'exit' is typed
                message = message.encode()
                client.sendall(message)
                
                #receive echo from server
                #response = client.recv(1024)
                #print(f"Server response: {response.decode()}")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == '__main__':
    connect_to_server(SERVER_IP, PORT)