import socket
import threading




HOST, PORT = "0.0.0.0", 9090


def handle_client_connection(client_socket):
    try:
        
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            print(f"Received: {data.decode()}")
            
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