import socket
import threading
import json

#Server Address (LocalHost)
HOST = '127.0.0.1'
PORT = 8000

clients = {}  

#Sends a message to all the clients except for the sender
def broadcast(message, sender_socket):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message)
            except:
                client.close()
                del clients[client]

#Handle communication with one client
def handle_client(client_socket):
    try:
        pubkey_data = client_socket.recv(4096).decode()
        clients[client_socket] = {'public_key': pubkey_data, 'addr': client_socket.getpeername()}
        print(f"Received public key from {clients[client_socket]['addr']}")

        # Send the list of all public keys to every client
        def send_keys_update():
            keys = {str(addr): info['public_key'] for client, info in clients.items() for addr in [info['addr']]}
            keys_json = json.dumps(keys).encode()
            for client in clients:
                client.send(keys_json)

        send_keys_update()

        # Receive and forward messages
        while True:
            message = client_socket.recv(8192)
            if not message:
                break
            broadcast(message, client_socket)

    except Exception as e:
        print(f"Error: {e}")

     # When the client disconnects
    finally:
        print(f"Connection closed {clients[client_socket]['addr']}")
        client_socket.close()

         # Remove the client from the dictionary
        if client_socket in clients:
            del clients[client_socket]
        send_keys_update()

# Start the TCP server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"Server started on {HOST}:{PORT}")

      # Accept clients forever
    while True:
        client_socket, addr = server.accept()
        print(f"New connection from {addr}")
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()

# Entry point
if __name__ == "__main__":
    start_server()
