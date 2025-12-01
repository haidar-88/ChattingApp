"""
server.py - Central server for the chat application
Handles client connections, peer discovery, heartbeat monitoring, and logging
"""
from socket import *
import json
import threading
import time
import base64
from rsa_utils import load_key_for_server

# Server configuration constants
serverPort = 7777  # Port on which the server listens for client connections
serverIP = '127.0.0.1'  # Server IP address (localhost)
log_file = r'logs\server_log.jsonl'  # Path to log file for storing client activities

# Global dictionary to track active clients
# Format: {username: {'socket': socket, 'address': (ip, port), 'public_key': key, 
#                      'tcp_listener': port, 'udp_listener': port, 'last_seen': timestamp}}
active_clients = {}

def write_to_log_file(username, ip, port, tcp_port, udp_port, public_key, alive, timestamp):
    """
    Logs client connection/disconnection events to the log file.
    
    Args:
        username: Client's username
        ip: Client's IP address
        port: Port used for server connection
        tcp_port: Port client listens on for TCP messages
        udp_port: Port client listens on for UDP file transfers
        public_key: Client's RSA public key
        alive: Boolean indicating if client is connected (True) or disconnected (False)
        timestamp: Unix timestamp of the event
    """
    with open(log_file, 'a') as f:
        # Encode public key as base64 string for JSON storage
        public_key_str = base64.b64encode(public_key.save_pkcs1()).decode()
        data = {"username": username, "ip": ip, "connection_port": port, "is_alive": alive, 
                "tcp_listener_port": tcp_port, "udp_listener_port": udp_port, "public_RSA_key": public_key_str, "time": timestamp}
        json.dump(data, f)
        f.write("\n")

def write_to_log_file_communication(type, sender, receiver, timestamp):
    """
    Logs communication events (messages or file transfers) between clients.
    
    Args:
        type: Type of communication ('Message' or 'File')
        sender: Username of the sender
        receiver: Username of the receiver
        timestamp: Unix timestamp of the event
    """
    with open(log_file, 'a') as f:
        data = {"type": type, "sender": sender, "receiver": receiver, "time": timestamp}
        json.dump(data, f)
        f.write("\n")

def write_to_log_file_request(sender, request):
    """
    Logs client requests (e.g., peer discovery, heartbeat) to the log file.
    
    Args:
        sender: Username of the client making the request
        request: Description of the request (e.g., "Peer Discovery", "Heartbeat")
    """
    with open(log_file, 'a') as f:
        data = {"sender": sender, "request": request}
        json.dump(data, f)
        f.write("\n")

def get_username_and_ports(clientSocket):
    """
    Extracts client information from the initial connection message.
    Expected format: "USERNAME:username||tcp_port:port, udp_port:port||public_key:base64_key"
    
    Args:
        clientSocket: Socket connected to the client
        
    Returns:
        Tuple of (username, tcp_port, udp_port, public_key) or (None, None, None, None) on error
    """
    try:
        # Receive initial client registration data
        data = clientSocket.recv(4096).decode()
        print("Received raw:", repr(data))

        # Parse the message format: USERNAME||PORTS||PUBLIC_KEY
        user_part, ports_part, key_part = data.split("||")

        # Extract username
        username = user_part.split(":")[1].strip()

        # Extract TCP and UDP listener ports
        tcp_port = ports_part.split(",")[0].split(":")[1].strip()
        udp_port = ports_part.split(",")[1].split(":")[1].strip()

        # Extract and decode public key
        public_key_b64 = key_part.split(":")[1].strip()
        public_key_bytes = base64.b64decode(public_key_b64)
        public_key = load_key_for_server(public_key_bytes)

        return username, int(tcp_port), int(udp_port), public_key

    except Exception as e:
        print("Error extracting client info:", e)
        return None, None, None, None

def handle_client(clientSocket, clientAddress):
    """
    Handles communication with a connected client in a separate thread.
    Manages peer discovery requests, heartbeat monitoring, and communication logging.
    
    Args:
        clientSocket: Socket connected to the client
        clientAddress: Tuple of (IP address, port) of the client
    """
    ip, port = clientAddress[0], clientAddress[1]
    
    # Extract client registration information
    username, tcp_port, udp_port, public_key = get_username_and_ports(clientSocket)
    write_to_log_file(username, ip, port, tcp_port, udp_port, public_key, True, time.time())

    # Validate client registration
    if username is None:
        print("Client disconnected or sent invalid data.")
        clientSocket.close()
        return

    # Register client in active clients dictionary
    print(f'UPDATED CLIENT INFO: Client connected, IP: {ip}, Port With Server: {port}, Username: {username}, tcp port {tcp_port}, udp port {udp_port}')
    active_clients[username] = {
                        "socket": clientSocket,
                        "address": (ip, port),
                        "public_key": public_key,
                        "tcp_listener": tcp_port,
                        "udp_listener": udp_port,
                        "last_seen": time.time()
                    }
    # Set socket timeout for non-blocking receive operations
    clientSocket.settimeout(1)

    # Main client communication loop
    while True:
        try:
            try:
                # Receive message from client
                message = clientSocket.recv(2048).decode()
                if not message:
                    # Client closed connection gracefully
                    print(f'Client closed connection, IP: {ip}, Port: {port}, time: {time.time()}')
                    write_to_log_file(username, ip, port, tcp_port, udp_port, public_key, False, time.time())
                    active_clients.pop(username, None)
                    clientSocket.close()
                    return
                print('Received Message: ', repr(message))
                
                # Handle peer discovery request
                if message.upper().startswith('PEER_DISC'):
                    try:
                        # Build peer list with all active clients (excluding the requester)
                        peer_list = {
                            user: {
                                "ip": info["address"][0],
                                "tcp_port": info["tcp_listener"],
                                "udp_port": info["udp_listener"], 
                                "public_key": base64.b64encode(info["public_key"].save_pkcs1()).decode()
                            }
                            for user, info in active_clients.items()
                        }
                        # Send peer list as JSON
                        clientSocket.send(json.dumps(peer_list).encode())
                        write_to_log_file_request(username, "Peer Discovery")

                    except Exception as e: 
                        print('Error Sending Peer Discovery Content.')

                # Handle heartbeat (keep-alive) message
                elif message.upper().startswith("PING"):
                    active_clients[username]['last_seen'] = time.time()
                    print("Sent a heartbeat ACK to Client")
                    clientSocket.send('ACK'.encode())
                    write_to_log_file_request(username, "Heartbeat - ACKING BACK")

                # Handle message sent notification
                elif message.startswith("MESSAGESENT"):
                    parts = message.split('|')
                    sender = parts[1]
                    receiver = parts[2]
                    write_to_log_file_communication('Message', sender, receiver, time.time())
                    print(f"Message Sent from {sender} to {receiver}")

                # Handle file sent notification
                elif message.upper().startswith("FILESENT"):
                    parts = message.split('|')
                    sender = parts[1]
                    receiver = parts[2]
                    write_to_log_file_communication('File', sender, receiver, time.time())
                    print(f"File Sent from {sender} to {receiver}")

            except timeout:
                    # No data received in this interval, continue to timeout check
                    pass
            
            # Check if client has timed out (no heartbeat for 60 seconds)
            if time.time() - active_clients[username]['last_seen'] > 60:
                # Client timeout: no heartbeat received for 60 seconds
                print(f"Client timed out: {ip}:{port}")
                write_to_log_file(username, ip, port, tcp_port, udp_port, public_key, False, time.time())
                clientSocket.close()
                active_clients.pop(username, None)
                break

        except ConnectionResetError:
            # Client disconnected abruptly (connection reset)
            print(f"Client {ip}:{port} disconnected abruptly")
            write_to_log_file(username, ip, port, tcp_port, udp_port, public_key, False, time.time())
            clientSocket.close()
            if username in active_clients:
                active_clients.pop(username, None)
            break

        except Exception as e:
            # Handle any other unexpected errors
            print("Handle Client Error: ", e)
            write_to_log_file(username, ip, port, tcp_port, udp_port, public_key, False, time.time())
            clientSocket.close()
            if username in active_clients:
                active_clients.pop(username, None)
            break

if __name__ == '__main__':
    """
    Main server entry point.
    Creates a TCP socket, binds to the server port, and listens for client connections.
    Each client connection is handled in a separate thread.
    """
    try:
        # Create TCP socket and bind to server address
        serverSocket = socket(AF_INET, SOCK_STREAM)
        serverSocket.bind((serverIP, serverPort))
    except Exception as e:
        print('Creating or Binding Socket Failed')
        exit(-1)

    serverSocket.listen(5) # 5 Connection at a time
    print('Server is ready to receive connections')

    # Main server loop: accept connections and spawn handler threads
    while True:
        try:
            # Accept a new client connection
            clientSocket, clientAddress = serverSocket.accept()
            # Create a new thread to handle this client
            client_main_thread = threading.Thread(target=handle_client, args=(clientSocket, clientAddress))
            client_main_thread.start()
        except Exception as e:
            print('Connection to Client Failed')
            continue