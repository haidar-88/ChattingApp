from socket import *
import json
import threading
import time
import base64
from rsa_utils import load_key_for_server

# --- Server Configuration ---
serverPort = 7777
serverIP = '127.0.0.1'
log_file = r'logs\server_log.jsonl' # Log file for client activity (JSON Lines format)

# Global dictionary to store information about currently connected clients
# Key: username (string), Value: dictionary of client metadata
active_clients = {} # {username: {'socket': socket_obj, 'address': (ip, port), ...}}

# ------------------------------------
# --- Logging Functions ---
# ------------------------------------

def write_to_log_file(username, ip, port, tcp_port, udp_port, public_key, alive, timestamp):
    """Logs client connection/disconnection events with comprehensive details."""
    with open(log_file, 'a') as f:
        # Serialize RSA public key to a Base64 string for logging
        public_key_str = base64.b64encode(public_key.save_pkcs1()).decode()
        data = {
            "username": username, 
            "ip": ip, 
            "connection_port": port, # Server port used by the client's connection
            "is_alive": alive, 
            "tcp_listener_port": tcp_port, # Client's P2P TCP port
            "udp_listener_port": udp_port, # Client's P2P UDP port
            "public_RSA_key": public_key_str, 
            "time": timestamp
        }
        json.dump(data, f)
        f.write("\n")

def write_to_log_file_communication(type, sender, receiver, timestamp):
    """Logs P2P communication events (Message or File transfer signals)."""
    with open(log_file, 'a') as f:
        data = {"type": type, "sender": sender, "receiver": receiver, "time": timestamp}
        json.dump(data, f)
        f.write("\n")

def write_to_log_file_request(sender, request):
    """Logs client requests to the server (e.g., Peer Discovery, Heartbeat)."""
    with open(log_file, 'a') as f:
        data = {"sender": sender, "request": request, "time": time.time()} # Added time here for consistency
        json.dump(data, f)
        f.write("\n")

# ------------------------------------
# --- Client Handling Utilities ---
# ------------------------------------

def get_username_and_ports(clientSocket):
    """
    Receives the initial client handshake data, which contains:
    Username, P2P TCP Port, P2P UDP Port, and RSA Public Key.
    """
    try:
        # Expected format: USERNAME:user||tcp_port:1234, udp_port:5678||public_key:b64_key
        data = clientSocket.recv(4096).decode()
        print("Received raw:", repr(data))

        user_part, ports_part, key_part = data.split("||")

        username = user_part.split(":")[1].strip()

        # Extracting TCP and UDP ports
        tcp_port = ports_part.split(",")[0].split(":")[1].strip()
        udp_port = ports_part.split(",")[1].split(":")[1].strip()

        # Decoding and loading the RSA public key
        public_key_b64 = key_part.split(":")[1].strip()
        public_key_bytes = base64.b64decode(public_key_b64)
        public_key = load_key_for_server(public_key_bytes) # Utility function to load key

        return username, int(tcp_port), int(udp_port), public_key

    except Exception as e:
        print("Error extracting client info:", e)
        return None, None, None, None

def handle_client(clientSocket, clientAddress):
    """
    Manages the connection and command loop for a single client in a separate thread.
    This is the core logic of the server/registry.
    """
    ip, port = clientAddress[0], clientAddress[1]
    
    # 1. Initial Handshake
    username, tcp_port, udp_port, public_key = get_username_and_ports(clientSocket)
    
    if username is None:
        print("Client disconnected or sent invalid data.")
        clientSocket.close()
        return
    
    # Log the successful connection
    write_to_log_file(username, ip, port, tcp_port, udp_port, public_key, True, time.time())

    print(f'UPDATED CLIENT INFO: Client connected, IP: {ip}, Port With Server: {port}, Username: {username}, tcp port {tcp_port}, udp port {udp_port}')
    
    # Store client data in the global registry
    active_clients[username] = {
        "socket": clientSocket,
        "address": (ip, port),
        "public_key": public_key,
        "tcp_listener": tcp_port,
        "udp_listener": udp_port,
        "last_seen": time.time()
    }
    clientSocket.settimeout(1) # Set a small timeout for non-blocking recv

    # 2. Main Client Loop (Heartbeat and Request Handling)
    while True:
        try:
            try:
                message = clientSocket.recv(2048).decode()
                
                # If no message is received (socket closed gracefully)
                if not message:
                    print(f'Client closed connection, IP: {ip}, Port: {port}, time: {time.time()}')
                    write_to_log_file(username, ip, port, tcp_port, udp_port, public_key, False, time.time())
                    active_clients.pop(username, None)
                    clientSocket.close()
                    return # Exit thread
                
                print('Received Message: ', repr(message))
                
                # --- Handle Peer Discovery Request ---
                if message.upper().startswith('PEER_DISC'):
                    try:
                        # Build the peer list for the client, excluding the client itself
                        peer_list = {
                            user: {
                                "ip": info["address"][0],
                                "tcp_port": info["tcp_listener"],
                                "udp_port": info["udp_listener"], 
                                # Send the peer's public key for KEM (Key Exchange Mechanism)
                                "public_key": base64.b64encode(info["public_key"].save_pkcs1()).decode()
                            }
                            for user, info in active_clients.items()
                            if user != username
                        }
                        clientSocket.send(json.dumps(peer_list).encode())
                        write_to_log_file_request(username, "Peer Discovery")

                    except Exception as e: 
                        print('Error Sending Peer Discovery Content.', e)

                # --- Handle Heartbeat Request ---
                elif message.upper().startswith("PING"):
                    active_clients[username]['last_seen'] = time.time() # Update last seen time
                    print("Sent a heartbeat ACK to Client")
                    clientSocket.send('ACK'.encode())
                    write_to_log_file_request(username, "Heartbeat - ACKING BACK")

                # --- Handle Communication Signals (for logging purposes only) ---
                elif message.startswith("MESSAGESENT"):
                    parts = message.split('|')
                    sender = parts[1]
                    receiver = parts[2]
                    write_to_log_file_communication('Message', sender, receiver, time.time())
                    print(f"Message Sent from {sender} to {receiver}")

                elif message.upper().startswith("FILESENT"):
                    parts = message.split('|')
                    sender = parts[1]
                    receiver = parts[2]
                    write_to_log_file_communication('File', sender, receiver, time.time())
                    print(f"File Sent from {sender} to {receiver}")

            except timeout:
                pass # Expected behavior when using settimeout(1)
            
            # 3. Handle Client Timeout (Inactivity)
            # If no PING has been received for more than 60 seconds
            if time.time() - active_clients[username]['last_seen'] > 60:
                print(f"Client timed out: {ip}:{port}")
                write_to_log_file(username, ip, port, tcp_port, udp_port, public_key, False, time.time())
                clientSocket.close()
                active_clients.pop(username, None)
                break # Exit loop and thread

        except ConnectionResetError:
            # Handle abrupt disconnection
            print(f"Client {ip}:{port} disconnected abruptly")
            write_to_log_file(username, ip, port, tcp_port, udp_port, public_key, False, time.time())
            clientSocket.close()
            if username in active_clients:
                active_clients.pop(username, None)
            break

        except Exception as e:
            # Catch all other exceptions
            print("Handle Client Error: ", e)
            write_to_log_file(username, ip, port, tcp_port, udp_port, public_key, False, time.time())
            clientSocket.close()
            if username in active_clients:
                active_clients.pop(username, None)
            break

# ------------------------------------
# --- Server Main Loop ---
# ------------------------------------

if __name__ == '__main__':
    try:
        # Create and bind the main server socket
        serverSocket = socket(AF_INET, SOCK_STREAM)
        serverSocket.bind((serverIP, serverPort))
    except Exception as e:
        print('Creating or Binding Socket Failed')
        exit(-1)

    serverSocket.listen(5) # Allow up to 5 pending connections
    print('Server is ready to receive connections')

    # Continuous loop to accept new client connections
    while True:
        try:
            clientSocket, clientAddress = serverSocket.accept()
            # Start a new thread to handle the incoming client connection
            client_main_thread = threading.Thread(target=handle_client, args=(clientSocket, clientAddress))
            client_main_thread.start()
        except Exception as e:
            print('Connection to Client Failed')
            continue