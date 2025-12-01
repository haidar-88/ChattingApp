"""
network.py - Core networking functionality for TCP chat and UDP file transfer
Handles all socket operations, peer discovery, and server communication
"""
from socket import * # Import all from socket module
import json
import base64
import os
import struct
import time
from aes_utils import generate_aes_key, aes_encrypt, aes_decrypt
import rsa

# Server configuration (Central Registry for P2P discovery)
serverPort = 7777
serverIP = '127.0.0.1'

# File transfer configuration
CHUNK_SIZE = 4096  # 4KB chunks for UDP file transfer

class NetworkManager:
    """
    Manages all network connections for the client, including
    server communication (TCP), peer-to-peer chat (TCP), and 
    file transfers (UDP).
    """

    def __init__(self, username, private_key, public_key):
        self.username = username
        self.private_key = private_key
        self.public_key = public_key
        # Ports will be dynamically assigned upon binding
        self.tcp_port = 0
        self.udp_port = 0
        
        # Sockets
        self.server_socket = None          # Connection to the central server
        self.tcp_listener_socket = None    # Listens for incoming chat connections (TCP)
        self.udp_listener_socket = None    # Listens for incoming file chunks (UDP)
        
        # Peer state management
        self.active_peer_connections = {}  # {username: TCP socket}
        self.peer_list = {}                # {username: {ip, tcp_port, udp_port, public_key}}
        self.running = False               # State flag for cleanup

        # Cryptography
        self.aes_key = generate_aes_key() # Client's own symmetric key
        self.peer_aes_keys = {}          # {peer_username: peer's AES key}

    # -----------------------------
    # Server Connection & Communication
    # -----------------------------
    def connect_to_server(self):
        """Establishes the initial TCP connection to the central server."""
        try:
            self.server_socket = socket(AF_INET, SOCK_STREAM)
            self.server_socket.connect((serverIP, serverPort))
            return True
        except Exception as e:
            print(f"Connection to server failed: {e}")
            return False

    def send_username_ports_key(self):
        """Sends client registration data (username, ports, public RSA key) to the server."""
        try:
            # Encode public key to Base64 string for safe transmission
            b64_key = base64.b64encode(self.public_key.save_pkcs1()).decode()
            self.server_socket.send(
                f"USERNAME:{self.username}||tcp_port:{self.tcp_port}, udp_port:{self.udp_port}||public_key:{b64_key}".encode()
            )
            return True
        except Exception as e:
            print(f"Sending Username Failed: {e}")
            return False

    def request_peer_list(self):
        """Requests and parses the list of active peers from the server."""
        try:
            self.server_socket.send("PEER_DISC".encode())
            data = self.server_socket.recv(4096)
            if not data:
                return {}
            
            # Parse the JSON data received from the server
            data = json.loads(data.decode())
            updated = {}
            for peer_username, peer_info in data.items():
                if peer_username == self.username:
                    continue
                updated[peer_username] = {
                    "ip": peer_info["ip"],
                    "tcp_port": peer_info["tcp_port"],
                    "udp_port": peer_info["udp_port"],
                    "public_key": peer_info["public_key"]  # RSA Public Key in Base64
                }
            self.peer_list = updated
            return updated
        except Exception as e:
            print(f"Error receiving peer list: {e}")
            return {}

    def send_heartbeat(self):
        """Sends a 'PING' to the server to maintain active status and checks for 'ACK'."""
        if not self.server_socket:
            return False
        try:
            self.server_socket.send("PING".encode())
            if self.server_socket.recv(1024).decode() == "ACK":
                return True
        except:
            pass # Server connection likely lost
        return False

    def signal_communication(self, type, sender, receiver):
        """Sends a status update (e.g., 'MESSAGESENT', 'FILESENT') to the server."""
        message = f"{type}|{sender}|{receiver}".encode()
        self.server_socket.send(message)
        print(f"signaled to server {type}")
    
    # -----------------------------
    # TCP Listener
    # -----------------------------
    def start_tcp_listener(self):
        """Initializes the TCP socket to listen for incoming chat connections."""
        try:
            self.tcp_listener_socket = socket(AF_INET, SOCK_STREAM)
            # Bind to all interfaces (0.0.0.0)
            self.tcp_listener_socket.bind(('0.0.0.0', self.tcp_port))
            self.tcp_listener_socket.listen(5)
            self.tcp_listener_socket.settimeout(1.0) # Set timeout for non-blocking operation
            # Get the dynamically assigned port number
            self.tcp_port = self.tcp_listener_socket.getsockname()[1]
            return True
        except Exception as e:
            print(f"Failed to start TCP listener: {e}")
            return False

    def accept_tcp_connection(self):
        """Accepts a new incoming TCP connection (used by TCPListenerThread)."""
        try:
            client_socket, addr = self.tcp_listener_socket.accept()
            return client_socket, addr
        except timeout:
            return None # Expected during non-blocking wait
        except Exception as e:
            print(f"Error accepting TCP connection: {e}")
            return None

    def connect_to_peer_tcp(self, peer_username):
        """
        Establishes a new TCP connection to a peer if one doesn't exist.
        Also initiates the secure AES key exchange using the peer's RSA public key.
        """
        if peer_username not in self.peer_list:
            return None
        if peer_username in self.active_peer_connections:
            return self.active_peer_connections[peer_username] # Return existing socket

        try:
            peer = self.peer_list[peer_username]
            sock = socket(AF_INET, SOCK_STREAM)
            # Connect using the IP and TCP port from the peer list
            sock.connect((peer["ip"], peer["tcp_port"]))
            self.active_peer_connections[peer_username] = sock

            # Exchange AES key (Key Encapsulation Mechanism)
            if peer_username not in self.peer_aes_keys:
                # Load the peer's RSA public key
                peer_pub_bytes = base64.b64decode(peer["public_key"])
                peer_pub_key = rsa.PublicKey.load_pkcs1(peer_pub_bytes)
                
                # Encrypt the client's AES key using the peer's RSA public key
                encrypted_aes = rsa.encrypt(self.aes_key, peer_pub_key)
                encrypted_b64 = base64.b64encode(encrypted_aes).decode()
                
                # Send the encrypted AES key to the peer
                print("sending aes key")
                sock.send(f"AES_KEY:{encrypted_b64}".encode())
            return sock
        except Exception as e:
            print(f"Failed to connect to peer {peer_username}: {e}")
            return None

    def receive_tcp_message(self, peer_socket):
        """Receives and decrypts a message or an AES key from a peer over TCP."""
        try:
            data = peer_socket.recv(8192)
            if not data:
                # Peer closed the connection
                return None, None, True

            message = data.decode()

            # Handle incoming AES key exchange
            if message.startswith("AES_KEY:"):
                encrypted_key_b64 = message[len("AES_KEY:"):]
                encrypted_bytes = base64.b64decode(encrypted_key_b64)
                # Decrypt the received AES key using the client's RSA private key
                aes_key = rsa.decrypt(encrypted_bytes, self.private_key)
                print('AES Key decrypted:', aes_key)

                # Temporarily save the key using the socket ID until the username is known
                temp_key = id(peer_socket)
                self.peer_aes_keys[temp_key] = aes_key
                print('Saved AES key temporarily:', self.peer_aes_keys)
                return None, None, False

            print('Before Splitting and Decrypting: ', message)
            # Handle normal encrypted messages
            if "|" in message:
                peer_username, enc_bytes = message.split("|", 1)
                
                # If this is the first message from a newly connected peer, save the socket
                if peer_username not in self.active_peer_connections:
                    self.active_peer_connections[peer_username] = peer_socket

                # If an AES key was temporarily saved (via socket ID), move it to the actual username
                temp_key = id(peer_socket)
                if temp_key in self.peer_aes_keys:
                    self.peer_aes_keys[peer_username] = self.peer_aes_keys.pop(temp_key)

                if peer_username in self.peer_aes_keys:
                    # Decrypt the message using the peer's AES key
                    encrypted_bytes = base64.b64decode(enc_bytes)
                    plaintext = aes_decrypt(self.peer_aes_keys[peer_username], encrypted_bytes)
                    return peer_username, plaintext.decode(), False
                else:
                    return None, "[Encrypted message, AES key not established]", False

            return None, None, False

        except (ConnectionResetError, ConnectionAbortedError):
            # Peer forcibly closed connection
            return None, None, True
        except timeout:
            return None, None, False
        except Exception as e:
            print(f"Error decrypting TCP message: {e}")
            return None, None, False

    def send_tcp_message(self, peer_username, message):
        """Encrypts a message using the client's own AES key and sends it over TCP."""
        sock = self.connect_to_peer_tcp(peer_username)
        if not sock:
            return False
        
        try:
            plaintext = message.encode()
            # Encrypt the message using the client's AES key
            encrypted_bytes = aes_encrypt(self.aes_key, plaintext)
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode()  # Convert to safe Base64 string

            # Protocol: USERNAME|ENCRYPTED_MESSAGE
            info = f"{self.username}|{encrypted_b64}"
            sock.send(info.encode())
            self.signal_communication('MESSAGESENT', self.username, peer_username)
            return True

        except Exception:
            # Connection failed or closed, remove from active connections
            self.active_peer_connections.pop(peer_username, None)
            return False


    # -----------------------------
    # UDP Listener
    # -----------------------------
    def start_udp_listener(self):
        """Initializes the UDP socket to listen for incoming file chunks."""
        try:
            self.udp_listener_socket = socket(AF_INET, SOCK_DGRAM)
            self.udp_listener_socket.bind(('0.0.0.0', self.udp_port))
            self.udp_listener_socket.settimeout(1.0)
            # Get the dynamically assigned port number
            self.udp_port = self.udp_listener_socket.getsockname()[1]
            return True
        except Exception as e:
            print(f"Failed to start UDP listener: {e}")
            return False

    # -------------------------------------------------------------
    # UDP FILE TRANSFER
    # -------------------------------------------------------------
    def send_file_udp(self, peer_username, file_path):
        """
        Sends a file to a peer using a custom reliable UDP protocol 
        (Stop-and-Wait ARQ) with chunking and resume support.
        """
        if peer_username not in self.peer_list or not os.path.exists(file_path):
            return False

        peer = self.peer_list[peer_username]
        ip = peer["ip"]
        udp_port = peer["udp_port"]
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        
        # 

        def wait_for_ack(expected_id, timeout_sec=0.5):
            """Wait for a specific ACK ID. Returns True if the correct ACK is received."""
            self.udp_listener_socket.settimeout(timeout_sec)
            try:
                data, _ = self.udp_listener_socket.recvfrom(1024)
                if data[0] == 4:  # Packet type 4 is ACK
                    # Unpack ACK ID (4-byte unsigned integer)
                    ack_id = struct.unpack("!I", data[1:5])[0]
                    print('received ACK from the file chunck transfer, ACK: ', ack_id)
                    return ack_id == expected_id
                return False
            except timeout:
                return False

        try:
            # -------------------------------------------------------
            # 1) SEND FILE_START (Packet Type 1)
            # -------------------------------------------------------
            start_meta = {
                "filename": file_name,
                "size": file_size,
                "sender": self.username
            }
            start_bytes = json.dumps(start_meta).encode("utf-8")
            # Packet format: Type (1 byte) + Length (4 bytes, Network Byte Order) + Metadata (JSON)
            packet = b"\x01" + struct.pack("!I", len(start_bytes)) + start_bytes

            self.udp_listener_socket.sendto(packet, (ip, udp_port))

            # Wait briefly for FILE_RESUME response (Stop-and-Wait for metadata)
            resume_offset = 0
            start_time = time.time()
            while time.time() - start_time < 1.0:  # 1 second max wait
                # The receiver (receive_udp_message) will send a FILE_RESUME packet (Type 5)
                msg_type, data = self.receive_udp_message()[:2]
                if msg_type == "FILE_RESUME" and data["filename"] == file_name:
                    resume_offset = data["received"]
                    break
            
            # -------------------------------------------------------
            # 2) SEND FILE CHUNKS WITH ACKs (Packet Type 2)
            # -------------------------------------------------------
            chunk_number = resume_offset // CHUNK_SIZE
            with open(file_path, "rb") as f:
                # Move file pointer to resume position
                f.seek(resume_offset)
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    # Header: Type (1) + Chunk Num (4) + Chunk Length (4)
                    header = b"\x02" + struct.pack("!II", chunk_number, len(chunk))
                    packet = header + chunk

                    # Stop-and-wait loop: resend until ACK is received
                    while True:
                        self.udp_listener_socket.sendto(packet, (ip, udp_port))
                        if wait_for_ack(chunk_number):
                            break

                    yield chunk_number, len(chunk)
                    chunk_number += 1

            # -------------------------------------------------------
            # 3) SEND FILE_END (Packet Type 3)
            # -------------------------------------------------------
            end_meta = {
                "filename": file_name,
                "sender": self.username
            }
            end_bytes = json.dumps(end_meta).encode("utf-8")
            # Packet format: Type (1 byte) + Length (4 bytes) + Metadata (JSON)
            packet = b"\x03" + struct.pack("!I", len(end_bytes)) + end_bytes

            # Use a reserved ACK ID for the FILE_END packet
            reserved_ack = 999999001
            while True:
                self.udp_listener_socket.sendto(packet, (ip, udp_port))
                if wait_for_ack(reserved_ack):
                    break
            self.signal_communication('FILESENT', self.username, peer_username)
            return True

        except Exception as e:
            print("Error sending file via UDP:", e)
            return False

    def receive_udp_message(self):
        """
        Receives and processes incoming UDP packets (FILE_START, FILE_CHUNK, FILE_END, ACK).
        Implements file resume logic for incoming transfers.
        """
        try:
            data, addr = self.udp_listener_socket.recvfrom(CHUNK_SIZE + 100)
            if len(data) < 1:
                return None, None

            msg_type = data[0]      # Packet Type (first byte)
            payload = data[1:]

            # -------------------------------------------------------
            # FILE_START (Type 1)
            # -------------------------------------------------------
            if msg_type == 1:
                # Unpack metadata length and load JSON
                meta_len = struct.unpack("!I", payload[:4])[0]
                meta = json.loads(payload[4:4+meta_len].decode("utf-8"))

                # 1. SEND ACK for the FILE_START (using reserved ACK ID)
                ack_packet = b"\x04" + struct.pack("!I", 999999000)
                self.udp_listener_socket.sendto(ack_packet, addr)
                
                # 2. FILE RESUME SUPPORT: Check if a partial file exists
                filename = meta["filename"]
                sender_name = meta["sender"]
                partial_dir = "received_files"
                os.makedirs(partial_dir, exist_ok=True)
                partial_path = os.path.join(partial_dir, filename + ".part")

                # Determine how many bytes are already downloaded
                received_bytes = 0
                if os.path.exists(partial_path):
                    received_bytes = os.path.getsize(partial_path)

                # 3. Send FILE_RESUME response (Type 5) back to the sender
                resume_info = {
                    "filename": filename,
                    "received": received_bytes, # Tell the sender where to resume
                    "sender": sender_name
                }
                resume_bytes = json.dumps(resume_info).encode("utf-8")
                resume_packet = b"\x05" + struct.pack("!I", len(resume_bytes)) + resume_bytes
                self.udp_listener_socket.sendto(resume_packet, addr)

                meta["resume_bytes"] = received_bytes
                
                return "FILE_START", meta

            # -------------------------------------------------------
            # FILE_CHUNK (Type 2)
            # -------------------------------------------------------
            if msg_type == 2:
                # Unpack chunk number and length
                chunk_num, chunk_len = struct.unpack("!II", payload[:8])
                chunk_data = payload[8:8+chunk_len]

                # SEND ACK for the received chunk (ACK ID = chunk number)
                ack_packet = b"\x04" + struct.pack("!I", chunk_num)
                self.udp_listener_socket.sendto(ack_packet, addr)

                return "FILE_CHUNK", (chunk_num, chunk_len, chunk_data)

            # -------------------------------------------------------
            # FILE_END (Type 3)
            # -------------------------------------------------------
            if msg_type == 3:
                # Unpack metadata length and load JSON
                meta_len = struct.unpack("!I", payload[:4])[0]
                meta = json.loads(payload[4:4+meta_len].decode("utf-8"))

                # SEND ACK for the FILE_END (using reserved ACK ID)
                ack_packet = b"\x04" + struct.pack("!I", 999999001)
                self.udp_listener_socket.sendto(ack_packet, addr)

                return "FILE_END", meta
            
            # -------------------------------------------------------
            # FILE_RESUME (Type 5) - Sent by receiver, processed by sender (not here)
            # -------------------------------------------------------
            if msg_type == 5:
                meta_len = struct.unpack("!I", payload[:4])[0]
                meta = json.loads(payload[4:4+meta_len].decode("utf-8"))
                return "FILE_RESUME", meta
            
            # -------------------------------------------------------
            # ACK (Type 4) - Sent by receiver, processed by sender (not here)
            # -------------------------------------------------------
            if msg_type == 4:
                ack_id = struct.unpack("!I", payload[:4])[0]
                return "ACK", ack_id

            return None, None

        except timeout:
            return None, None
        except Exception as e:
            print("Error receiving UDP message:", e)
            return None, None

    # -----------------------------
    # Cleanup
    # -----------------------------
    def close_all(self):
        """Closes all active sockets when the client shuts down."""
        self.running = False
        if self.server_socket:
            try: self.server_socket.close()
            except: pass
        for s in self.active_peer_connections.values():
            try: s.close()
            except: pass
        if self.tcp_listener_socket:
            try: self.tcp_listener_socket.close()
            except: pass
        if self.udp_listener_socket:
            try: self.udp_listener_socket.close()
            except: pass