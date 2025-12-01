"""
network.py - Core networking functionality for TCP chat and UDP file transfer
Handles all socket operations, peer discovery, and server communication
"""
from socket import *
import json
import base64
import os
import struct
import time
from aes_utils import generate_aes_key, aes_encrypt, aes_decrypt
import rsa

# Server configuration
serverPort = 7777
serverIP = '127.0.0.1'

# File transfer configuration
CHUNK_SIZE = 4096  # 4KB chunks for UDP file transfer

class NetworkManager:
    """
    Manages all network operations including server communication, peer connections,
    TCP messaging, and UDP file transfers. Handles encryption key exchange and message encryption.
    """

    def __init__(self, username, private_key, public_key):
        """
        Initialize the network manager with user credentials.
        
        Args:
            username: User's username
            private_key: RSA private key for decrypting messages
            public_key: RSA public key for encrypting messages
        """
        self.username = username
        self.private_key = private_key
        self.public_key = public_key
        
        # Port numbers (0 means auto-assign by OS)
        self.tcp_port = 0  # Port for TCP listener (chat messages)
        self.udp_port = 0  # Port for UDP listener (file transfers)
        
        # Socket references
        self.server_socket = None  # Connection to central server
        self.tcp_listener_socket = None  # TCP socket for receiving messages
        self.udp_listener_socket = None  # UDP socket for receiving files
        
        # Connection tracking
        self.active_peer_connections = {}  # {username: socket} for active TCP connections
        self.peer_list = {}  # {username: {ip, tcp_port, udp_port, public_key}} from server
        self.running = False  # Flag to control thread execution

        # Encryption keys
        self.aes_key = generate_aes_key()  # This client's AES key for symmetric encryption
        self.peer_aes_keys = {}  # {username: aes_key} - AES keys shared with each peer

    # -----------------------------
    # Server Connection & Communication
    # -----------------------------
    def connect_to_server(self):
        """
        Establish TCP connection to the central server.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.server_socket = socket(AF_INET, SOCK_STREAM)
            self.server_socket.connect((serverIP, serverPort))
            return True
        except Exception as e:
            print(f"Connection to server failed: {e}")
            return False

    def send_username_ports_key(self):
        """
        Send registration information to the server.
        Format: "USERNAME:name||tcp_port:port, udp_port:port||public_key:base64_key"
        
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            # Encode public key as base64 for transmission
            b64_key = base64.b64encode(self.public_key.save_pkcs1()).decode()
            self.server_socket.send(
                f"USERNAME:{self.username}||tcp_port:{self.tcp_port}, udp_port:{self.udp_port}||public_key:{b64_key}".encode()
            )
            return True
        except Exception as e:
            print(f"Sending Username Failed: {e}")
            return False

    def request_peer_list(self):
        """
        Request list of active peers from the server.
        
        Returns:
            Dictionary of active peers: {username: {ip, tcp_port, udp_port, public_key}}
            Empty dictionary on error
        """
        try:
            # Send peer discovery request
            self.server_socket.send("PEER_DISC".encode())
            data = self.server_socket.recv(4096)
            if not data:
                return {}
            
            # Parse JSON response
            data = json.loads(data.decode())
            updated = {}
            
            # Filter out self from peer list
            for peer_username, peer_info in data.items():
                if peer_username == self.username:
                    continue
                updated[peer_username] = {
                    "ip": peer_info["ip"],
                    "tcp_port": peer_info["tcp_port"],
                    "udp_port": peer_info["udp_port"],
                    "public_key": peer_info["public_key"]  # keep as base64 string
                }
            self.peer_list = updated
            return updated
        except Exception as e:
            print(f"Error receiving peer list: {e}")
            return {}

    def send_heartbeat(self):
        """
        Send heartbeat (keep-alive) message to server to maintain connection.
        
        Returns:
            True if server responded with ACK, False otherwise
        """
        if not self.server_socket:
            return False
        try:
            self.server_socket.send("PING".encode())
            if self.server_socket.recv(1024).decode() == "ACK":
                return True
        except:
            pass
        return False

    def signal_communication(self, type, sender, receiver):
        """
        Notify server about a communication event (message or file transfer).
        
        Args:
            type: Type of communication ('MESSAGESENT' or 'FILESENT')
            sender: Username of sender
            receiver: Username of receiver
        """
        message = f"{type}|{sender}|{receiver}".encode()
        self.server_socket.send(message)
        print(f"signaled to server {type}")
    
    # -----------------------------
    # TCP Listener
    # -----------------------------
    def start_tcp_listener(self):
        """
        Start TCP listener socket for receiving chat messages from peers.
        If tcp_port is 0, OS will assign an available port.
        
        Returns:
            True if listener started successfully, False otherwise
        """
        try:
            self.tcp_listener_socket = socket(AF_INET, SOCK_STREAM)
            self.tcp_listener_socket.bind(('0.0.0.0', self.tcp_port))
            self.tcp_listener_socket.listen(5)
            self.tcp_listener_socket.settimeout(1.0)
            self.tcp_port = self.tcp_listener_socket.getsockname()[1]
            return True
        except Exception as e:
            print(f"Failed to start TCP listener: {e}")
            return False

    def accept_tcp_connection(self):
        """
        Accept an incoming TCP connection from a peer.
        Non-blocking: returns None if no connection is available.
        
        Returns:
            Tuple (client_socket, addr) if connection accepted, None otherwise
        """
        try:
            client_socket, addr = self.tcp_listener_socket.accept()
            return client_socket, addr
        except timeout:
            # No connection available (expected behavior due to timeout)
            return None
        except Exception as e:
            print(f"Error accepting TCP connection: {e}")
            return None

    def connect_to_peer_tcp(self, peer_username):
        """
        Establish TCP connection to a peer and exchange AES encryption key.
        Uses RSA to securely exchange the AES key.
        
        Args:
            peer_username: Username of the peer to connect to
            
        Returns:
            Socket object if connection successful, None otherwise
        """
        # Validate peer exists in peer list
        if peer_username not in self.peer_list:
            return None
        
        # Return existing connection if already connected
        if peer_username in self.active_peer_connections:
            return self.active_peer_connections[peer_username]

        try:
            peer = self.peer_list[peer_username]
            # Create and establish TCP connection
            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect((peer["ip"], peer["tcp_port"]))
            self.active_peer_connections[peer_username] = sock

            # Exchange AES key if not already exchanged
            if peer_username not in self.peer_aes_keys:
                # Decode peer's public key
                peer_pub_bytes = base64.b64decode(peer["public_key"])
                peer_pub_key = rsa.PublicKey.load_pkcs1(peer_pub_bytes)
                # Encrypt our AES key with peer's public RSA key
                encrypted_aes = rsa.encrypt(self.aes_key, peer_pub_key)
                encrypted_b64 = base64.b64encode(encrypted_aes).decode()
                print("sending aes key")
                # Send encrypted AES key to peer
                sock.send(f"AES_KEY:{encrypted_b64}".encode())
            return sock
        except Exception as e:
            print(f"Failed to connect to peer {peer_username}: {e}")
            return None

    def receive_tcp_message(self, peer_socket):
        """
        Receive and decrypt a TCP message from a peer.
        Handles both AES key exchange and encrypted message decryption.
        
        Args:
            peer_socket: Socket connected to the peer
            
        Returns:
            Tuple (peer_username, decrypted_message, disconnected)
            - peer_username: Username of sender, None if not available
            - decrypted_message: Decrypted message text, None if no message
            - disconnected: True if peer closed connection, False otherwise
        """
        try:
            data = peer_socket.recv(8192)
            if not data:
                # Peer closed the connection gracefully
                return None, None, True

            message = data.decode()

            # Handle AES key exchange message
            if message.startswith("AES_KEY:"):
                # Extract and decrypt the AES key
                encrypted_key_b64 = message[len("AES_KEY:"):]
                encrypted_bytes = base64.b64decode(encrypted_key_b64)
                aes_key = rsa.decrypt(encrypted_bytes, self.private_key)
                print('AES Key decrypted:', aes_key)

                # Temporarily store key using socket ID (username not known yet)
                temp_key = id(peer_socket)
                self.peer_aes_keys[temp_key] = aes_key
                print('Saved AES key temporarily:', self.peer_aes_keys)
                return None, None, False

            print('Before Splitting and Decrypting: ', message)
            # Handle normal encrypted messages
            if "|" in message:
                # Format: "username|encrypted_base64"
                peer_username, enc_bytes = message.split("|", 1)
                
                # Update active connections if needed
                if peer_username not in self.active_peer_connections:
                    self.active_peer_connections[peer_username] = peer_socket

                # Move temporary AES key to real username mapping
                temp_key = id(peer_socket)
                if temp_key in self.peer_aes_keys:
                    self.peer_aes_keys[peer_username] = self.peer_aes_keys.pop(temp_key)

                # Decrypt message if AES key is available
                if peer_username in self.peer_aes_keys:
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
            # No data available (non-blocking receive)
            return None, None, False
        except Exception as e:
            print(f"Error decrypting TCP message: {e}")
            return None, None, False

    def send_tcp_message(self, peer_username, message):
        """
        Send an encrypted TCP message to a peer.
        
        Args:
            peer_username: Username of the recipient
            message: Plain text message to send
            
        Returns:
            True if message sent successfully, False otherwise
        """
        # Establish connection to peer if not already connected
        sock = self.connect_to_peer_tcp(peer_username)
        if not sock:
            return False
        
        try:
            # Encrypt message with AES key
            plaintext = message.encode()
            encrypted_bytes = aes_encrypt(self.aes_key, plaintext)
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode()  # safe string for transmission

            # Format: "username|encrypted_base64"
            info = f"{peer_username}|{encrypted_b64}"
            sock.send(info.encode())
            
            # Notify server of message sent
            self.signal_communication('MESSAGESENT', self.username, peer_username)
            return True

        except Exception:
            # Remove failed connection
            self.active_peer_connections.pop(peer_username, None)
            return False


    # -----------------------------
    # UDP Listener
    # -----------------------------
    def start_udp_listener(self):
        """
        Start UDP listener socket for receiving file transfers from peers.
        If udp_port is 0, OS will assign an available port.
        
        Returns:
            True if listener started successfully, False otherwise
        """
        try:
            self.udp_listener_socket = socket(AF_INET, SOCK_DGRAM)
            self.udp_listener_socket.bind(('0.0.0.0', self.udp_port))
            self.udp_listener_socket.settimeout(1.0)  # 1 second timeout for non-blocking receive
            # Update port number with actual assigned port
            self.udp_port = self.udp_listener_socket.getsockname()[1]
            return True
        except Exception as e:
            print(f"Failed to start UDP listener: {e}")
            return False

    # -------------------------------------------------------------
    # UDP FILE TRANSFER
    # -------------------------------------------------------------
    def send_file_udp(self, peer_username, file_path):
        if peer_username not in self.peer_list:
            return False
        if not os.path.exists(file_path):
            return False

        peer = self.peer_list[peer_username]
        ip = peer["ip"]
        udp_port = peer["udp_port"]

        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)

        def wait_for_ack(expected_id, timeout_sec=0.5):
            """
            Wait for a specific ACK (acknowledgment) packet.
            Used for reliable UDP file transfer with retransmission.
            
            Args:
                expected_id: The ACK ID we're waiting for
                timeout_sec: Timeout in seconds before giving up
                
            Returns:
                True if expected ACK received, False on timeout
            """
            self.udp_listener_socket.settimeout(timeout_sec)
            try:
                data, _ = self.udp_listener_socket.recvfrom(1024)
                if data[0] == 4:  # ACK message type
                    ack_id = struct.unpack("!I", data[1:5])[0]
                    print('received ACK from the file chunk transfer, ACK: ', ack_id)
                    return ack_id == expected_id
                return False
            except timeout:
                return False

        try:
            # -------------------------------------------------------
            # 1) SEND FILE_START packet (type 0x01)
            # -------------------------------------------------------
            start_meta = {
                "filename": file_name,
                "size": file_size,
                "sender": self.username
            }
            start_bytes = json.dumps(start_meta).encode("utf-8")
            # Packet format: [type(1 byte)][length(4 bytes)][json_data]
            packet = b"\x01" + struct.pack("!I", len(start_bytes)) + start_bytes

            self.udp_listener_socket.sendto(packet, (ip, udp_port))

            # Wait briefly for FILE_RESUME response (for resume support)
            resume_offset = 0
            start_time = time.time()
            while time.time() - start_time < 1.0:  # 1 second max wait
                msg_type, data = self.receive_udp_message()[:2]
                if msg_type == "FILE_RESUME" and data["filename"] == file_name:
                    resume_offset = data["received"]
                    break
            """
            reserved_ack = 999999000
            while True:
                self.udp_listener_socket.sendto(packet, (ip, udp_port))
                if wait_for_ack(reserved_ack):
                    break
            """
            # -------------------------------------------------------
            # 2) SEND FILE CHUNKS WITH ACKs (type 0x02)
            # -------------------------------------------------------
            # Calculate starting chunk number based on resume offset
            chunk_number = resume_offset // CHUNK_SIZE
            with open(file_path, "rb") as f:
                # Move file pointer to resume position (for partial file resume)
                f.seek(resume_offset)
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break  # End of file

                    # Packet format: [type(1 byte)][chunk_num(4 bytes)][chunk_len(4 bytes)][chunk_data]
                    header = b"\x02" + struct.pack("!II", chunk_number, len(chunk))
                    packet = header + chunk

                    # Reliable transfer: resend until ACK received
                    while True:
                        self.udp_listener_socket.sendto(packet, (ip, udp_port))
                        if wait_for_ack(chunk_number):
                            break

                    # Yield progress information
                    yield chunk_number, len(chunk)
                    chunk_number += 1

            # -------------------------------------------------------
            # 3) SEND FILE_END packet (type 0x03)
            # -------------------------------------------------------
            end_meta = {
                "filename": file_name,
                "sender": self.username
            }
            end_bytes = json.dumps(end_meta).encode("utf-8")
            # Packet format: [type(1 byte)][length(4 bytes)][json_data]
            packet = b"\x03" + struct.pack("!I", len(end_bytes)) + end_bytes

            # Wait for ACK with reserved ID for FILE_END
            reserved_ack = 999999001
            while True:
                self.udp_listener_socket.sendto(packet, (ip, udp_port))
                if wait_for_ack(reserved_ack):
                    break
            
            # Notify server of file transfer completion
            self.signal_communication('FILESENT', self.username, peer_username)
            return True

        except Exception as e:
            print("Error sending file via UDP:", e)
            return False

    def receive_udp_message(self):
        """
        Receive and parse a UDP message (file transfer packet or ACK).
        
        Returns:
            Tuple (msg_type, data) where:
            - msg_type: String describing message type ('FILE_START', 'FILE_CHUNK', 'FILE_END', 'ACK', 'FILE_RESUME')
            - data: Parsed message data (dict or tuple depending on type)
            Returns (None, None) on timeout or error
        """
        try:
            data, addr = self.udp_listener_socket.recvfrom(CHUNK_SIZE + 100)
            if len(data) < 1:
                return None, None

            msg_type = data[0]      # First byte indicates message type
            payload = data[1:]      # Rest of the packet is payload

            # -------------------------------------------------------
            # FILE_START (type 0x01)
            # -------------------------------------------------------
            if msg_type == 1:
                # Parse metadata: [length(4 bytes)][json_data]
                meta_len = struct.unpack("!I", payload[:4])[0]
                meta = json.loads(payload[4:4+meta_len].decode("utf-8"))

                # Send ACK with reserved ID for FILE_START
                ack_packet = b"\x04" + struct.pack("!I", 999999000)
                self.udp_listener_socket.sendto(ack_packet, addr)
                
                # ===== RESUME SUPPORT (Bonus Feature) =====
                # Check if partial file exists and send resume information
                filename = meta["filename"]
                sender_name = meta["sender"]
                partial_dir = "received_files"
                os.makedirs(partial_dir, exist_ok=True)

                partial_path = os.path.join(partial_dir, filename + ".part")

                # Determine how many bytes are already downloaded
                received_bytes = 0
                if os.path.exists(partial_path):
                    received_bytes = os.path.getsize(partial_path)

                # Send FILE_RESUME response (type 0x05) to inform sender of progress
                resume_info = {
                    "filename": filename,
                    "received": received_bytes,
                    "sender": sender_name
                }
                resume_bytes = json.dumps(resume_info).encode("utf-8")
                resume_packet = b"\x05" + struct.pack("!I", len(resume_bytes)) + resume_bytes
                self.udp_listener_socket.sendto(resume_packet, addr)

                meta["resume_bytes"] = received_bytes
                
                return "FILE_START", meta

            # -------------------------------------------------------
            # FILE_CHUNK (type 0x02)
            # -------------------------------------------------------
            if msg_type == 2:
                # Parse chunk: [chunk_num(4 bytes)][chunk_len(4 bytes)][chunk_data]
                chunk_num, chunk_len = struct.unpack("!II", payload[:8])
                chunk_data = payload[8:8+chunk_len]

                # Send ACK with chunk number
                ack_packet = b"\x04" + struct.pack("!I", chunk_num)
                self.udp_listener_socket.sendto(ack_packet, addr)

                return "FILE_CHUNK", (chunk_num, chunk_len, chunk_data)

            # -------------------------------------------------------
            # FILE_END (type 0x03)
            # -------------------------------------------------------
            if msg_type == 3:
                # Parse metadata: [length(4 bytes)][json_data]
                meta_len = struct.unpack("!I", payload[:4])[0]
                meta = json.loads(payload[4:4+meta_len].decode("utf-8"))

                # Send ACK with reserved ID for FILE_END
                ack_packet = b"\x04" + struct.pack("!I", 999999001)
                self.udp_listener_socket.sendto(ack_packet, addr)

                return "FILE_END", meta
            
            # -------------------------------------------------------
            # FILE_RESUME (type 0x05) - Receiver tells sender how many bytes exist
            # -------------------------------------------------------
            if msg_type == 5:
                # Parse resume information: [length(4 bytes)][json_data]
                meta_len = struct.unpack("!I", payload[:4])[0]
                meta = json.loads(payload[4:4+meta_len].decode("utf-8"))
                return "FILE_RESUME", meta
            
            # -------------------------------------------------------
            # ACK (type 0x04) - Acknowledgment packet
            # -------------------------------------------------------
            if msg_type == 4:
                # Parse ACK ID: [ack_id(4 bytes)]
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
        """
        Close all network connections and sockets.
        Called during application shutdown.
        """
        self.running = False
        
        # Close server connection
        if self.server_socket:
            try: self.server_socket.close()
            except: pass
        
        # Close all peer connections
        for s in self.active_peer_connections.values():
            try: s.close()
            except: pass
        
        # Close TCP listener
        if self.tcp_listener_socket:
            try: self.tcp_listener_socket.close()
            except: pass
        
        # Close UDP listener
        if self.udp_listener_socket:
            try: self.udp_listener_socket.close()
            except: pass