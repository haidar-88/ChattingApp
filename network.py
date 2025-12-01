"""
network.py - Core networking functionality for TCP chat and UDP file transfer
Handles:
- Server communication (registration, heartbeat, peer discovery)
- Peer-to-peer TCP messaging with RSA + AES hybrid encryption
- Peer-to-peer UDP file transfer with resume support, ACKs, and chunking
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
    Manages all networking responsibilities:
    - Connecting to the server
    - Registering username, ports, and public key
    - Managing TCP message connections with peers
    - Exchanging AES keys securely using RSA
    - Sending/receiving encrypted chat messages
    - Sending files using UDP with ACK and resume support
    """

    def __init__(self, username, private_key, public_key):
        """
        Initialize the networking layer.

        :param username: (str) Username of this client
        :param private_key: RSA private key for decrypting AES key
        :param public_key: RSA public key for sending to server/peers
        """
        self.username = username
        self.private_key = private_key
        self.public_key = public_key
        
        self.running = False
        # Ports (server assigns these dynamically after bind)
        self.tcp_port = 0
        self.udp_port = 0

        # Sockets
        self.server_socket = None
        self.tcp_listener_socket = None
        self.udp_listener_socket = None

        # peer_username → active TCP socket
        self.active_peer_connections = {}

        # peer_username → peer info (IP, ports, public key)
        self.peer_list = {}

        self.running = False

        # AES key for encrypting outgoing messages
        self.aes_key = generate_aes_key()

        # peer_username → AES key shared with that peer
        self.peer_aes_keys = {}

    # -----------------------------
    # Server Connection & Communication
    # -----------------------------
    def connect_to_server(self):
        """Create TCP connection with central server."""
        try:
            self.server_socket = socket(AF_INET, SOCK_STREAM)
            self.server_socket.connect((serverIP, serverPort))
            return True
        except Exception as e:
            print(f"Connection to server failed: {e}")
            return False

    def send_username_ports_key(self):
        """
        Send:
        - username
        - TCP port
        - UDP port
        - Public RSA key (base64 encoded)
        to the server.
        """
        try:
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
        Ask server for all connected peers.
        Returns a dict:
        {
            username: {ip, tcp_port, udp_port, public_key}
        }
        """
        try:
            self.server_socket.send("PEER_DISC".encode())
            data = self.server_socket.recv(4096)
            if not data:
                return {}
            data = json.loads(data.decode())
            updated = {}
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
        """Send PING → Expect ACK, otherwise server considered disconnected."""
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
        """Tell the server a message or file was sent for logging purposes."""
        message = f"{type}|{sender}|{receiver}".encode()
        self.server_socket.send(message)
        print(f"signaled to server {type}")
    
    # -----------------------------
    # TCP Listener
    # -----------------------------
    def start_tcp_listener(self):
        """Start TCP listener on any free port."""
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
        Accept a peer TCP connection.
        Non-blocking because timeout=1.0.
        """
        try:
            client_socket, addr = self.tcp_listener_socket.accept()
            return client_socket, addr
        except timeout:
            return None
        except Exception as e:
            print(f"Error accepting TCP connection: {e}")
            return None

    def connect_to_peer_tcp(self, peer_username):
        """
        Initiate TCP connection to peer.
        If connection exists, reuse it.
        If AES key is not established, send it encrypted using RSA.
        """
        if peer_username not in self.peer_list:
            return None
        if peer_username in self.active_peer_connections:
            return self.active_peer_connections[peer_username]

        try:
            peer = self.peer_list[peer_username]
            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect((peer["ip"], peer["tcp_port"]))
            self.active_peer_connections[peer_username] = sock

            # Exchange AES key if not already
            if peer_username not in self.peer_aes_keys:
                peer_pub_bytes = base64.b64decode(peer["public_key"])
                peer_pub_key = rsa.PublicKey.load_pkcs1(peer_pub_bytes)
                encrypted_aes = rsa.encrypt(self.aes_key, peer_pub_key)
                encrypted_b64 = base64.b64encode(encrypted_aes).decode()
                print("sending aes key")
                sock.send(f"AES_KEY:{encrypted_b64}".encode())
            return sock
        except Exception as e:
            print(f"Failed to connect to peer {peer_username}: {e}")
            return None

    def receive_tcp_message(self, peer_socket):
        """
        Handle all incoming TCP messages:
        - AES_KEY exchange
        - Encrypted messages
        - Connection resets
        """
        try:
            data = peer_socket.recv(8192)
            if not data:
                # Peer closed the connection
                return None, None, True

            message = data.decode()

            # If AES_KEY, save it with a temporary key
            if message.startswith("AES_KEY:"):
                encrypted_key_b64 = message[len("AES_KEY:"):]
                encrypted_bytes = base64.b64decode(encrypted_key_b64)
                aes_key = rsa.decrypt(encrypted_bytes, self.private_key)
                print('AES Key decrypted:', aes_key)

                # Temporary save until username known
                temp_key = id(peer_socket)
                self.peer_aes_keys[temp_key] = aes_key
                print('Saved AES key temporarily:', self.peer_aes_keys)
                return None, None, False

            print('Before Splitting and Decrypting: ', message)
            # For normal messages
            if "|" in message:
                peer_username, enc_bytes = message.split("|", 1)
                if peer_username not in self.active_peer_connections:
                    self.active_peer_connections[peer_username] = peer_socket

                # Move temporary AES key to real username
                temp_key = id(peer_socket)
                if temp_key in self.peer_aes_keys:
                    self.peer_aes_keys[peer_username] = self.peer_aes_keys.pop(temp_key)

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
            return None, None, False
        except Exception as e:
            print(f"Error decrypting TCP message: {e}")
            return None, None, False

    def send_tcp_message(self, peer_username, message):
        """
        Encrypt and send message to peer using AES.
        Format sent: "peer_username|<base64 encrypted>"
        """
        sock = self.connect_to_peer_tcp(peer_username)
        if not sock:
            return False
        
        try:
            plaintext = message.encode()
            encrypted_bytes = aes_encrypt(self.aes_key, plaintext)
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode()  # safe string

            info = f"{peer_username}|{encrypted_b64}"
            sock.send(info.encode())  # now this is safe
            self.signal_communication('MESSAGESENT', self.username, peer_username)
            return True

        except Exception:
            self.active_peer_connections.pop(peer_username, None)
            return False


    # -----------------------------
    # UDP Listener
    # -----------------------------
    def start_udp_listener(self):
        """Start UDP listener on any free port."""
        try:
            self.udp_listener_socket = socket(AF_INET, SOCK_DGRAM)
            self.udp_listener_socket.bind(('0.0.0.0', self.udp_port))
            self.udp_listener_socket.settimeout(1.0)
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
        Sends file via UDP in 3 steps:
        1. FILE_START → peer may respond with FILE_RESUME to resume
        2. FILE_CHUNK messages with ACK(chunk_id)
        3. FILE_END with final ACK
        """
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
            """Wait for a specific ACK ID, resend packet if timeout. Used for reliable UDP transfer."""
            self.udp_listener_socket.settimeout(timeout_sec)
            try:
                data, _ = self.udp_listener_socket.recvfrom(1024)
                if data[0] == 4:  # ACK
                    ack_id = struct.unpack("!I", data[1:5])[0]
                    print('received ACK from the file chunck transfer, ACK: ', ack_id)
                    return ack_id == expected_id
                return False
            except timeout:
                return False

        try:
            # -------------------------------------------------------
            # 1) SEND FILE_START
            # -------------------------------------------------------
            start_meta = {
                "filename": file_name,
                "size": file_size,
                "sender": self.username
            }
            start_bytes = json.dumps(start_meta).encode("utf-8")
            packet = b"\x01" + struct.pack("!I", len(start_bytes)) + start_bytes

            self.udp_listener_socket.sendto(packet, (ip, udp_port))

            # Check for FILE_RESUME
            resume_offset = 0
            start_time = time.time()
            while time.time() - start_time < 1.0:  # 1 second max wait
                msg_type, data = self.receive_udp_message()[:2]
                if msg_type == "FILE_RESUME" and data["filename"] == file_name:
                    resume_offset = data["received"]
                    break

            # -------------------------------------------------------
            # 2) SEND FILE CHUNKS WITH ACKs
            # -------------------------------------------------------
            chunk_number = resume_offset // CHUNK_SIZE
            with open(file_path, "rb") as f:
                # Move file pointer to resume position
                f.seek(resume_offset)
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    header = b"\x02" + struct.pack("!II", chunk_number, len(chunk))
                    packet = header + chunk

                    # wait for ACK(chuck_number) Reliable UDP transmission
                    while True:
                        self.udp_listener_socket.sendto(packet, (ip, udp_port))
                        if wait_for_ack(chunk_number):
                            break

                    yield chunk_number, len(chunk)
                    chunk_number += 1

            # -------------------------------------------------------
            # 3) SEND FILE_END
            # -------------------------------------------------------
            end_meta = {
                "filename": file_name,
                "sender": self.username
            }
            end_bytes = json.dumps(end_meta).encode("utf-8")
            packet = b"\x03" + struct.pack("!I", len(end_bytes)) + end_bytes

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
        Receive and decode UDP packets.
        Types:
            1 = FILE_START
            2 = FILE_CHUNK
            3 = FILE_END
            4 = ACK
            5 = FILE_RESUME  (receiver → sender)
        """
        try:
            data, addr = self.udp_listener_socket.recvfrom(CHUNK_SIZE + 100)
            if len(data) < 1:
                return None, None

            msg_type = data[0]      # first byte
            payload = data[1:]

            # -------------------------------------------------------
            # FILE_START
            # -------------------------------------------------------
            if msg_type == 1:
                meta_len = struct.unpack("!I", payload[:4])[0]
                meta = json.loads(payload[4:4+meta_len].decode("utf-8"))

                # ACK FILE_START
                ack_packet = b"\x04" + struct.pack("!I", 999999000)
                self.udp_listener_socket.sendto(ack_packet, addr)
                
                ####  This part is for the bonus (2)  #####
                # ===== RESUME SUPPORT =====
                filename = meta["filename"]
                sender_name = meta["sender"]
                partial_dir = "received_files"
                os.makedirs(partial_dir, exist_ok=True)

                partial_path = os.path.join(partial_dir, filename + ".part")

                # Determine how many bytes are already downloaded
                received_bytes = 0
                if os.path.exists(partial_path):
                    received_bytes = os.path.getsize(partial_path)

                # Send FILE_RESUME response (type 5)
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
            # FILE_CHUNK
            # -------------------------------------------------------
            if msg_type == 2:
                chunk_num, chunk_len = struct.unpack("!II", payload[:8])
                chunk_data = payload[8:8+chunk_len]

                # SEND ACK(chunk_num)
                ack_packet = b"\x04" + struct.pack("!I", chunk_num)
                self.udp_listener_socket.sendto(ack_packet, addr)

                return "FILE_CHUNK", (chunk_num, chunk_len, chunk_data)

            # -------------------------------------------------------
            # FILE_END
            # -------------------------------------------------------
            if msg_type == 3:
                meta_len = struct.unpack("!I", payload[:4])[0]
                meta = json.loads(payload[4:4+meta_len].decode("utf-8"))

                # SEND ACK
                ack_packet = b"\x04" + struct.pack("!I", 999999001)
                self.udp_listener_socket.sendto(ack_packet, addr)

                return "FILE_END", meta
            
            # -------------------------------------------------------
            # FILE_RESUME (Receiver tells sender how many bytes exist)
            # -------------------------------------------------------
            if msg_type == 5:
                meta_len = struct.unpack("!I", payload[:4])[0]
                meta = json.loads(payload[4:4+meta_len].decode("utf-8"))
                return "FILE_RESUME", meta
            
            # -------------------------------------------------------
            # ACK
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