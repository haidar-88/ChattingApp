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

    def __init__(self, username, private_key, public_key):
        self.username = username
        self.private_key = private_key
        self.public_key = public_key
        self.tcp_port = 0
        self.udp_port = 0
        self.server_socket = None
        self.tcp_listener_socket = None
        self.udp_listener_socket = None
        self.active_peer_connections = {}
        self.peer_list = {}
        self.running = False

        self.aes_key = generate_aes_key()
        self.peer_aes_keys = {}

    # -----------------------------
    # Server Connection & Communication
    # -----------------------------
    def connect_to_server(self):
        try:
            self.server_socket = socket(AF_INET, SOCK_STREAM)
            self.server_socket.connect((serverIP, serverPort))
            return True
        except Exception as e:
            print(f"Connection to server failed: {e}")
            return False

    def send_username_ports_key(self):
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
        if not self.server_socket:
            return False
        try:
            self.server_socket.send("PING".encode())
            if self.server_socket.recv(1024).decode() == "ACK":
                return True
        except:
            pass
        return False

    # -----------------------------
    # TCP Listener
    # -----------------------------
    def start_tcp_listener(self):
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
        try:
            client_socket, addr = self.tcp_listener_socket.accept()
            return client_socket, addr
        except timeout:
            return None
        except Exception as e:
            print(f"Error accepting TCP connection: {e}")
            return None

    def connect_to_peer_tcp(self, peer_username):
        """Establish TCP connection to a peer"""
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
        try:
            data = peer_socket.recv(8192)
            if not data:
                return ""

            message = data.decode()
            print(message)

            # If AES_KEY, save it with a temporary key
            if message.startswith("AES_KEY:"):
                encrypted_key_b64 = message[len("AES_KEY:"):]
                encrypted_bytes = base64.b64decode(encrypted_key_b64)
                aes_key = rsa.decrypt(encrypted_bytes, self.private_key)
                print('AES Key decrypted:', aes_key)

                # Use the socket's id as a temporary key
                temp_key = id(peer_socket)
                self.peer_aes_keys[temp_key] = aes_key
                print('Saved AES key temporarily:', self.peer_aes_keys)
                return (None, None)

            print('Before Splitting and Decrypting: ', message)
            # For normal messages
            if "|" in message:
                peer_username, enc_bytes = message.split("|", 1)
                if peer_username not in self.active_peer_connections:
                    self.active_peer_connections[peer_username] = peer_socket

                # If AES key was stored under temporary key, move it to real username
                temp_key = id(peer_socket)
                if temp_key in self.peer_aes_keys:
                    self.peer_aes_keys[peer_username] = self.peer_aes_keys.pop(temp_key)

                if peer_username in self.peer_aes_keys:
                    # Convert base64 back to bytes
                    encrypted_bytes = base64.b64decode(enc_bytes)
                    plaintext = aes_decrypt(self.peer_aes_keys[peer_username], encrypted_bytes)
                    return (peer_username, plaintext.decode())
                else:
                    return (None, "[Encrypted message, AES key not established]")

        except timeout:
            return (None, None)
        except Exception as e:
            print(f"Error decrypting TCP message: {e}")
            return (None, None)

    def send_tcp_message(self, peer_username, message):
        sock = self.connect_to_peer_tcp(peer_username)
        if not sock:
            return False
        
        try:
            plaintext = message.encode()
            encrypted_bytes = aes_encrypt(self.aes_key, plaintext)
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode()  # safe string

            info = f"{peer_username}|{encrypted_b64}"
            sock.send(info.encode())  # now this is safe
            return True

        except Exception:
            self.active_peer_connections.pop(peer_username, None)
            return False


    # -----------------------------
    # UDP Listener
    # -----------------------------
    def start_udp_listener(self):
        """Start UDP listener with dynamic port if needed"""
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
            """Wait for a specific ACK ID, resend packet if timeout."""
            self.udp_listener_socket.settimeout(timeout_sec)
            try:
                data, _ = self.udp_listener_socket.recvfrom(1024)
                if data[0] == 4:  # ACK
                    ack_id = struct.unpack("!I", data[1:5])[0]
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

            reserved_ack = 999999000
            while True:
                self.udp_listener_socket.sendto(packet, (ip, udp_port))
                if wait_for_ack(reserved_ack):
                    break

            # -------------------------------------------------------
            # 2) SEND FILE CHUNKS WITH ACKs
            # -------------------------------------------------------
            chunk_number = 0
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    header = b"\x02" + struct.pack("!II", chunk_number, len(chunk))
                    packet = header + chunk

                    # wait for ACK(chuck_number)
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

            return True

        except Exception as e:
            print("Error sending file via UDP:", e)
            return False

    def receive_udp_message(self):
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

                # SEND ACK
                ack_packet = b"\x04" + struct.pack("!I", 999999000)
                self.udp_listener_socket.sendto(ack_packet, addr)

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
