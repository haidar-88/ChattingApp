"""
network.py - Core networking functionality for TCP chat and UDP file transfer
Handles all socket operations, peer discovery, and server communication
"""
from socket import *
import json
import time
import os
import struct

# Server configuration
serverPort = 7777
serverIP = '127.0.0.1'

# File transfer configuration
CHUNK_SIZE = 4096  # 4KB chunks for UDP file transfer

"""Manages all network operations including server communication, TCP chat, and UDP file transfer"""
class NetworkManager:

    def __init__(self, username):
        # assign a random free port to avoid conflicts
        self.username = username
        self.tcp_port = 0
        self.udp_port = 0
        self.server_socket = None
        self.tcp_listener_socket = None
        self.udp_listener_socket = None
        self.active_peer_connections = {}
        self.peer_list = {}
        self.running = False

# -------------------------------------------------------------
# Server Connection & Communication
# -------------------------------------------------------------
    def connect_to_server(self):
        try:
            self.server_socket = socket(AF_INET, SOCK_STREAM)
            self.server_socket.connect((serverIP, serverPort))
            return True
        except Exception as e:
            print(f"Connection to server failed: {e}")
            return False
        
    def send_username_and_ports(self):
        try:
            self.server_socket.send(f"USERNAME:{self.username}||tcp_port:{self.tcp_port}, udp_port:{self.udp_port}".encode())
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
    
# -------------------------------------------------------------
# TCP LISTENER
# -------------------------------------------------------------
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
        
    def receive_tcp_message(self, peer_socket):
        try:
            data = peer_socket.recv(4096)
            if not data:
                return ""  # connection closed
            return data.decode()

        except timeout:
            return None, None
        except:
            return "NULLLL"

















    
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
            return sock

        except Exception as e:
            print(f"Failed to connect to peer {peer_username}: {e}")
            return None
    
    def send_tcp_message(self, peer_username, message):
        sock = self.connect_to_peer_tcp(peer_username)
        if not sock:
            return False
        
        try:
            info = f"{peer_username}|{message}"
            sock.send(info.encode())
            
            return True
        except Exception:
            self.active_peer_connections.pop(peer_username, None)
            return False
    


    # -------------------------------------------------------------
    # UDP LISTENER
    # -------------------------------------------------------------
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
        udp_port = peer["udp_port"]

        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)

        try:
            # Send metadata
            meta = {"type": "FILE_START", "filename": file_name, "size": file_size, "sender": self.username}
            meta_bytes = json.dumps(meta).encode("utf-8")
            header = struct.pack("!I", len(meta_bytes))
            self.udp_listener_socket.sendto(header + meta_bytes, (peer["ip"], udp_port))

            chunk_number = 0
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    header = struct.pack("!II", chunk_number, len(chunk))
                    self.udp_listener_socket.sendto(header + chunk, (peer["ip"], udp_port))
                    chunk_number += 1

                    yield chunk_number, len(chunk)

            # End packet
            end_meta = {"type": "FILE_END", "filename": file_name, "sender": self.username}
            end_bytes = json.dumps(end_meta).encode("utf-8")
            header = struct.pack("!I", len(end_bytes))
            self.udp_listener_socket.sendto(header + end_bytes, (peer["ip"], udp_port))

            return True

        except Exception as e:
            print(f"Error sending file via UDP: {e}")
            return False

    def receive_udp_message(self):
        if not self.udp_listener_socket:
            return None, None, None
        
        try:
            data, addr = self.udp_listener_socket.recvfrom(65536)
            if len(data) < 4:
                return None, None, None

            # metadata?
            header_len = struct.unpack("!I", data[:4])[0]
            if 0 < header_len < len(data):
                try:
                    meta = json.loads(data[4:4+header_len].decode("utf-8"))
                    if meta["type"] in ("FILE_START", "FILE_END"):
                        return meta["type"], meta, addr
                except:
                    pass

            # chunk
            if len(data) >= 8:
                chunk_num = struct.unpack("!I", data[0:4])[0]
                chunk_len = struct.unpack("!I", data[4:8])[0]
                return "FILE_CHUNK", (chunk_num, data[8:8+chunk_len]), addr

            return None, None, None

        except timeout:
            return None, None, None
        except Exception as e:
            print(f"Error receiving UDP message: {e}")
            return None, None, None

    # -------------------------------------------------------------
    # CLOSE ALL
    # -------------------------------------------------------------
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
