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
SERVER_IP = '127.0.0.1'
SERVER_PORT = 7777

# Default ports for client services
DEFAULT_TCP_PORT = 8888
DEFAULT_UDP_PORT = 9999

# File transfer configuration
CHUNK_SIZE = 4096  # 4KB chunks for UDP file transfer


class NetworkManager:
    """Manages all network operations including server communication, TCP chat, and UDP file transfer"""
    
    def __init__(self, tcp_port=DEFAULT_TCP_PORT, udp_port=DEFAULT_UDP_PORT, username=""):
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.username = username
        self.server_socket = None
        self.tcp_listener_socket = None
        self.udp_socket = None
        self.active_peer_connections = {}  # {peer_id: socket} for TCP connections
        self.peer_list = {}  # {peer_id: {'ip': ip, 'port': port, 'username': username}}
        self.running = False
        
    def connect_to_server(self):
        """Establish connection to central server for peer discovery"""
        try:
            self.server_socket = socket(AF_INET, SOCK_STREAM)
            self.server_socket.connect((SERVER_IP, SERVER_PORT))
            self.server_socket.settimeout(10)
            return True
        except Exception as e:
            print(f"Connection to Server Failed: {e}")
            return False
    
    def request_peer_list(self):
        """Request list of active peers from server"""
        if not self.server_socket:
            return {}
        
        try:
            self.server_socket.send("PEER_DISC".encode())
            data = self.server_socket.recv(4096)
            if data:
                # Server returns dict mapping port (str) to (ip, port) tuple
                # Format: {str(port): [ip, port]} or {str(port): (ip, port)}
                try:
                    server_data = json.loads(data.decode())
                except json.JSONDecodeError:
                    print("Invalid JSON response from server")
                    return {}
                
                # Convert to our format: {peer_id: {'ip': ip, 'port': int(port), 'username': '', 'udp_port': port+1}}
                updated_peers = {}
                
                if not isinstance(server_data, dict):
                    print(f"Unexpected server response format: {type(server_data)}")
                    return {}
                
                for port_str, addr_data in server_data.items():
                    try:
                        if isinstance(addr_data, list) and len(addr_data) >= 2:
                            ip = addr_data[0]
                            port = int(addr_data[1]) if isinstance(addr_data[1], (int, str)) else addr_data[1]
                            peer_id = f"{ip}:{port}"
                            updated_peers[peer_id] = {
                                'ip': ip,
                                'port': port,
                                'udp_port': port + 1,  # Assume UDP port is TCP port + 1
                                'username': f"Peer-{port_str}"
                            }
                        elif isinstance(addr_data, tuple) and len(addr_data) >= 2:
                            ip = addr_data[0]
                            port = int(addr_data[1]) if isinstance(addr_data[1], (int, str)) else addr_data[1]
                            peer_id = f"{ip}:{port}"
                            updated_peers[peer_id] = {
                                'ip': ip,
                                'port': port,
                                'udp_port': port + 1,
                                'username': f"Peer-{port_str}"
                            }
                        elif isinstance(addr_data, dict):
                            # Handle dict format if server changes
                            ip = addr_data.get('ip', '')
                            port = addr_data.get('port', 0)
                            peer_id = f"{ip}:{port}"
                            updated_peers[peer_id] = {
                                'ip': ip,
                                'port': port,
                                'udp_port': addr_data.get('udp_port', port + 1),
                                'username': addr_data.get('username', f"Peer-{port_str}")
                            }
                    except Exception as e:
                        print(f"Error parsing peer data for {port_str}: {e}")
                        continue
                
                self.peer_list = updated_peers
                return updated_peers
        except timeout:
            print("Timeout waiting for peer list")
            return {}
        except Exception as e:
            print(f"Error receiving peer list: {e}")
            return {}
    
    def send_heartbeat(self):
        """Send PING heartbeat to server"""
        if not self.server_socket:
            return False
        
        try:
            self.server_socket.send("PING".encode())
            # Wait for ACK
            try:
                resp = self.server_socket.recv(1024).decode()
                if resp == "ACK":
                    return True
            except timeout:
                return False
        except Exception as e:
            print(f"Error sending heartbeat: {e}")
            return False
    
    def start_tcp_listener(self):
        """Start TCP listener socket for receiving chat messages"""
        try:
            self.tcp_listener_socket = socket(AF_INET, SOCK_STREAM)
            self.tcp_listener_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            self.tcp_listener_socket.bind(('0.0.0.0', self.tcp_port))
            self.tcp_listener_socket.listen(5)
            self.tcp_listener_socket.settimeout(1.0)  # Non-blocking with timeout
            return True
        except Exception as e:
            print(f"Failed to start TCP listener: {e}")
            return False
    
    def accept_tcp_connection(self):
        """Accept incoming TCP connection (non-blocking)"""
        if not self.tcp_listener_socket:
            return None
        
        try:
            client_socket, addr = self.tcp_listener_socket.accept()
            peer_id = f"{addr[0]}:{addr[1]}"
            return client_socket, peer_id, addr
        except timeout:
            return None
        except Exception as e:
            print(f"Error accepting TCP connection: {e}")
            return None
    
    def connect_to_peer_tcp(self, peer_id):
        """Establish TCP connection to a peer for chat"""
        if peer_id not in self.peer_list:
            return None
        
        if peer_id in self.active_peer_connections:
            return self.active_peer_connections[peer_id]
        
        try:
            peer_info = self.peer_list[peer_id]
            peer_socket = socket(AF_INET, SOCK_STREAM)
            peer_socket.connect((peer_info['ip'], peer_info['port']))
            self.active_peer_connections[peer_id] = peer_socket
            return peer_socket
        except Exception as e:
            print(f"Failed to connect to peer {peer_id}: {e}")
            return None
    
    def send_tcp_message(self, peer_id, message):
        """Send a chat message via TCP to a peer"""
        peer_socket = self.connect_to_peer_tcp(peer_id)
        if not peer_socket:
            return False
        
        try:
            # Format: username|message
            formatted_message = f"{self.username}|{message}"
            peer_socket.send(formatted_message.encode('utf-8'))
            return True
        except Exception as e:
            print(f"Error sending TCP message: {e}")
            # Connection may be broken, remove it
            if peer_id in self.active_peer_connections:
                del self.active_peer_connections[peer_id]
            return False
    
    def receive_tcp_message(self, peer_socket):
        """Receive a message from TCP socket
        
        Returns:
            tuple: (username, message) if message received
            tuple: (None, None) if no data (timeout)
            tuple: ("", "") if connection closed (empty recv)
        """
        try:
            peer_socket.settimeout(0.1)  # Short timeout for non-blocking
            data = peer_socket.recv(4096)
            if data:
                message = data.decode('utf-8')
                # Parse format: username|message
                if '|' in message:
                    username, msg = message.split('|', 1)
                    return username, msg
                return "Unknown", message
            else:
                # Empty data means connection closed
                return "", ""
        except timeout:
            return None, None
        except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
            # Connection error - connection is closed
            return "", ""
        except Exception as e:
            print(f"Error receiving TCP message: {e}")
            return "", ""
    
    def start_udp_listener(self):
        """Start UDP socket for file transfer"""
        try:
            self.udp_socket = socket(AF_INET, SOCK_DGRAM)
            self.udp_socket.bind(('0.0.0.0', self.udp_port))
            self.udp_socket.settimeout(1.0)  # Non-blocking with timeout
            return True
        except Exception as e:
            print(f"Failed to start UDP listener: {e}")
            return False
    
    def send_file_udp(self, peer_id, file_path):
        """Send a file to peer via UDP in chunks"""
        if peer_id not in self.peer_list:
            return False
        
        if not os.path.exists(file_path):
            return False
        
        peer_info = self.peer_list[peer_id]
        # Get UDP port, default to TCP port + 1 if not set
        udp_port = peer_info.get('udp_port', peer_info.get('port', DEFAULT_UDP_PORT) + 1)
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        
        try:
            # Send file metadata first (filename and size)
            metadata = {
                'type': 'FILE_START',
                'filename': file_name,
                'size': file_size,
                'sender': self.username
            }
            metadata_msg = json.dumps(metadata).encode('utf-8')
            # Prefix with message type identifier
            header = struct.pack('!I', len(metadata_msg))
            self.udp_socket.sendto(header + metadata_msg, (peer_info['ip'], udp_port))
            
            # Send file in chunks
            chunk_number = 0
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    # Pack chunk data: chunk_number, chunk_data
                    chunk_header = struct.pack('!II', chunk_number, len(chunk))
                    self.udp_socket.sendto(chunk_header + chunk, (peer_info['ip'], udp_port))
                    chunk_number += 1
                    
                    yield chunk_number, len(chunk)  # Progress callback
            
            # Send file end marker
            end_metadata = {
                'type': 'FILE_END',
                'filename': file_name,
                'sender': self.username
            }
            end_msg = json.dumps(end_metadata).encode('utf-8')
            header = struct.pack('!I', len(end_msg))
            self.udp_socket.sendto(header + end_msg, (peer_info['ip'], udp_port))
            
            return True
        except Exception as e:
            print(f"Error sending file via UDP: {e}")
            return False
    
    def receive_udp_message(self):
        """Receive UDP message (for file transfer or other UDP messages)"""
        if not self.udp_socket:
            return None, None, None
        
        try:
            data, addr = self.udp_socket.recvfrom(65536)  # Max UDP packet size
            if len(data) < 4:
                return None, None, None
            
            # Try to parse as metadata message (JSON)
            header_length = struct.unpack('!I', data[:4])[0]
            if header_length > 0 and header_length < len(data):
                try:
                    metadata_json = data[4:4+header_length].decode('utf-8')
                    metadata = json.loads(metadata_json)
                    if metadata.get('type') == 'FILE_START':
                        return 'FILE_START', metadata, addr
                    elif metadata.get('type') == 'FILE_END':
                        return 'FILE_END', metadata, addr
                except:
                    pass
            
            # Parse as file chunk: chunk_number (4 bytes) + chunk_length (4 bytes) + data
            if len(data) >= 8:
                chunk_number = struct.unpack('!I', data[0:4])[0]
                chunk_length = struct.unpack('!I', data[4:8])[0]
                chunk_data = data[8:8+chunk_length]
                return 'FILE_CHUNK', (chunk_number, chunk_data), addr
            
            return None, None, None
        except timeout:
            return None, None, None
        except Exception as e:
            print(f"Error receiving UDP message: {e}")
            return None, None, None
    
    def close_all(self):
        """Close all sockets and clean up"""
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        for peer_socket in self.active_peer_connections.values():
            try:
                peer_socket.close()
            except:
                pass
        self.active_peer_connections.clear()
        
        if self.tcp_listener_socket:
            try:
                self.tcp_listener_socket.close()
            except:
                pass
        
        if self.udp_socket:
            try:
                self.udp_socket.close()
            except:
                pass
