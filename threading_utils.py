"""
threading_utils.py - Background thread classes for network operations
Provides QThread-based classes for handling server communication, TCP/UDP listeners,
and file transfers in separate threads to keep the GUI responsive.
"""
from PyQt5.QtCore import QThread, pyqtSignal
import time
import threading

# ------------------- Server Communication -------------------
class ServerCommunicationThread(QThread):
    """
    Background thread for server communication.
    Handles peer discovery requests and heartbeat monitoring.
    """
    # Qt signals for thread-safe GUI updates
    peer_list_updated = pyqtSignal(dict)  # Emitted when peer list changes
    server_connection_status = pyqtSignal(bool)  # Emitted when connection status changes
    
    def __init__(self, network_manager):
        """
        Initialize the server communication thread.
        
        Args:
            network_manager: NetworkManager instance to use for server operations
        """
        super().__init__()
        self.network_manager = network_manager
        self.running = True
    
    def run(self):
        """
        Main thread execution loop.
        Connects to server, sends registration, and periodically requests peer list and sends heartbeat.
        """
        # Connect to server
        if self.network_manager.connect_to_server():
            print('Connected to server')
        
        # Send registration information
        if self.network_manager.send_username_ports_key():
            print('Username and Ports sent')
        
        heartbeat_timer = 0
        while self.running:
            time.sleep(2)  # Wait 2 seconds between iterations
            
            # Request updated peer list
            peers = self.network_manager.request_peer_list()
            self.peer_list_updated.emit(peers)
            
            # Send heartbeat every 30 seconds, timeout after 60 seconds
            if heartbeat_timer >= 30:
                if heartbeat_timer > 60:
                    # Connection lost, stop thread
                    self.stop()
                    continue
                print('sending heartbeat')
                connected = self.network_manager.send_heartbeat()
                if connected:
                    heartbeat_timer = 0  # Reset timer on successful heartbeat
                self.server_connection_status.emit(connected)
            heartbeat_timer += 2
    
    def stop(self):
        """
        Stop the thread execution loop.
        """
        self.server_connection_status.emit(False)
        self.running = False


# ------------------- TCP Listener -------------------
class TCPListenerThread(QThread):
    """
    Background thread for listening to incoming TCP connections from peers.
    Accepts connections and spawns handler threads for each peer.
    """
    # Qt signals for thread-safe GUI updates
    message_received = pyqtSignal(str, str)  # Emitted when message received: (username, message)
    connection_closed = pyqtSignal(str)      # Emitted when peer disconnects: (peer_username)
    
    def __init__(self, network_manager):
        """
        Initialize the TCP listener thread.
        
        Args:
            network_manager: NetworkManager instance to use for TCP operations
        """
        super().__init__()
        self.network_manager = network_manager
        self.running = True
    
    def run(self):
        """
        Main thread execution loop.
        Starts TCP listener and accepts incoming peer connections.
        """
        self.network_manager.start_tcp_listener()
        while self.running:
            result = self.network_manager.accept_tcp_connection()
            if result:
                # New connection accepted, spawn handler thread
                client_socket, addr = result
                threading.Thread(
                    target=self.handle_peer,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
                
    def handle_peer(self, client_socket, addr):
        """
        Handle communication with a single peer connection.
        Runs in a separate thread for each peer.
        
        Args:
            client_socket: Socket connected to the peer
            addr: Peer address tuple (IP, port)
        """
        while self.running:
            peer_username, message, disconnected = self.network_manager.receive_tcp_message(client_socket)

            if disconnected:
                # Peer closed connection
                print(f"[TCP] Peer disconnected: {peer_username or addr}")
                if peer_username:
                    self.connection_closed.emit(peer_username)
                break

            if not message or not peer_username:
                continue

            # Update active connections if needed
            if peer_username not in self.network_manager.active_peer_connections:
                self.network_manager.active_peer_connections[peer_username] = client_socket

            # Emit message to GUI (thread-safe signal)
            self.message_received.emit(peer_username, message)

        # Clean up socket on exit
        try:
            client_socket.close()
        except:
            pass
    
    def stop(self):
        """
        Stop the thread execution loop.
        """
        self.running = False

# ------------------- UDP Listener -------------------
class UDPListenerThread(QThread):
    """
    Background thread for listening to incoming UDP file transfers from peers.
    Receives file transfer packets and emits signals for GUI handling.
    """
    # Qt signals for thread-safe GUI updates
    file_start_received = pyqtSignal(dict)    # Emitted when FILE_START received: (metadata)
    file_chunk_received = pyqtSignal(tuple)  # Emitted when FILE_CHUNK received: (chunk_info)
    file_end_received = pyqtSignal(dict)     # Emitted when FILE_END received: (metadata)
    
    def __init__(self, network_manager):
        """
        Initialize the UDP listener thread.
        
        Args:
            network_manager: NetworkManager instance to use for UDP operations
        """
        super().__init__()
        self.network_manager = network_manager
        self.running = True
    
    def run(self):
        """
        Main thread execution loop.
        Starts UDP listener and processes incoming file transfer packets.
        """
        self.network_manager.start_udp_listener()
        while self.running:
            msg_type, data = self.network_manager.receive_udp_message()
            
            # Route packet to appropriate signal based on type
            if msg_type == 'FILE_START':
                self.file_start_received.emit(data)
            elif msg_type == 'FILE_CHUNK':
                self.file_chunk_received.emit(data)
            elif msg_type == 'FILE_END':
                self.file_end_received.emit(data)
    
    def stop(self):
        """
        Stop the thread execution loop.
        """
        self.running = False

# ------------------- File Transfer -------------------
class FileTransferThread(QThread):
    """
    Background thread for sending files via UDP to a peer.
    Runs file transfer in background to avoid blocking the GUI.
    """
    # Qt signals for thread-safe GUI updates
    transfer_progress = pyqtSignal(int, int)  # Emitted per chunk: (chunk_number, chunk_size)
    transfer_complete = pyqtSignal()         # Emitted when transfer completes
    
    def __init__(self, network_manager, peer_id, file_path):
        """
        Initialize the file transfer thread.
        
        Args:
            network_manager: NetworkManager instance to use for file transfer
            peer_id: Username of the peer to send file to
            file_path: Path to the file to send
        """
        super().__init__()
        self.network_manager = network_manager
        self.peer_id = peer_id
        self.file_path = file_path
    
    def run(self):
        """
        Main thread execution.
        Sends file via UDP and emits progress signals.
        """
        # Send file and emit progress for each chunk
        for chunk_number, chunk_size in self.network_manager.send_file_udp(self.peer_id, self.file_path):
            self.transfer_progress.emit(chunk_number, chunk_size)
        # Signal completion
        self.transfer_complete.emit()
        