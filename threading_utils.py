from PyQt5.QtCore import QThread, pyqtSignal # Base classes for threading and signals
import time
import threading # Standard Python threading for handling multiple concurrent peer connections

# ------------------- Server Communication (QThread) -------------------
class ServerCommunicationThread(QThread):
    """
    Handles continuous communication with the central discovery server, 
    including peer list requests and heartbeats.
    """
    # Signals emitted to the GUI thread
    peer_list_updated = pyqtSignal(dict)    # Emits the latest list of active peers
    server_connection_status = pyqtSignal(bool) # Emits True/False based on heartbeat success
    
    def __init__(self, network_manager):
        super().__init__()
        self.network_manager = network_manager
        self.running = True
    
    def run(self):
        """Main loop for server registration, peer discovery, and heartbeat."""
        # 1. Initial Connection and Registration
        if self.network_manager.connect_to_server():
            print('Connected to server')
        else:
            self.server_connection_status.emit(False)
            self.stop()
            return

        if self.network_manager.send_username_ports_key():
            print('Username and Ports sent')
        
        heartbeat_timer = 0
        
        # 2. Continuous Operation Loop
        while self.running:
            time.sleep(2)
            
            # Request and emit updated peer list every 2 seconds
            peers = self.network_manager.request_peer_list()
            self.peer_list_updated.emit(peers)
            
            heartbeat_timer += 2

            # Send Heartbeat (PING) every 30 seconds
            if heartbeat_timer >= 30:
                if heartbeat_timer > 60:
                    # Connection failed for two consecutive heartbeats (30s interval * 2)
                    self.stop()
                    continue
                
                print('sending heartbeat')
                connected = self.network_manager.send_heartbeat()
                
                if connected:
                    heartbeat_timer = 0
                
                # Signal the connection status back to the GUI
                self.server_connection_status.emit(connected)
    
    def stop(self):
        """Safely stops the thread and signals disconnection."""
        self.server_connection_status.emit(False)
        self.running = False


# ------------------- TCP Listener (QThread) -------------------
class TCPListenerThread(QThread):
    """
    Listens for incoming TCP connections (P2P chat) and delegates 
    the handling of each new connection to a separate standard Python thread.
    """
    # Signals emitted to the GUI thread
    message_received = pyqtSignal(str, str) # Emits received chat message (username, message content)
    connection_closed = pyqtSignal(str)     # Emits username when a peer disconnects
    
    def __init__(self, network_manager):
        super().__init__()
        self.network_manager = network_manager
        self.running = True
    
    def run(self):
        """Starts the main TCP listening socket and accepts new connections."""
        self.network_manager.start_tcp_listener()
        while self.running:
            # Non-blocking accept call
            result = self.network_manager.accept_tcp_connection()
            
            if result:
                client_socket, addr = result
                # Start a new, non-QThread to handle ongoing communication with this specific peer
                threading.Thread(
                    target=self.handle_peer,
                    args=(client_socket, addr),
                    daemon=True # Daemon threads exit when the main program does
                ).start()
                
    def handle_peer(self, client_socket, addr):
        """
        Runs in a standard thread to continuously receive messages from one peer.
        This isolates each peer's communication and decryption process.
        """
        peer_username = None # Initialize username for disconnection signal
        while self.running:
            # receive_tcp_message handles decryption and key exchange
            peer_username_temp, message, disconnected = self.network_manager.receive_tcp_message(client_socket)
            
            # Update peer_username if it becomes available (after AES key exchange)
            if peer_username_temp:
                peer_username = peer_username_temp 

            if disconnected:
                # Peer closed connection (gracefully or abruptly)
                print(f"[TCP] Peer disconnected: {peer_username or addr}")
                if peer_username:
                    self.connection_closed.emit(peer_username)
                break

            if not message or not peer_username:
                continue

            # Ensure the active socket is saved under the username in the NetworkManager
            if peer_username not in self.network_manager.active_peer_connections:
                self.network_manager.active_peer_connections[peer_username] = client_socket

            # Emit message to GUI (Safe signal to QThread)
            self.message_received.emit(peer_username, message)

        # Clean up socket when the inner loop breaks
        try:
            client_socket.close()
        except:
            pass
    
    def stop(self):
        """Safely stops the listener thread."""
        self.running = False

# ------------------- UDP Listener (QThread) -------------------
class UDPListenerThread(QThread):
    """
    Listens for incoming UDP packets related to file transfer (FILE_START, FILE_CHUNK, FILE_END).
    """
    # Signals emitted to the GUI thread for file transfer state management
    file_start_received = pyqtSignal(dict) # Signals new file transfer attempt (metadata)
    file_chunk_received = pyqtSignal(tuple) # Signals arrival of a data chunk
    file_end_received = pyqtSignal(dict) # Signals transfer completion
    
    def __init__(self, network_manager):
        super().__init__()
        self.network_manager = network_manager
        self.running = True
    
    def run(self):
        """Starts the UDP listening socket and processes incoming packets."""
        self.network_manager.start_udp_listener()
        while self.running:
            # receive_udp_message handles packet parsing and sends ACKs
            msg_type, data = self.network_manager.receive_udp_message()
            
            # Emit the corresponding signal based on the packet type
            if msg_type == 'FILE_START':
                self.file_start_received.emit(data)
            elif msg_type == 'FILE_CHUNK':
                self.file_chunk_received.emit(data)
            elif msg_type == 'FILE_END':
                self.file_end_received.emit(data)
    
    def stop(self):
        """Safely stops the UDP listener thread."""
        self.running = False

# ------------------- File Transfer (QThread) -------------------
class FileTransferThread(QThread):
    """
    Manages the outgoing file transfer process using the NetworkManager's UDP protocol.
    """
    # Signals emitted to update the GUI progress bar
    transfer_progress = pyqtSignal(int, int) # Emits current chunk number and size sent
    transfer_complete = pyqtSignal()
    
    def __init__(self, network_manager, peer_id, file_path):
        super().__init__()
        self.network_manager = network_manager
        self.peer_id = peer_id
        self.file_path = file_path
    
    def run(self):
        """
        Initiates the file sending process and yields progress updates.
        The `send_file_udp` function acts as a generator, yielding chunks as they are successfully sent and ACKed.
        """
        # Iterate over the progress generator returned by send_file_udp
        for chunk_number, chunk_size in self.network_manager.send_file_udp(self.peer_id, self.file_path):
            self.transfer_progress.emit(chunk_number, chunk_size)
            
        # Signal completion once the generator finishes
        self.transfer_complete.emit()