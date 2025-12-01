from PyQt5.QtCore import QThread, pyqtSignal
import time
import threading

# ------------------- Server Communication -------------------
class ServerCommunicationThread(QThread):
    peer_list_updated = pyqtSignal(dict)
    server_connection_status = pyqtSignal(bool)
    
    def __init__(self, network_manager):
        super().__init__()
        self.network_manager = network_manager
        self.running = True
    
    def run(self):
        if self.network_manager.connect_to_server():
            print('Connected to server')
        if self.network_manager.send_username_ports_key():
            print('Username and Ports sent')
        heartbeat_timer = 0
        while self.running:
            time.sleep(2)
            peers = self.network_manager.request_peer_list()
            #print('Peer List: ',[ name for name, info in peers.items()])
            self.peer_list_updated.emit(peers)
            if heartbeat_timer >= 30:
                if heartbeat_timer > 60:
                    self.stop()
                    continue
                print('sending heartbeat')
                connected = self.network_manager.send_heartbeat()
                if connected:
                    heartbeat_timer = 0
                self.server_connection_status.emit(connected)
            heartbeat_timer += 2
    
    def stop(self):
        self.server_connection_status.emit(False)
        self.running = False


# ------------------- TCP Listener -------------------
class TCPListenerThread(QThread):
    message_received = pyqtSignal(str, str)  # username, message
    connection_closed = pyqtSignal(str)      # peer_id
    
    def __init__(self, network_manager):
        super().__init__()
        self.network_manager = network_manager
        self.running = True
    
    def run(self):
        self.network_manager.start_tcp_listener()
        while self.running:
            result = self.network_manager.accept_tcp_connection()
            if result:
                client_socket, addr = result
                threading.Thread(
                    target=self.handle_peer,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
                
    def handle_peer(self, client_socket, addr):
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

            if peer_username not in self.network_manager.active_peer_connections:
                self.network_manager.active_peer_connections[peer_username] = client_socket

            # Emit message to GUI
            self.message_received.emit(peer_username, message)

        # Clean up socket
        try:
            client_socket.close()
        except:
            pass
            """peer_username, message = self.network_manager.receive_tcp_message(client_socket)
            if message is None:
                continue
            message = message.strip()
            self.message_received.emit(peer_username, message)"""

    
    def stop(self):
        self.running = False

# ------------------- UDP Listener -------------------
class UDPListenerThread(QThread):
    file_start_received = pyqtSignal(dict)
    file_chunk_received = pyqtSignal(tuple)
    file_end_received = pyqtSignal(dict)
    
    def __init__(self, network_manager):
        super().__init__()
        self.network_manager = network_manager
        self.running = True
    
    def run(self):
        self.network_manager.start_udp_listener()
        while self.running:
            msg_type, data = self.network_manager.receive_udp_message()
            #print("FROM THREADS IN UDP LISTENER TRYING TO SEE COMMUNICATION: ", msg_type, data)
            if msg_type == 'FILE_START':
                self.file_start_received.emit(data)
            elif msg_type == 'FILE_CHUNK':
                self.file_chunk_received.emit(data)
            elif msg_type == 'FILE_END':
                self.file_end_received.emit(data)
    
    def stop(self):
        self.running = False

# ------------------- File Transfer -------------------
class FileTransferThread(QThread):
    transfer_progress = pyqtSignal(int, int)  # chunk_number, chunk_size
    transfer_complete = pyqtSignal()
    
    def __init__(self, network_manager, peer_id, file_path):
        super().__init__()
        self.network_manager = network_manager
        self.peer_id = peer_id
        self.file_path = file_path
    
    def run(self):
        for chunk_number, chunk_size in self.network_manager.send_file_udp(self.peer_id, self.file_path):
            self.transfer_progress.emit(chunk_number, chunk_size)
        self.transfer_complete.emit()
        