"""
client.py - Main entry point for the P2P chat client application
Initializes PyQt GUI, network components, and threading
"""
import sys
from PyQt5.QtWidgets import QApplication, QInputDialog
from PyQt5.QtCore import Qt

from network import NetworkManager
from gui import ChatWindow
from threading_utils import (
    ServerCommunicationThread,
    TCPListenerThread,
    UDPListenerThread,
    FileTransferThread
)


class ChatClient:
    """Main client application class that coordinates all components"""
    
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setApplicationName("P2P Chat Application")
        
        # Get username from user
        username, ok = QInputDialog.getText(
            None, 'Username', 'Enter your username:',
            text='User'
        )
        if not ok or not username.strip():
            username = 'User'
        
        # Initialize network manager
        self.network_manager = NetworkManager(
            tcp_port=8888,  # Default TCP port for chat
            udp_port=9999,  # Default UDP port for file transfer
            username=username.strip()
        )
        
        # Initialize GUI
        self.gui = ChatWindow(self.network_manager)
        
        # Initialize threads
        self.server_thread = None
        self.tcp_listener_thread = None
        self.udp_listener_thread = None
        
        # Connect signals and slots
        self.setup_connections()
        
        # Start background threads
        self.start_threads()
    
    def setup_connections(self):
        """Connect GUI signals to network operations and thread signals to GUI slots"""
        # Connect GUI's send file button to file transfer handler
        self.gui.send_file_btn.clicked.connect(self.handle_send_file)
    
    def start_threads(self):
        """Start all background threads"""
        # Server communication thread (peer discovery and heartbeat)
        self.server_thread = ServerCommunicationThread(self.network_manager)
        self.server_thread.peer_list_updated.connect(self.gui.update_peer_list)
        self.server_thread.server_connection_status.connect(self.gui.update_server_status)
        self.server_thread.start()
        
        # TCP listener thread (incoming chat messages)
        self.tcp_listener_thread = TCPListenerThread(self.network_manager)
        self.tcp_listener_thread.message_received.connect(self.gui.display_message)
        self.tcp_listener_thread.connection_closed.connect(self.on_peer_disconnected)
        self.tcp_listener_thread.start()
        
        # UDP listener thread (incoming file transfers)
        self.udp_listener_thread = UDPListenerThread(self.network_manager)
        self.udp_listener_thread.file_start_received.connect(self.gui.handle_file_start)
        self.udp_listener_thread.file_chunk_received.connect(self.gui.handle_file_chunk)
        self.udp_listener_thread.file_end_received.connect(self.gui.handle_file_end)
        self.udp_listener_thread.start()
    
    def handle_send_file(self):
        """Handle file send request from GUI"""
        if not self.gui.current_peer:
            return
        
        from PyQt5.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getOpenFileName(
            self.gui, "Select File to Send", "", "All Files (*)"
        )
        if not file_path:
            return
        
        # UDP port should already be set in peer_info from server response
        # (we assume UDP port = TCP port + 1)
        peer_id = self.gui.current_peer
        if peer_id not in self.network_manager.peer_list:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self.gui, "Error", "Peer not found in peer list.")
            return
        
        # Start file transfer in separate thread
        transfer_thread = FileTransferThread(
            self.network_manager,
            peer_id,
            file_path
        )
        transfer_thread.transfer_progress.connect(self.gui.update_file_progress)
        transfer_thread.transfer_complete.connect(self.gui.file_transfer_complete)
        transfer_thread.start()
    
    def on_peer_disconnected(self, peer_id):
        """Handle peer disconnection"""
        if peer_id == self.gui.current_peer:
            self.gui.chat_header.setText("Peer disconnected. Select another peer.")
            self.gui.message_input.setEnabled(False)
            self.gui.send_button.setEnabled(False)
            self.gui.send_file_btn.setEnabled(False)
    
    def run(self):
        """Start the application main loop"""
        self.gui.show()
        
        # Cleanup on exit
        def cleanup():
            # Stop all threads
            if self.server_thread:
                self.server_thread.stop()
                self.server_thread.wait()
            
            if self.tcp_listener_thread:
                self.tcp_listener_thread.stop()
                self.tcp_listener_thread.wait()
            
            if self.udp_listener_thread:
                self.udp_listener_thread.stop()
                self.udp_listener_thread.wait()
            
            # Close network connections
            self.network_manager.close_all()
        
        self.app.aboutToQuit.connect(cleanup)
        
        sys.exit(self.app.exec_())


def main():
    """Main entry point"""
    client = ChatClient()
    client.run()


if __name__ == '__main__':
    main()
