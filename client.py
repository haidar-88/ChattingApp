# client.py
import sys
from PyQt5.QtWidgets import QApplication, QInputDialog, QMessageBox
from gui import ChatWindow
import random
from rsa_utils import *
import os

from network import NetworkManager
from threading_utils import (
    ServerCommunicationThread,
    TCPListenerThread,
    UDPListenerThread,
    FileTransferThread
)


class ChatClient:
    def __init__(self):
        self.app = QApplication(sys.argv)

        username, ok = QInputDialog.getText(
            None, 'Username', 'Enter your username:'
        )

        if not ok or not username.strip():
            username = 'User' + random.randint(1,1000)

        priv_path = f"keys\\{username}_private.pem"
        pub_path = f"keys\\{username}_public.pem"

        # Load if exists, else generate
        if os.path.exists(priv_path) and os.path.exists(pub_path):
            private_key = load_private_key(priv_path)
            public_key = load_public_key(pub_path)
        else:
            private_key, public_key = generate_rsa_keypair()
            save_private_key(priv_path, private_key)
            save_public_key(pub_path, public_key)

        # Initialize network manager
        self.network_manager = NetworkManager(
            username=username.strip(),
            private_key=private_key,
            public_key=public_key
        )

        # Initialize GUI
        self.gui = ChatWindow(self.network_manager)

        # Initialize threads
        self.server_thread = None
        self.tcp_listener_thread = None
        self.udp_listener_thread = None

        # Connect signals and slots
        self.setup_connections()

        # Start threads
        self.start_threads()

    # ------------------- Setup -------------------

    def setup_connections(self):
        self.gui.send_button.clicked.connect(self.handle_send_message)
        self.gui.send_file_btn.clicked.connect(self.handle_send_file)

    # ------------------- Threads -------------------

    def start_threads(self):
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

        # Server communication thread (peer list and heartbeat)
        self.server_thread = ServerCommunicationThread(self.network_manager)
        self.server_thread.peer_list_updated.connect(self.gui.update_peer_list)
        self.server_thread.server_connection_status.connect(self.gui.update_server_status)
        self.server_thread.start()


    def GenerateEncryptionKeys(bits = 2048): #RSA to enrcrypt the AES symmetric key in order to exchange it securly 
        public_key, private_key = rsa.newkeys(bits)
        return private_key, public_key

    # ------------------- Message Handling -------------------
    def handle_send_message(self):
        if not self.gui.current_peer:
            QMessageBox.warning(self.gui, "Error", "Please select a peer first.")
            return

        message = self.gui.message_input.text().strip()
        if not message:
            return

        peer_username = self.gui.current_peer
        success = self.network_manager.send_tcp_message(peer_username, message)
        if success:
            self.gui.display_message("Me", message, True)
            self.gui.message_input.clear()
        else:
            self.gui.display_message("System", f"Failed to send message to {peer_username}")

    # ------------------- File Handling -------------------

    def handle_send_file(self):
        if not self.gui.current_peer:
            QMessageBox.warning(self.gui, "Error", "Please select a peer first.")
            return

        from PyQt5.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getOpenFileName(
            self.gui, "Select File to Send", "", "All Files (*)"
        )

        if not file_path:
            return

        peer_username = self.gui.current_peer
        if peer_username not in self.network_manager.peer_list:
            QMessageBox.warning(self.gui, "Error", "Peer not found in peer list.")
            return

        # Start file transfer in a separate thread
        transfer_thread = FileTransferThread(self.network_manager, peer_username, file_path)
        transfer_thread.transfer_progress.connect(self.update_file_progress)
        transfer_thread.transfer_complete.connect(self.file_transfer_complete)
        transfer_thread.start()

    def update_file_progress(self, chunk_number, chunk_size):
        self.gui.file_progress_label.setText(f"Sent chunk {chunk_number}, size {chunk_size} bytes")

    def file_transfer_complete(self):
        self.gui.chat_display.append("File transfer completed")
        self.gui.file_progress_label.setText("")

    # ------------------- Peer Disconnect -------------------

    def on_peer_disconnected(self, peer_username):
        if peer_username == self.gui.current_peer:
            self.gui.chat_header.setText("Peer disconnected. Select another peer.")
            self.gui.message_input.setEnabled(False)
            self.gui.send_button.setEnabled(False)
            self.gui.send_file_btn.setEnabled(False)

    # ------------------- Run -------------------

    def run(self):
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



if __name__ == "__main__":
    client = ChatClient()
    client.run()