"""
client.py - Main client application entry point
Initializes the GUI, network manager, and background threads for the chat application
"""
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
    """
    Main client class that coordinates the GUI, network manager, and background threads.
    Handles user authentication, key management, and message/file transfer coordination.
    """
    def __init__(self):
        """
        Initialize the chat client application.
        Prompts for username, loads or generates RSA keys, and sets up all components.
        """
        # Initialize Qt application
        self.app = QApplication(sys.argv)

        # Prompt user for username
        username, ok = QInputDialog.getText(
            None, 'Username', 'Enter your username:'
        )

        # Generate random username if user cancelled or entered empty string
        if not ok or not username.strip():
            username = 'User' + str(random.randint(1,1000))

        # Define paths for RSA key files
        priv_path = f"keys\\{username}_private.pem"
        pub_path = f"keys\\{username}_public.pem"

        # Load existing keys if they exist, otherwise generate new keypair
        if os.path.exists(priv_path) and os.path.exists(pub_path):
            private_key = load_private_key(priv_path)
            public_key = load_public_key(pub_path)
        else:
            # Generate new 2048-bit RSA keypair
            private_key, public_key = generate_rsa_keypair()
            # Ensure keys directory exists
            os.makedirs("keys", exist_ok=True)
            save_private_key(priv_path, private_key)
            save_public_key(pub_path, public_key)

        # Store username for later use
        self.username = username.strip()
        
        # Initialize network manager with user credentials
        self.network_manager = NetworkManager(
            username=self.username,
            private_key=private_key,
            public_key=public_key
        )

        # Initialize GUI with network manager reference
        self.gui = ChatWindow(self.network_manager)

        # Initialize thread references (will be created in start_threads)
        self.server_thread = None
        self.tcp_listener_thread = None
        self.udp_listener_thread = None

        # Track active file transfer threads
        self.active_file_transfers = []

        # Connect GUI signals to handler methods
        self.setup_connections()

        # Start background threads for networking
        self.start_threads()

    # ------------------- Setup -------------------

    def setup_connections(self):
        """
        Connect GUI button signals to their respective handler methods.
        """
        self.gui.send_button.clicked.connect(self.handle_send_message)
        self.gui.send_file_btn.clicked.connect(self.handle_send_file)

    # ------------------- Threads -------------------

    def start_threads(self):
        """
        Initialize and start all background threads for networking operations.
        Each thread handles a specific aspect of network communication.
        """
        # TCP listener thread: handles incoming chat messages from peers
        self.tcp_listener_thread = TCPListenerThread(self.network_manager)
        self.tcp_listener_thread.message_received.connect(self.gui.display_message)
        self.tcp_listener_thread.connection_closed.connect(self.on_peer_disconnected)
        self.tcp_listener_thread.start()

        # UDP listener thread: handles incoming file transfers from peers
        self.udp_listener_thread = UDPListenerThread(self.network_manager)
        self.udp_listener_thread.file_start_received.connect(self.gui.handle_file_start)
        self.udp_listener_thread.file_chunk_received.connect(self.gui.handle_file_chunk)
        self.udp_listener_thread.file_end_received.connect(self.gui.handle_file_end)
        self.udp_listener_thread.start()

        # Server communication thread: handles peer discovery and heartbeat
        self.server_thread = ServerCommunicationThread(self.network_manager)
        self.server_thread.peer_list_updated.connect(self.gui.update_peer_list)
        self.server_thread.server_connection_status.connect(self.gui.update_server_status)
        self.server_thread.start()

    def GenerateEncryptionKeys(self, bits = 2048):
        """
        Generate RSA keypair for encrypting AES symmetric keys during key exchange.
        Note: This method is not currently used; keys are generated in __init__.
        
        Args:
            bits: Key size in bits (default 2048)
            
        Returns:
            Tuple of (private_key, public_key)
        """
        import rsa
        public_key, private_key = rsa.newkeys(bits)
        return private_key, public_key

    # ------------------- Message Handling -------------------
    def handle_send_message(self):
        """
        Handle sending a text message to the selected peer.
        Called when the send button is clicked.
        """
        # Validate that a peer is selected
        if not self.gui.current_peer:
            QMessageBox.warning(self.gui, "Error", "Please select a peer first.")
            return

        # Get message text from input field
        message = self.gui.message_input.text().strip()
        if not message:
            return

        # Send message via network manager
        peer_username = self.gui.current_peer
        success = self.network_manager.send_tcp_message(peer_username, message)
        if success:
            self.gui.display_message("Me", message, True)
            self.gui.message_input.clear()
        else:
            # Show error if send failed
            self.gui.display_message("System", f"Failed to send message to {peer_username}")

    # ------------------- File Handling -------------------

    def handle_send_file(self):
        """
        Handle sending a file to the selected peer.
        Called when the send file button is clicked.
        """
        # Validate that a peer is selected
        if not self.gui.current_peer:
            QMessageBox.warning(self.gui, "Error", "Please select a peer first.")
            return

        # Open file dialog to select file
        from PyQt5.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getOpenFileName(
            self.gui, "Select File to Send", "", "All Files (*)"
        )

        if not file_path:
            return

        # Validate peer is in peer list
        peer_username = self.gui.current_peer
        if peer_username not in self.network_manager.peer_list:
            QMessageBox.warning(self.gui, "Error", "Peer not found in peer list.")
            return
        
        # Read file and display in chat as outgoing
        with open(file_path, "rb") as f:
            file_bytes = f.read()
        self.gui.add_clickable_file_message(
            os.path.basename(file_path), file_bytes, outgoing=True
        )

        # Start file transfer in a separate thread to avoid blocking GUI
        transfer_thread = FileTransferThread(self.network_manager, peer_username, file_path)
        transfer_thread.transfer_progress.connect(self.update_file_progress)
        
        # Define callback for when transfer completes
        def on_transfer_complete():
            self.file_transfer_complete()
            if transfer_thread in self.active_file_transfers:
                self.active_file_transfers.remove(transfer_thread)
        
        transfer_thread.transfer_complete.connect(on_transfer_complete)
        
        # Track and start the transfer thread
        self.active_file_transfers.append(transfer_thread)
        transfer_thread.start()

    def update_file_progress(self, chunk_number, chunk_size):
        """
        Update the GUI with file transfer progress.
        
        Args:
            chunk_number: Current chunk number being sent
            chunk_size: Size of the chunk in bytes
        """
        self.gui.file_progress_label.setText(f"Sent chunk {chunk_number}, size {chunk_size} bytes")

    def file_transfer_complete(self):
        """
        Called when file transfer is complete. Clears the progress label.
        """
        self.gui.file_progress_label.setText("")

    # ------------------- Peer Disconnect -------------------

    def on_peer_disconnected(self, peer_username):
        """
        Handle peer disconnection event.
        Disables chat functionality if the disconnected peer was the current chat partner.
        
        Args:
            peer_username: Username of the disconnected peer
        """
        if peer_username == self.gui.current_peer:
            # Disable chat UI if current peer disconnected
            self.gui.chat_header.setText("Peer disconnected. Select another peer.")
            self.gui.message_input.setEnabled(False)
            self.gui.send_button.setEnabled(False)
            self.gui.send_file_btn.setEnabled(False)

    # ------------------- Run -------------------

    def run(self):
        """
        Start the GUI application and enter the event loop.
        Sets up cleanup handlers for graceful shutdown.
        """
        # Show the main window
        self.gui.show()
        
        # Define cleanup function to be called on application exit
        def cleanup():
            """
            Cleanup function: stops all threads and closes network connections.
            """
            # Stop all background threads and wait for them to finish
            if self.server_thread:
                self.server_thread.stop()
                self.server_thread.wait()
            
            if self.tcp_listener_thread:
                self.tcp_listener_thread.stop()
                self.tcp_listener_thread.wait()
            
            if self.udp_listener_thread:
                self.udp_listener_thread.stop()
                self.udp_listener_thread.wait()
            
            # Close all network connections
            self.network_manager.close_all()
        
        # Connect cleanup to application quit signal
        self.app.aboutToQuit.connect(cleanup)
        
        # Start the Qt event loop
        sys.exit(self.app.exec_())



if __name__ == "__main__":
    """
    Application entry point.
    Creates and runs the chat client.
    """
    client = ChatClient()
    client.run()