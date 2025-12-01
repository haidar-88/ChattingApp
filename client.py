# client.py
import sys
import random
import os
# Import necessary PyQt5 modules for GUI
from PyQt5.QtWidgets import QApplication, QInputDialog, QMessageBox

# Import the main GUI window class
from gui import ChatWindow

# Import RSA utility functions for key management
from rsa_utils import *

# Import the network management class
from network import NetworkManager

# Import custom threading classes for concurrent operations
from threading_utils import (
    ServerCommunicationThread,  # Handles registration, peer list, and heartbeat
    TCPListenerThread,          # Listens for incoming chat messages (TCP)
    UDPListenerThread,          # Listens for incoming file chunks (UDP)
    FileTransferThread          # Handles sending files (UDP)
)


class ChatClient:
    """
    The main class for the P2P chat client application.
    Manages the GUI, network connections, RSA keys, and background threads.
    """
    def __init__(self):
        # Initialize the PyQt application instance
        self.app = QApplication(sys.argv)

        # Prompt the user for a username upon starting the client
        username, ok = QInputDialog.getText(
            None, 'Username', 'Enter your username:'
        )

        # If the user cancels or enters an empty username, generate a random one
        if not ok or not username.strip():
            username = 'User' + str(random.randint(1, 1000))

        # Define file paths for storing the client's RSA keys
        priv_path = f"keys\\{username}_private.pem"
        pub_path = f"keys\\{username}_public.pem"

        # --- RSA Key Management ---
        # Load existing keys if they exist, otherwise generate a new key pair
        if os.path.exists(priv_path) and os.path.exists(pub_path):
            private_key = load_private_key(priv_path)
            public_key = load_public_key(pub_path)
        else:
            private_key, public_key = generate_rsa_keypair()
            # Save the newly generated keys
            save_private_key(priv_path, private_key)
            save_public_key(pub_path, public_key)
        # --- End Key Management ---

        # Initialize the NetworkManager with the username and RSA keys
        self.network_manager = NetworkManager(
            username=username.strip(),
            private_key=private_key,
            public_key=public_key
        )

        # Initialize the GUI (ChatWindow)
        self.gui = ChatWindow(self.network_manager)

        # Initialize thread placeholders
        self.server_thread = None
        self.tcp_listener_thread = None
        self.udp_listener_thread = None

        # List to keep track of active file transfer threads
        self.active_file_transfers = []

        # Connect GUI signals (button clicks) to handler methods
        self.setup_connections()

        # Start all required background threads
        self.start_threads()

    # ------------------- Setup -------------------

    def setup_connections(self):
        """Connects GUI elements (signals) to their corresponding handler methods (slots)."""
        self.gui.send_button.clicked.connect(self.handle_send_message)
        self.gui.send_file_btn.clicked.connect(self.handle_send_file)

    # ------------------- Threads -------------------

    def start_threads(self):
        """Initializes and starts all background listener and communication threads."""
        
        # TCP listener thread (for incoming chat messages)
        self.tcp_listener_thread = TCPListenerThread(self.network_manager)
        self.tcp_listener_thread.message_received.connect(self.gui.display_message)
        self.tcp_listener_thread.connection_closed.connect(self.on_peer_disconnected)
        self.tcp_listener_thread.start()

        # UDP listener thread (for incoming file transfer chunks)
        self.udp_listener_thread = UDPListenerThread(self.network_manager)
        # Connect signals for various stages of file reception to GUI handlers
        self.udp_listener_thread.file_start_received.connect(self.gui.handle_file_start)
        self.udp_listener_thread.file_chunk_received.connect(self.gui.handle_file_chunk)
        self.udp_listener_thread.file_end_received.connect(self.gui.handle_file_end)
        self.udp_listener_thread.start()

        # Server communication thread (for peer list updates and heartbeat)
        self.server_thread = ServerCommunicationThread(self.network_manager)
        self.server_thread.peer_list_updated.connect(self.gui.update_peer_list)
        self.server_thread.server_connection_status.connect(self.gui.update_server_status)
        self.server_thread.start()


     def GenerateEncryptionKeys(self, bits = 2048): #RSA to enrcrypt the AES symmetric key in order to exchange it securly 
         public_key, private_key = rsa.newkeys(bits)
         return private_key, public_key

    # ------------------- Message Handling -------------------
    def handle_send_message(self):
        """Handles sending a text message when the 'Send' button is clicked."""
        if not self.gui.current_peer:
            QMessageBox.warning(self.gui, "Error", "Please select a peer first.")
            return

        message = self.gui.message_input.text().strip()
        if not message:
            return

        peer_username = self.gui.current_peer
        # Use the NetworkManager to send the message via TCP
        success = self.network_manager.send_tcp_message(peer_username, message)
        
        if success:
            # Display the sent message in the local chat window
            self.gui.display_message("Me", message, True)
            self.gui.message_input.clear()
        else:
            self.gui.display_message("System", f"Failed to send message to {peer_username}")

    # ------------------- File Handling -------------------

    def handle_send_file(self):
        """Handles selecting a file and initiating a file transfer."""
        if not self.gui.current_peer:
            QMessageBox.warning(self.gui, "Error", "Please select a peer first.")
            return

        # Use QFileDialog to let the user select a file
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
        
        # Read the file content to display a clickable placeholder for the user
        with open(file_path, "rb") as f:
            file_bytes = f.read()
        self.gui.add_clickable_file_message(
            os.path.basename(file_path), file_bytes, outgoing=True
        )

        # Start the file transfer in a separate FileTransferThread (uses UDP)
        transfer_thread = FileTransferThread(self.network_manager, peer_username, file_path)
        transfer_thread.transfer_progress.connect(self.update_file_progress)
        
        # Define a cleanup function to run upon transfer completion
        def on_transfer_complete():
            self.file_transfer_complete()
            # Remove the thread from the active transfers list
            if transfer_thread in self.active_file_transfers:
                self.active_file_transfers.remove(transfer_thread)
        
        transfer_thread.transfer_complete.connect(on_transfer_complete)
        
        self.active_file_transfers.append(transfer_thread)
        transfer_thread.start()

    def update_file_progress(self, chunk_number, chunk_size):
        """Updates the GUI with the current file transfer progress."""
        self.gui.file_progress_label.setText(f"Sent chunk {chunk_number}, size {chunk_size} bytes")

    def file_transfer_complete(self):
        """Clears the progress label once a file transfer is done."""
        self.gui.file_progress_label.setText("")

    # ------------------- Peer Disconnect -------------------

    def on_peer_disconnected(self, peer_username):
        """Handles the event when a connected peer disconnects."""
        if peer_username == self.gui.current_peer:
            # Disable chat input if the disconnected peer was the current one
            self.gui.chat_header.setText("Peer disconnected. Select another peer.")
            self.gui.message_input.setEnabled(False)
            self.gui.send_button.setEnabled(False)
            self.gui.send_file_btn.setEnabled(False)

    # ------------------- Run -------------------

    def run(self):
        """Shows the GUI and enters the application's event loop."""
        self.gui.show()
        
        # Cleanup on exit: ensure all background threads are stopped gracefully
        def cleanup():
            # Stop the Server Communication thread
            if self.server_thread:
                self.server_thread.stop()
                self.server_thread.wait()
            
            # Stop the TCP Listener thread
            if self.tcp_listener_thread:
                self.tcp_listener_thread.stop()
                self.tcp_listener_thread.wait()
            
            # Stop the UDP Listener thread
            if self.udp_listener_thread:
                self.udp_listener_thread.stop()
                self.udp_listener_thread.wait()
            
            # Close all network sockets
            self.network_manager.close_all()
        
        # Connect the cleanup function to the application's aboutToQuit signal
        self.app.aboutToQuit.connect(cleanup)
        
        # Start the PyQt event loop
        sys.exit(self.app.exec_())


if __name__ == "__main__":
    # Entry point for the client application
    client = ChatClient()
    client.run()