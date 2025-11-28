# gui.py (username-based chat)
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget,
    QTextEdit, QLineEdit, QPushButton, QFileDialog
)
from PyQt5.QtCore import Qt

class ChatWindow(QMainWindow):
    def __init__(self, network_manager):
        super().__init__()
        self.network_manager = network_manager
        self.setWindowTitle("P2P Chat Application")
        self.setGeometry(100, 100, 700, 500)

        self.current_peer = None
        self.file_transfer_total = 0
        self.file_transfer_received = 0

        # Chat history keyed by username
        self.chat_history = {}

        # Main widget & layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        self.main_layout = QVBoxLayout()
        main_widget.setLayout(self.main_layout)

        # Server status
        self.server_status_label = QLabel("Server: Unknown")
        self.main_layout.addWidget(self.server_status_label)

        # Peer list (usernames)
        self.peer_list_widget = QListWidget()
        self.peer_list_widget.itemClicked.connect(self.on_peer_selected)
        self.main_layout.addWidget(self.peer_list_widget)

        # Chat header
        self.chat_header = QLabel("Select a peer to start chat")
        self.main_layout.addWidget(self.chat_header)

        # Chat display
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.main_layout.addWidget(self.chat_display)

        # Message input & send button
        input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setEnabled(False)
        self.send_button = QPushButton("Send")
        self.send_button.setEnabled(False)
        
        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_button)
        self.main_layout.addLayout(input_layout)

        # File send button
        self.send_file_btn = QPushButton("Send File")
        self.send_file_btn.setEnabled(False)
        self.send_file_btn.clicked.connect(self.select_and_send_file)
        self.main_layout.addWidget(self.send_file_btn)

        # File progress label
        self.file_progress_label = QLabel("")
        self.main_layout.addWidget(self.file_progress_label)

    # ======================== Server Methods ========================
    def update_server_status(self, status: bool):
        self.server_status_label.setText("Server: Online" if status else "Server: Offline")

    def update_peer_list(self, peers: list):
        """peers is now a list of usernames"""
        self.peer_list_widget.clear()
        for username in peers:
            self.peer_list_widget.addItem(username)
            if username not in self.chat_history:
                self.chat_history[username] = []

    # ======================== Peer Selection ========================
    def on_peer_selected(self, item):
        self.current_peer = item.text()
        self.chat_header.setText(f"Chatting with: {self.current_peer}")
        self.message_input.setEnabled(True)
        self.send_button.setEnabled(True)
        self.send_file_btn.setEnabled(True)
        self.update_chat_display()

    # ======================== Chat Display ========================
    def display_message(self, username, message):
        """
        username: sender of the message (peer or self)
        message: message text
        """
        if username not in self.chat_history:
            self.chat_history[username] = []
        self.chat_history[username].append((username, message))
        self.chat_display.append(f"{username}: {message}")
    
    def update_chat_display(self):
        """Refresh chat display for currently selected username"""
        self.chat_display.clear()
        if not self.current_peer:
            return
        for username, message in self.chat_history.get(self.current_peer, []):
            self.chat_display.append(f"{username}: {message}")

    # ======================== File Transfer ========================
    def select_and_send_file(self):
        if not self.current_peer:
            return
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if file_path:
            self.chat_display.append(f"Sending file: {file_path}")
            for chunk_number, chunk_size in self.network_manager.send_file_udp(self.current_peer, file_path):
                self.file_progress_label.setText(f"Sent chunk {chunk_number}, size {chunk_size} bytes")
            self.chat_display.append("File transfer completed")
            self.file_progress_label.setText("")

    def handle_file_start(self, metadata, addr=None):
        sender_username = metadata.get("sender", self.current_peer)
        self.display_message("System", f"Receiving file: {metadata['filename']} from {sender_username}")
        self.file_transfer_total = metadata.get("size", 0)
        self.file_transfer_received = 0
        self.file_progress_label.setText(f"Receiving: {metadata['filename']} 0%")

    def handle_file_chunk(self, chunk_info, addr=None):
        chunk_number, chunk_size = chunk_info
        self.file_transfer_received += chunk_size
        percent = int((self.file_transfer_received / self.file_transfer_total) * 100) if self.file_transfer_total else 0
        self.file_progress_label.setText(f"Receiving: {percent}%")

    def handle_file_end(self, metadata, addr=None):
        sender_username = metadata.get("sender", self.current_peer)
        self.display_message("System", f"File received: {metadata['filename']} from {sender_username}")
        self.file_progress_label.setText("")
