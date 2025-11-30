# gui_modern.py
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget,
    QLineEdit, QPushButton, QFileDialog, QScrollArea, QSizePolicy
)
from PyQt5.QtCore import Qt
import os
from network import CHUNK_SIZE

class ChatWindow(QMainWindow):
    def __init__(self, network_manager):
        super().__init__()
        self.network_manager = network_manager
        self.setWindowTitle(f"ChatX Application | Username: {self.network_manager.username}")
        self.setGeometry(100, 100, 700, 500)

        self.current_peer = None
        self.file_transfer_total = 0
        self.file_transfer_received = 0

        self.incoming_file_name = None
        self.incoming_file_buffer = None
        self.file_transfer_done = False

        self.chat_history = {}  # Stores both text and files per peer

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        self.main_layout = QVBoxLayout()
        main_widget.setLayout(self.main_layout)

        # Server status
        self.server_status_label = QLabel("Server Status: Please Wait")
        self.main_layout.addWidget(self.server_status_label)

        # Peer list
        self.peer_list_widget = QListWidget()
        self.peer_list_widget.itemClicked.connect(self.on_peer_selected)
        self.main_layout.addWidget(self.peer_list_widget)

        # Chat header
        self.chat_header = QLabel("Select a peer to start chat")
        self.main_layout.addWidget(self.chat_header)

        # Chat display area with scroll
        self.chat_area_widget = QWidget()
        self.chat_area_layout = QVBoxLayout()
        self.chat_area_layout.setAlignment(Qt.AlignTop)
        self.chat_area_widget.setLayout(self.chat_area_layout)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setWidget(self.chat_area_widget)
        self.scroll_area.setStyleSheet("background-color: #f2f2f2; border: none;")
        self.scroll_area.setMinimumHeight(300)
        self.main_layout.addWidget(self.scroll_area)

        # Message input
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

        self.file_progress_label = QLabel("")
        self.main_layout.addWidget(self.file_progress_label)

    # ======================== Server & Peer ========================
    def update_server_status(self, status: bool):
        self.server_status_label.setText("Server: Online" if status else "Server: Offline")

    def update_peer_list(self, peers: list):
        self.peer_list_widget.clear()
        for username in peers:
            self.peer_list_widget.addItem(username)
            if username not in self.chat_history:
                self.chat_history[username] = []

    def on_peer_selected(self, item):
        self.current_peer = item.text()
        self.chat_header.setText(f"Chatting with: {self.current_peer}")
        self.message_input.setEnabled(True)
        self.send_button.setEnabled(True)
        self.send_file_btn.setEnabled(True)
        self.update_chat_display()

    # ======================== Chat Display ========================
    def display_message(self, username, message, outgoing=False):
        # Store text messages in history
        if self.current_peer and {"type": "text", "content": message, "outgoing": outgoing} not in self.chat_history[self.current_peer]:
            self.chat_history[self.current_peer].append({"type": "text", "content": message, "outgoing": outgoing})

        # Bubble style
        bubble = QLabel(message)
        bubble.setWordWrap(True)
        bubble.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)  # adaptive width
        bubble.setStyleSheet(
            f"""
            padding:8px;
            border-radius:12px;
            background-color: {'#dcf8c6' if outgoing else '#ffffff'};
            color: #000;
            font-size: 14px;
            """
        )

        # Dynamically set max width based on scroll area width
        max_width = int(self.scroll_area.width() * 0.6)
        bubble.setMaximumWidth(max_width)

        # Add username for incoming messages
        container = QVBoxLayout()
        container.addWidget(bubble)
        container_widget = QWidget()
        container_widget.setLayout(container)

        # Align left/right
        align_layout = QHBoxLayout()
        if outgoing:
            align_layout.addStretch()
            align_layout.addWidget(container_widget)
        else:
            align_layout.addWidget(container_widget)
            align_layout.addStretch()
        align_widget = QWidget()
        align_widget.setLayout(align_layout)

        self.chat_area_layout.addWidget(align_widget)
        self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().maximum())

    def update_chat_display(self):
        # Clear current chat area
        for i in reversed(range(self.chat_area_layout.count())):
            widget = self.chat_area_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        if not self.current_peer:
            return

        # Render chat history (text + files)
        for item in self.chat_history.get(self.current_peer, []):
            if item["type"] == "text":
                self.display_message(self.current_peer, item["content"], outgoing=item["outgoing"])
            elif item["type"] == "file":
                # Only add clickable file once
                self.add_clickable_file_message(item["filename"], item["data"], outgoing=item["outgoing"], add_to_history=False)

    # ======================== File Transfer ========================
    def select_and_send_file(self):
        if not self.current_peer:
            return
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if file_path:
            for chunk_number, chunk_size in self.network_manager.send_file_udp(self.current_peer, file_path):
                self.file_progress_label.setText(f"Sent chunk {chunk_number}, size {chunk_size} bytes")
            self.file_progress_label.setText("")

            with open(file_path, "rb") as f:
                file_bytes = f.read()
            self.add_clickable_file_message(os.path.basename(file_path), file_bytes, outgoing=True)

    def handle_file_start(self, metadata, addr=None):
        print("DEBUG handle_file_start called:", metadata)
        self.file_transfer_done = False
        #self.incoming_file_name = metadata.get("filename")
        self.file_transfer_total = metadata.get("size", 0)
        self.file_transfer_received = 0
        self.incoming_file_name = metadata["filename"]

        #os.makedirs("received_files", exist_ok=True)
        #self.incoming_file_path = os.path.join("received_files", self.incoming_file_name + ".part")
        self.incoming_file_buffer = bytearray()
        partial_dir = "received_files"
        os.makedirs(partial_dir, exist_ok=True)
        self.incoming_file_path = os.path.join(partial_dir, self.incoming_file_name + ".part")

        ### 
        self.received_chunks = set()
        progress_path = self.incoming_file_path + ".progress"
        if os.path.exists(progress_path):
            with open(progress_path, "r") as f:
                self.received_chunks = set(map(int, f.read().split(',')))
        ###

        # Load existing partial file if exists
        if os.path.exists(self.incoming_file_path):
            self.incoming_file_buffer = bytearray(open(self.incoming_file_path, "rb").read())
        else:
            self.incoming_file_buffer = bytearray()
        #self.file_transfer_received = len(self.incoming_file_buffer)
        ######self.file_progress_label.setText(f"Receiving: {self.incoming_file_name} 0%")
        #percent = int((self.file_transfer_received / self.file_transfer_total) * 100) if self.file_transfer_total else 0
        #self.file_progress_label.setText(f"Receiving: {self.incoming_file_name} {percent}%")
        total_chunks = (self.file_transfer_total + CHUNK_SIZE - 1) // CHUNK_SIZE
        percent = int((len(self.received_chunks) / total_chunks) * 100) if self.file_transfer_total else 0
        self.file_progress_label.setText(f"Receiving: {self.incoming_file_name} {percent}%")

        # Notify sender of current received bytes for resuming
        if addr:  # addr is the UDP sender's address
            resume_msg = {
                "filename": self.incoming_file_name,
                #"received": self.
                "received_chunks": list(self.received_chunks)
            }
            resume_bytes = json.dumps(resume_msg).encode('utf-8')
            #packet = b"\x05" + struct.pack("!I", len(json.dumps(resume_msg))) + json.dumps(resume_msg).encode()
            packet = b"\x05" + struct.pack("!I", len(resume_bytes)) + resume_bytes
            self.network_manager.udp_listener_socket.sendto(packet, addr)

        print(f"Started receiving file: {self.incoming_file_name}, size: {self.file_transfer_total}")

    def handle_file_chunk(self, chunk_info, addr=None):
        chunk_num, chunk_len, chunk_bytes = chunk_info
        start_pos = chunk_num * CHUNK_SIZE
        end_pos = start_pos + chunk_len

        if start_pos >= len(self.incoming_file_buffer):
            self.incoming_file_buffer.extend(chunk_bytes)
            self.file_transfer_received += chunk_len
        else:
            overlap = len(self.incoming_file_buffer) - start_pos
            if overlap < chunk_len:
                self.incoming_file_buffer.extend(chunk_bytes[overlap:])
                self.file_transfer_received += (chunk_len - overlap)

        with open(self.incoming_file_path, "wb") as f:
            f.write(self.incoming_file_buffer)

        print("CHUNK:", chunk_num)
        print("Received so far:", self.file_transfer_received)
        print("Total size:", self.file_transfer_total)
        
        ###
        self.received_chunks.add(chunk_num)

        # Update progress bar
        total_chunks = (self.file_transfer_total + CHUNK_SIZE - 1) // CHUNK_SIZE
        percent = int((len(self.received_chunks) / total_chunks) * 100)
        self.file_progress_label.setText(f"Receiving: {self.incoming_file_name} {percent}%")

        # Save progress to disk for resuming
        progress_path = self.incoming_file_path + ".progress"
        with open(progress_path, "w") as pf:
            pf.write(','.join(map(str, self.received_chunks))) 
        ###
        #percent = int((self.file_transfer_received / self.file_transfer_total) * 100) if self.file_transfer_total else 0
        #self.file_progress_label.setText(f"Receiving: {self.incoming_file_name} {percent}%")

    def handle_file_end(self, metadata, addr=None):
        print("DEBUG handle_file_end called. metadata:", metadata, "current incoming_file_name:", self.incoming_file_name)
        if self.file_transfer_done:
            print("IGNORED duplicate FILE_END")
            return
        self.file_transfer_done = True

        final_filename = metadata.get("filename") or self.incoming_file_name
        if not final_filename:
            print("ERROR: No filename for FILE_END")
            return

        final_dir = "received_files"
        os.makedirs(final_dir, exist_ok=True)
        final_path = os.path.join(final_dir, final_filename)

        with open(final_path, "wb") as f:
            f.write(self.incoming_file_buffer)

        print(f"File saved: {final_path}")

        if self.incoming_file_path and os.path.exists(self.incoming_file_path):
            os.remove(self.incoming_file_path)

        self.add_clickable_file_message(final_filename, self.incoming_file_buffer, outgoing=False)
        self.incoming_file_buffer = None
        self.incoming_file_name = None
        self.incoming_file_path = None
        self.file_transfer_total = 0
        self.file_transfer_received = 0
        self.file_progress_label.setText("")

    def add_clickable_file_message(self, file_name, file_bytes, outgoing=False, add_to_history=True):
        if add_to_history and self.current_peer:
            if self.current_peer not in self.chat_history:
                self.chat_history[self.current_peer] = []
            # Avoid duplicates
            if {"type": "file", "filename": file_name, "data": file_bytes, "outgoing": outgoing} not in self.chat_history[self.current_peer]:
                self.chat_history[self.current_peer].append({
                    "type": "file",
                    "filename": file_name,
                    "data": file_bytes,
                    "outgoing": outgoing
                })

        btn = QPushButton(f"📎 {file_name}")
        btn.setStyleSheet(
            "text-align:left; background:#e0e0ff; padding:8px; border-radius:12px; font-size:14px;"
        )
        btn.clicked.connect(lambda: self.save_received_file(file_name, file_bytes))

        align_layout = QHBoxLayout()
        if outgoing:
            align_layout.addStretch()
            align_layout.addWidget(btn)
        else:
            align_layout.addWidget(btn)
            align_layout.addStretch()

        container = QWidget()
        container.setLayout(align_layout)
        self.chat_area_layout.addWidget(container)
        self.scroll_area.verticalScrollBar().setValue(
            self.scroll_area.verticalScrollBar().maximum()
        )

    def save_received_file(self, file_name, file_bytes):
        save_path, _ = QFileDialog.getSaveFileName(self, "Save File", file_name)
        if save_path:
            with open(save_path, "wb") as f:
                f.write(file_bytes)
            self.display_message("System", f"File saved: {save_path}")
