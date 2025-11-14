from socket import *
import threading
import json
import time

serverPort = 7777
serverIP = '127.0.0.1'
active_clients = {}
opened_chats = {}

def udp_receiver():
    return

def tcp_receiver(peerSocket):
    while True:
        try:
            data = peerSocket.recv(4096)
            if not data:
                break
            msg = data.decode()
            print(f"From: {peerSocket}, Message: {msg}")
            print("> ", end="", flush=True)
        except:
            break

def chat_loop():
    peer = input('Enter peer username')
    while True:
        peer_username, peer_ip, peer_port = active_clients[peer] #This wont work bcz dict doesnt have username as key
        try:                                                     #but I'll figure it out later...
            peerSocket = socket(AF_INET, SOCK_STREAM)
            peerSocket.connect((peer_ip, peer_port))
            opened_chats[peer_username] = peerSocket
            threading.Thread(target=tcp_receiver, args=(peerSocket,), daemon=True).start()
        except:
            print('Cannot open a Socket with Peer')

        next_action = input()
        if next_action.startswith("/new "): #if user entered to another chat we salt the beginning with 'New Chat'
            peer = active_clients[next_action.split('New Chat')[1]]
            continue
        send_message(peerSocket, next_action)

def send_message(peerSocket, message):
    try:
        peerSocket.send(message.encode())
    except:
        print('Cannot Send Message')

def send_file(peerSocket, message):
    return

def server_communication():
    try:
        clientSocket = socket(AF_INET, SOCK_STREAM)
        clientSocket.connect((serverIP, serverPort))
        clientSocket.settimeout(10) 
    except:
        print("Connection to Server Failed")
        exit(-1)

    request = "PEER_DISC".encode()
    heartbeat = "PING".encode()

    while True:
        try:
            clientSocket.send(request)
            print("Sent peer discovery request")
        except:
            print("Failed to send PEER_DISC")

        try:
            data = clientSocket.recv(4096)
            active_clients = json.loads(data.decode())
            print("Peers:", active_clients)
        except timeout:
            print("Timeout waiting for peer list")
        except:
            print("Error receiving peer file")

        time.sleep(30)

        try:
            clientSocket.send(heartbeat)
            print("PING sent")
        except:
            print("Failed to send PING")
            continue

        ack_received = False
        retries = 0
        MAX_RETRIES = 3
        while not ack_received and retries < MAX_RETRIES:
            try:
                resp = clientSocket.recv(1024).decode()
                if resp == "ACK":
                    print("ACK received")
                    ack_received = True
            except timeout:
                retries += 1
                print("ACK timeout. Retransmitting PING...")
                clientSocket.send(b"PING")
            except:
                print("Error waiting for ACK")

        if not ack_received:
            print("Server is unresponsive — closing connection")
            clientSocket.close()
            return


if __name__ == '__main__':
    server_thread = threading.Thread(target=server_communication, args=())
    server_thread.start()
    chat_loop()