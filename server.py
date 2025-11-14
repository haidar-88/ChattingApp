from socket import *
import json
import threading
import time

serverPort = 7777
serverIP = '127.0.0.1'
log_file = 'logs\server_log.json'

active_clients = {} # {client_socket: {'addr': (ip, port), 'last_seen': timestamp}}

def write_to_log_file(ip, port, alive, time):
    with open(log_file, 'a') as f:
        data = {"ip": ip, "port": port, "is_alive": alive, "time": time}
        json.dump(data, f)

def handle_client(clientSocket, ip, port):
    active_clients[clientSocket] = {'addr': (ip, port), 'last_seen': time.time()}
    clientSocket.settimeout(1)
    while True:
        try:
            try:
                message = clientSocket.recv(2048).decode()
                if not message:
                    print(f'Client closed connection, IP: {ip}, Port: {port}, time: {time.time()}')
                    write_to_log_file(ip, port, False, time.time())
                    del active_clients[clientSocket]
                    clientSocket.close()
                    return
                
                if message.upper().startswith('PEER_DISC'):
                    try:
                        clientSocket.send(json.dumps({str(addr[1]): info['addr'] for addr, info in active_clients.items()}).encode())
                    except Exception as e: 
                        print('Error Sending Peer Discovery Content.')
                elif message.upper().startswith("PING"):
                    active_clients[clientSocket]['last_seen'] = time.time()
                    clientSocket.send('ACK'.encode())

            except socket.timeout:
                    pass # no data received in this interval, continue
            
            if time.time() - active_clients[clientSocket]['last_seen'] > 60:
                print(f"Client timed out: {ip}:{port}")
                # Log to JSON file
                write_to_log_file(ip, port, False, time.time())
                clientSocket.close()
                del active_clients[clientSocket]
                break

        except ConnectionResetError:
            print(f"Client {ip}:{port} disconnected abruptly")
            write_to_log_file(ip, port, False, time.time())
            clientSocket.close()
            if clientSocket in active_clients:
                del active_clients[clientSocket]
            break

        except Exception as e:
            print("Handle Client Error: ", e)
            write_to_log_file(ip, port, False, time.time())
            clientSocket.close()
            if clientSocket in active_clients:
                del active_clients[clientSocket]
            break

if __name__ == '__main__':
    try:
        serverSocket = socket(AF_INET, SOCK_STREAM)
        serverSocket.bind((serverIP, serverPort))
    except Exception as e:
        print('Creating or Binding Socket Failed')
        exit(-1)

    serverSocket.listen(5) # 5 Connection at a time
    print('Server is ready to receive connections')

    while True:
        try:
            clientSocket, clientAddress = serverSocket.accept()
            ip, port = clientAddress[0], clientAddress[1]
            print(f'Client connected, IP: {ip}, Port: {port}')
            write_to_log_file(ip, port, True, time.time())
        except Exception as e:
            print('Connection to Client Failed')
            continue

        client_main_thread = threading.Thread(target=handle_client, args=(clientSocket, ip, port))
        client_main_thread.start()
