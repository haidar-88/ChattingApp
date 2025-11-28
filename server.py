from socket import *
import json
import threading
import time

serverPort = 7777
serverIP = '127.0.0.1'
log_file = r'logs\server_log.jsonl'

active_clients = {} # {client_socket: {'addr': (ip, port), 'last_seen': timestamp}}

def write_to_log_file(ip, port, alive, timestamp):
    with open(log_file, 'a') as f:
        data = {"ip": ip, "port": port, "is_alive": alive, "time": timestamp}
        json.dump(data, f)
        f.write("\n")

def get_username_and_ports(clientSocket):
    try:
        data = clientSocket.recv(2048).decode()
        print("Received raw:", repr(data))

        user_part, ports_part = data.split("||")

        username = user_part.split(":")[1].strip()

        tcp_port = ports_part.split(",")[0].split(":")[1].strip()
        udp_port = ports_part.split(",")[1].split(":")[1].strip()

        return username, int(tcp_port), int(udp_port)

    except Exception as e:
        print("Error extracting client info:", e)
        return None, None, None

def handle_client(clientSocket, clientAddress):
    ip, port = clientAddress[0], clientAddress[1]
    username, tcp_port, udp_port = get_username_and_ports(clientSocket)

    if username is None:
        print("Client disconnected or sent invalid data.")
        clientSocket.close()
        return

    print(f'UPDATED CLIENT INFO: Client connected, IP: {ip}, Port With Server: {port}, Username: {username}, tcp port {tcp_port}, udp port {udp_port}')
    active_clients[username] = {
                        "socket": clientSocket,
                        "address": (ip, port),
                        "tcp_listener": tcp_port,
                        "udp_listener": udp_port,
                        "last_seen": time.time()
                    }
    clientSocket.settimeout(1)

    while True:
        try:
            try:
                message = clientSocket.recv(2048).decode()
                if not message:
                    print(f'Client closed connection, IP: {ip}, Port: {port}, time: {time.time()}')
                    write_to_log_file(ip, port, False, time.time())
                    active_clients.pop(username, None)
                    clientSocket.close()
                    return
                print('Received Message: ', repr(message))
                if message.upper().startswith('PEER_DISC'):
                    try:
                        peer_list = {
                            user: {
                                "ip": info["address"][0],
                                "tcp_port": info["tcp_listener"],
                                "udp_port": info["udp_listener"], 
                            }
                            for user, info in active_clients.items()
                        }
                        clientSocket.send(json.dumps(peer_list).encode())

                    except Exception as e: 
                        print('Error Sending Peer Discovery Content.')

                elif message.upper().startswith("PING"):
                    active_clients[username]['last_seen'] = time.time()
                    clientSocket.send('ACK'.encode())

            except timeout:
                    pass # no data received in this interval, continue
            
            if time.time() - active_clients[username]['last_seen'] > 60:
                print(f"Client timed out: {ip}:{port}")
                # Log to JSON file
                write_to_log_file(ip, port, False, time.time())
                clientSocket.close()
                active_clients.pop(username, None)
                break

        except ConnectionResetError:
            print(f"Client {ip}:{port} disconnected abruptly")
            write_to_log_file(ip, port, False, time.time())
            clientSocket.close()
            if username in active_clients:
                active_clients.pop(username, None)
            break

        except Exception as e:
            print("Handle Client Error: ", e)
            write_to_log_file(ip, port, False, time.time())
            clientSocket.close()
            if username in active_clients:
                active_clients.pop(username, None)
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
            client_main_thread = threading.Thread(target=handle_client, args=(clientSocket, clientAddress))
            client_main_thread.start()
        except Exception as e:
            print('Connection to Client Failed')
            continue