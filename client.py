from socket import *

serverPort = 7777
serverIP = '127.0.0.1'

try:
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((serverIP, serverPort))
except:
    print('Connection Failed')
    exit(-1)

request = 'PEER_DISC'.encode()

while True:
    try:
        clientSocket.send(request)
        print('Request sent')
        break
    except:
        print('Failed to Fetch Peers')

try:
    peers = clientSocket.recv(1024)
    if peers > 0:
        peers = peers.decode()
    else:
        print('Error')
except:
    print('Error receiving peer file')

print(peers)

clientSocket.close()