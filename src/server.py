import socket
import threading
import time
bind_ip = '0.0.0.0'
bind_port = 5005

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((bind_ip, bind_port))
server.listen(5)  # max backlog of connections

print 'Listening on {}:{}'.format(bind_ip, bind_port)


def handle_client_connection(client_socket):
    while True:
        request = client_socket.recv(1024)
        print 'Received {}'.format(request)
        client_socket.send(b'123123')
        time.sleep(1)

while True:
    client_sock, address = server.accept()
    print 'Accepted connection from {}:{}'.format(address[0], address[1])
    target=handle_client_connection(client_sock) 
