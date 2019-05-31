import socket
import threading
import time
from Crypto import Random
from Crypto.Cipher import AES

bind_ip = '0.0.0.0'
bind_port = 5005

class AESCipher:

    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        # iv = Random.new().read( AES.block_size )
        iv =  bytes([0xa5]*16)
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        #return base64.b64encode( cipher.encrypt( raw ) )
        return cipher.encrypt( raw )

    def decrypt( self, enc ):
        #enc = base64.b64decode(enc)
        iv = bytes([0xa5]*16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return cipher.decrypt(enc)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((bind_ip, bind_port))
server.listen(5)  # max backlog of connections

print ('Listening on {}:{}'.format(bind_ip, bind_port))
<<<<<<< HEAD

key = bytes([0xa5]*32)
cipher = AESCipher(key)
encrypted = cipher.encrypt(bytes([0x5a]*32))

decrypted = cipher.decrypt(encrypted)
print (encrypted)
print (decrypted)
count = 0 

def handle_client_connection(client_socket):
    request = client_socket.recv(32)
    print ('Received {}'.format(request))
    client_socket.send(encrypted)
    request = client_socket.recv(32)
    data = cipher.decrypt(encrypted)
    print(data)
=======

key = bytes([0xa5]*32)
cipher = AESCipher(key)
encrypted = cipher.encrypt(bytes([0xa5]*32))
decrypted = cipher.decrypt(encrypted)
print (encrypted)
print (decrypted)

def handle_client_connection(client_socket):
    while True:
        request = client_socket.recv(32)
        print ('Received {}'.format(request))
        client_socket.send(encrypted)
>>>>>>> 2f8068e1730b966836e03398c4982cde43cd33f8

while True:
    client_sock, address = server.accept()
    print ('Accepted connection from {}:{}'.format(address[0], address[1]))
<<<<<<< HEAD
    target=handle_client_connection(client_sock)
    client_sock.close()
=======
    target=handle_client_connection(client_sock) 
>>>>>>> 2f8068e1730b966836e03398c4982cde43cd33f8
