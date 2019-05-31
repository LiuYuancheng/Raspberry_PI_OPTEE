#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        taServer.py
#
# Purpose:     Trust application TCP server. Send the challenge data to the 
#              trust app and decode the response swatt value.(AES256)
# Author:      Yuancheng Liu
#
# Created:     2019/05/08
# Copyright:   YC
# License:     YC
#-----------------------------------------------------------------------------
import socket
import threading
import time
from Crypto import Random
from Crypto.Cipher import AES


bind_ip = '0.0.0.0'
bind_port = 5007

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class AESCipher:
    """ Bytes AES256 cipher"""

    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        iv =  bytes([0xa5]*16)
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return cipher.encrypt( raw )

    def decrypt( self, enc ):
        iv = bytes([0xa5]*16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return cipher.decrypt(enc)

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class taServer(object):
    
    def __init__(self):
        """ init the TCP socket."""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((bind_ip, bind_port))
        self.server.listen(5)  # max backlog of connections
        print ('Listening on {}:{}'.format(bind_ip, bind_port))

        # fixed AES key which is same as the trust APP's TA
        self.key = bytes([0xa5]*32)
        self.challengeB = bytes([0x5a]*32)
        # init the AES cipher
        self.cipher = AESCipher(self.key)
        self.encrypted = self.cipher.encrypt(self.challengeB)
        self.decrypted = self.cipher.decrypt(self.encrypted)
        print (self.encrypted)
        print (self.decrypted)
        print ("Init finished")

#-----------------------------------------------------------------------------
    def handle_client_connection(self, client_socket):
        request = client_socket.recv(32)
        print ('Received {}'.format(request))
        print ('Send the encrypted challenge bytes')
        client_socket.send(self.encrypted)
        
        print ('Received the SWATT bytes and decode:')
        request = client_socket.recv(32)
        data = self.cipher.decrypt(request)
        print(data)

#-----------------------------------------------------------------------------
    def startServer(self):
        while True:
            print('Wait for connection')
            client_sock, address = self.server.accept()
            print ('Accepted connection from {}:{}'.format(address[0], address[1]))
            target = self.handle_client_connection(client_sock)
            client_sock.close()

#-----------------------------------------------------------------------------
def startServ():
    server = taServer()
    print("Server inited.")
    server.startServer()

if __name__ == '__main__':
    startServ()