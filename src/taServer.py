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
import IOT_Att as SWATT

# if got error install Crypto please usethis: 
#   >> pip install pycryptodome
#   from Crypto.Cipher import AES  #Works
# or 
#   >> pip install pycryptodomex
#   from Cryptodome.Cipher import AES 
# For python3 the package name is now pycryptodome or pycryptodomex
# If you need compatibility with your project with Python2 use pycryptodome
# or else use pycryptodomex which is a library independent of the old PyCrypto.
# https://stackoverflow.com/questions/51824628/modulenotfounderror-no-module-named-crypto-error
from Crypto.Cipher import AES


bind_ip = '0.0.0.0'
bind_port = 5007
CHA_LEN = 7     # default challenge we are going to use. 

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
        # Calculate the SWATT value
        self.challengeStr = ""
        self.swattHd = SWATT.swattCal()
        self.swattHd.setPuff(1549465112)

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

    def setSwattChalStr(self, challengeStr):

        if len(challengeStr) < CHA_LEN: 
            print("The challenge string is not long enough.")
            return
        self.challengeStr = challengeStr[:CHA_LEN]
        self.challengeB = bytes([ord(n) for n in self.challengeStr] + [ord('Z')]*25)
        self.encrypted = self.cipher.encrypt(self.challengeB)
        print(self.challengeB)
            
#-----------------------------------------------------------------------------
    def handle_client_connection(self, client_socket):
        request = client_socket.recv(32)
        print ('Received {}'.format(request))
        print ('Send the encrypted challenge bytes')
        client_socket.send(self.encrypted)
        # Calcualte the SWATT value for verification.
        result = self.swattHd.getSWATT(self.challengeStr, 300, "firmwareSample")
        print ('Received the SWATT bytes and decode:')
        request = client_socket.recv(32)
        data = self.cipher.decrypt(request)
        print(result)
        print("-------------")
        data = str(data).split('x0')[0]
        print(data)
        # The back data example is b'4098\x00ZZZZZZZZZZ'
        if int(data[2:-1]) == result: 
            print("The file Swatt value has been verified.")
        else: 
            print("The value are differet:"+str((data[2:-1]), result))

#-----------------------------------------------------------------------------
    def startServer(self):
        while True:
            print('Wait for connection')
            client_sock, address = self.server.accept()
            print ('Accepted connection from {}:{}'.format(address[0], address[1]))
            self.handle_client_connection(client_sock)
            client_sock.close()

#-----------------------------------------------------------------------------
def startServ():
    server = taServer()

    print("Server inited.")
    server.setSwattChalStr("abdcedfs")
    server.startServer()

if __name__ == '__main__':
    startServ()