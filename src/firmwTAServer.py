#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        firmwTAServer.py
#
# Purpose:     Trust application TCP server. Send the challenge string to the 
#              trust app and decode the response swatt value.(AES256)
# Author:      Yuancheng Liu
#
# Created:     2019/05/08
# Copyright:   YC
# License:     YC
#-----------------------------------------------------------------------------
import socket
import IOT_Att as SWATT
import firmwMsgMgr

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

LOCAL_BIND_IP   = '0.0.0.0'
LOCAL_PORT      = 5007
DEFUALT_CH_LEN  = 7     # default challenge we are going to use. 

# AES parameters:
DE_BUFFER_SIZE = 32     # defialt AES cipher buffer size.
DE_AES_KEY  = bytes([0xa5]*32) # default AES Key
DE_AES_IV   = bytes([0xa5]*16) # default AES IV
#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class AESCipher:
    """ AES256 bytes data cipher, edit from the github project: 
        https://gist.github.com/swinton/8409454
    """

    def __init__(self, key, iv, mode):
        self.key = key
        self.iv = iv
        self.cipherMode = mode

    def updateParam(self, key=None, iv=None, mode=None):
        if key:self.key = key
        if iv:self.iv = iv
        if mode:self.cipherMode = mode

    def encrypt(self, raw):
        #iv =  bytes([0xa5]*16)
        #cipher = AES.new(self.key, AES.MODE_CBC, iv )
        cipher = AES.new(self.key, self.cipherMode, self.iv)
        return cipher.encrypt(raw)

    def decrypt(self, enc):
        #iv = bytes([0xa5]*16)
        #cipher = AES.new(self.key, AES.MODE_CBC, iv )
        cipher = AES.new(self.key, self.cipherMode, self.iv)
        return cipher.decrypt(enc)

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class firmwTAServer(object):
    
    def __init__(self):
        """ init the TCP socket, SWATT calculator and AES cipher."""
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind((LOCAL_BIND_IP, LOCAL_PORT))
            self.server.listen(1)  # max backlog of connections
            print('TA_Server: inited and listen on {}:{}'.format(
                LOCAL_BIND_IP, LOCAL_PORT))

            # Init the SWATT calculator.
            self.challengeStr = ""
            self.challengeLen = DEFUALT_CH_LEN
            self.swattHd = SWATT.swattCal()
            self.swattHd.setPuff(SWATT.DE_PUFF)

            # Init the message manager
            self.msgMgr= firmwMsgMgr.msgMgr(self) # create the message manager.

            # fixed AES key which is same as the trust APP's TA
            self.key = DE_AES_KEY
            self.challengeB = bytes([0x5a]*32)
            # init the AES cipher
            self.cipher = AESCipher(DE_AES_KEY, DE_AES_IV, AES.MODE_CBC)
            print("TA_Server: Init finished.")
        except:
            print("TA_Server: Init failed, termiate the program.")
            exit()

#-----------------------------------------------------------------------------
    def setSwattChalStr(self, challengeStr, challengelen=None):
        """ pad the input SWATT challengeStr"""
        if len(challengeStr) < self.challengeLen:
            print("TA_Server: The challenge string is not long enough.")
            return
        self.challengeLen = int(challengelen) if challengelen else DEFUALT_CH_LEN
        self.challengeStr = challengeStr[:self.challengeLen]
        # pad the input challenge string to bytes data with b'Z'.
        self.challengeB = bytes(
            [ord(n) for n in self.challengeStr] + [ord('Z')]*(DE_BUFFER_SIZE-self.challengeLen))

#-----------------------------------------------------------------------------
    def handle_client_connection(self, client_socket):
        
        #request = client_socket.recv(32)
        request = client_socket.recv(DE_BUFFER_SIZE)
        print ('TA_Server: Get message: {}'.format(request))
        data = self.msgMgr.loadMsg(request)
        # Set the challenge string based on the request.
        
        key_v, gw_id, pro_v, c_len, m , n, _ = str(data)[2:].split(';')
        print((key_v, gw_id, pro_v, c_len, m , n))

        swattStr = self.swattHd.randomChallStr(stringLength=int(c_len))
        self.setSwattChalStr(swattStr, challengelen=int(c_len))

        if(int(key_v)):
            print("TA_Server: user key version %s" %key_v)
            self.cipher.updateParam(key=DE_AES_KEY, iv=DE_AES_IV, mode=AES.MODE_CBC)
    
        print ('TA_Server:  Send the encrypted challenge bytes')
        self.encrypted = self.cipher.encrypt(self.challengeB)
        client_socket.send(self.encrypted)
           
        self.swattHd.setIterationNum(int(n))
        # Calcualte the SWATT value for verification.
        result = self.swattHd.getSWATT(self.challengeStr, int(m), "ran")
        result = int(result, 0) # hex string to int.
        print ('TA_Server:  SWATT result<%s>' % str(result))
        
        print("-------------")
        print ('TA_Server: Received the SWATT bytes and decode')
        #request = client_socket.recv(32)
        request = client_socket.recv(DE_BUFFER_SIZE)
        data = self.cipher.decrypt(request)
        data = str(data).split('x0')[0]
        print('TA_Server: Received the SWATT<%s>' %str(data))
        # The back data example is b'4098\x00ZZZZZZZZZZ'
        resp = 'T'
        if int(data[2:-1]) == result: 
            print("The file Swatt value has been verified.")
        else: 
            print("The value are differet:"+str((data[2:-1], result)))
            resp = 'F'
        self.challengeB = bytes([ord(resp)]+[ord(n) for n in self.challengeStr] + [ord('Z')]*(DE_BUFFER_SIZE-self.challengeLen-1))
        self.encrypted = self.cipher.encrypt(self.challengeB)
        client_socket.send(self.encrypted)
        request = client_socket.recv(1024)
        msg = str(self.msgMgr.loadMsg(request))[2:].split(';')
        if msg[0] == '': 
            print("The program is not running.")
        else: 
            for data in msg[:-1]:
                print(data)
        print("Finished the verification ")

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
    server = firmwTAServer()
    print("Server inited.")
    server.startServer()

if __name__ == '__main__':
    startServ()
