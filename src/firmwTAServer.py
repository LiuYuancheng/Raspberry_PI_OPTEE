#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        firmwTAServer.py
#
# Purpose:     Trust application TCP server. Send the AES 256 session key and 
#              swatt challenge string to the trust app and decode the response
#              swatt value.(AES256)
# Author:      Yuancheng Liu
#
# Created:     2019/05/08
# Copyright:   NUS – Singtel Cyber Security Research & Development Laboratory
# License:     YC @ NUS
#-----------------------------------------------------------------------------
import socket
import IOT_Att as SWATT
import firmwMsgMgr
import firmwGlobal as gv

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
        self.iv = iv
        self.key = key
        self.cipherMode = mode

    def updateParam(self, key=None, iv=None, mode=None):
        if iv:  self.iv = iv
        if key: self.key = key
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
    """ Trust application TCP server. Send the AES 256 session key and 
        swatt challenge string to the trust app and decode the response
        swatt value.(AES256)
    """
    def __init__(self):
        """ init the TCP socket, SWATT calculator and AES cipher."""
        try:
            # Init the TCP server. 
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind((LOCAL_BIND_IP, gv.TCTCP_PORT)) # port 5007
            self.server.listen(1)  # max backlog of connections
            print('TA_Server: inited and listen on {}:{}'.format(
                LOCAL_BIND_IP, gv.TCTCP_PORT))
            # Init the SWATT calculator.
            self.challengeStr = ""
            self.challengeLen = DEFUALT_CH_LEN
            self.challengeB = bytes([0x5a]*32)  # defualt challenge bytes list. 
            self.swattHd = SWATT.swattCal()
            self.swattHd.setPuff(SWATT.DE_PUFF)
            # Init the message manager.
            self.msgMgr= firmwMsgMgr.msgMgr(self) # create the message manager.
            # Fixed AES256 key which is same as the trust APP's TA
            self.key = DE_AES_KEY # Comm session key after connection authorization. 
            # Init the AES cipher
            self.cipher = AESCipher(DE_AES_KEY, DE_AES_IV, AES.MODE_CBC)
            # Init checking file name/path
            self.filename = "ran"

            print("TA_Server: Init finished.")
        except Exception as e:
            print("TA_Server: Init failed, termiate the program. Exception: %s" %str(e))
            exit()

#--firmwTAServer---------------------------------------------------------------
    def exchangeSessionKey(self, client_socket, key_v):
        """ Create the random 32bytes AES256 encryption/decryption session key, 
            encrypted the session key with defualt key and send to the client.
            session key: 32bytes list will all lower case letters.
        """
        print("TA_Server: user comm key version <%s>." % key_v)
        self.cipher.updateParam(
            key=DE_AES_KEY, iv=DE_AES_IV, mode=AES.MODE_CBC)
        sessionKey = self.swattHd.randomChallStr(stringLength=32)
        print("Send the session key used to encryption/decryptiuon: <%s>" % sessionKey)
        self.key = bytes([ord(n) for n in sessionKey])
        self.encrypted = self.cipher.encrypt(self.key)
        client_socket.send(self.encrypted)
        request = client_socket.recv(DE_BUFFER_SIZE)
        data = self.msgMgr.loadMsg(request)
        print('TA_Server: Get client session key set message: {}'.format(data))
        # Switch to use the new session key.
        self.cipher.updateParam(key=self.key, iv=DE_AES_IV, mode=AES.MODE_CBC)

#--firmwTAServer---------------------------------------------------------------
    def handleClientConnection(self, client_socket):
        """ Handle the connection request of the TCP client."""
        request = client_socket.recv(DE_BUFFER_SIZE)
        print ('TA_Server: Get connection request message: {}'.format(request))
        data = self.msgMgr.loadMsg(request)
        # Set the challenge string based on the request.
        key_v, gw_id, pro_v, c_len, m, n, _ = str(data)[2:].split(';')
        #print((key_v, gw_id, pro_v, c_len, m, n))
        print(" - trusClient key version <%s>." % key_v)
        print(" - trusClient gateway id  <%s>." % gw_id)
        print(" - trusClient program version <%s>." % pro_v)
        print(" - trusClient challenge len <%s>." % c_len)
        print(" - trusClient Swatt (m,n) len <%s>." % str((m, n)))

        # Set up and init AES connunication session key. 
        self.exchangeSessionKey(client_socket, key_v)

        # Verify the file swatt value with the trustClient.
        resp = self.swattVerify(client_socket, c_len, m , n)

        # Send the verification result to the client and fetch the program running information.
        self.challengeB = bytes([ord(resp)]+[ord(n) for n in self.challengeStr] + [
                                ord('Z')]*(DE_BUFFER_SIZE-self.challengeLen-1))
        self.encrypted = self.cipher.encrypt(self.challengeB)
        client_socket.send(self.encrypted)
        request = client_socket.recv(1024)
        msg = str(self.msgMgr.loadMsg(request))[2:].split(';')
        # Show the feedback result.
        fbMsg = "The program is not running." if msg[0] == '' else '\n'.join(msg[:-1])
        print(fbMsg)
        print("Finished the verification ")

#--firmwTAServer---------------------------------------------------------------
    def setSwattChalStr(self, challengeStr, challengelen=None):
        """ Pad the input SWATT challengeStr"""
        if len(challengeStr) < self.challengeLen:
            print("TA_Server: The challenge string is not long enough.")
            return
        self.challengeLen = int(challengelen) if challengelen else DEFUALT_CH_LEN
        self.challengeStr = challengeStr[:self.challengeLen]
        # pad the input challenge string to bytes data with b'Z'.
        self.challengeB = bytes(
            [ord(n) for n in self.challengeStr] + [ord('Z')]*(DE_BUFFER_SIZE-self.challengeLen))

#--firmwTAServer---------------------------------------------------------------
    def swattVerify(self, client_socket, c_len, m, n):
        """ Generate the random Swatt-challenge string based on the c_len, send 
            AES encrypted challenge string and calcualte the local file's swatt 
            value, then verfiy the feedback swatt data from the client.
        """
        # Generate the new SWATT random challenge string and send to client.
        swattStr = self.swattHd.randomChallStr(stringLength=int(c_len))
        self.setSwattChalStr(swattStr, challengelen=int(c_len))
        print('TA_Server:  Send the encrypted challenge string <%s> as bytes list.' %
              self.challengeStr)
        self.encrypted = self.cipher.encrypt(self.challengeB)
        client_socket.send(self.encrypted)
        self.swattHd.setIterationNum(int(n))
        # Calcualte the SWATT value for verification.
        result = self.swattHd.getSWATT(
            self.challengeStr, int(m), self.filename)
        result = int(result, 0)  # hex string to int.
        print('TA_Server:  SWATT result<%s>' % str(result))
        request = client_socket.recv(DE_BUFFER_SIZE)
        data = self.cipher.decrypt(request)
        data = str(data).split('x0')[0]
        print('TA_Server: Received the SWATT<%s>' % str(data))
        resp = 'T'
        if int(data[2:-1]) == result: 
            print("The file Swatt value has been verified.")
        else: 
            print("The value are differet:"+str((data[2:-1], result)))
            resp = 'F'
        return resp

#-----------------------------------------------------------------------------
    def startServer(self):
        """ Start the Server"""
        while True:
            print('Wait for trustClient make connection...')
            client_sock, address = self.server.accept()
            print ('Accepted connection from {}:{}'.format(address[0], address[1]))
            self.handleClientConnection(client_sock)
            client_sock.close()

#-----------------------------------------------------------------------------
def startServ():
    server = firmwTAServer()
    print("Server inited.")
    server.startServer()

if __name__ == '__main__':
    startServ()
