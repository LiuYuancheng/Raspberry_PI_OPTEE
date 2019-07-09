#-----------------------------------------------------------------------------
# Name:        firmwGlobal.py
#
# Purpose:     This module is used set the Local config file as global value 
#              which will be used in the other modules.
# Author:      Yuancheng Liu
#
# Created:     2019/05/17
# Copyright:   NUS – Singtel Cyber Security Research & Development Laboratory
# License:     YC @ NUS
#-----------------------------------------------------------------------------
import os

dirpath = os.getcwd()
print("firmwGlobal: Current working directory is : %s" %dirpath)

APP_NAME = 'XAKA firmware sign tool_v1.1'

# Server ip and port for connection: 
LOCAL_IP = '127.0.0.1'
SITCP_PORT = 5005   # port for firmware sign request.
RGTCP_PORT = 5006   # port for sensor registration request.
TCTCP_PORT = 5007   # port for trustClient executable file verification. 

# Firmware sign server choice:
SI_SERVER_CHOICE = {
    "LocalDefault [127.0.0.1]"  : ('127.0.0.1', SITCP_PORT),
    "Server_1 [192.168.0.100]"  : ('192.168.0.100', SITCP_PORT),
    "Server_2 [192.168.0.101]"  : ('192.168.0.101', SITCP_PORT)
}

#UI window ICON.
ICON_PATH = "".join([dirpath, "\\firmwSign\\singtelIcon.ico"])

# Defualt firmware path
DEFUALT_FW = "".join([dirpath, "\\firmwSign\\firmwareSample"])

# RSA encryp/decrypt setting:
RSA_ENCODE_MODE = 'base64'# or 'hex' Sign encode mode.
RSA_UNLOCK  = "Anything for 30-day trial" # RSA unblock periodic
RSA_CERT_PATH = "".join([dirpath, "\\firmwSign\\publickey.cer"])
RSA_PRI_PATH = "".join( [dirpath, "\\firmwSign\\privatekey.pem"]) # RSA pricate key

# Recieved private key/sert from the server.
RECV_CERT_PATH = "".join([dirpath, "\\firmwSign\\receivered.cer"])
RECV_PRIK_PATH = "".join([dirpath, "\\firmwSign\\receivered.pem"]) 

# sqlite database file.
DB_PATH = "".join([dirpath, "\\firmwSign\\firmwDB.db"])

# TSL/SSL communication setting:
CA_PATH = "".join([dirpath, "\\firmwSign\\testCert\\CA.cert"])
# Client SSL private key and certificate.    
CSSL_PRIK_PATH = "".join([dirpath, "\\firmwSign\\testCert\\client.pkey"])
CSSL_CERT_PATH = "".join([dirpath, "\\firmwSign\\testCert\\client.cert"])
# Server SSL pricate key and certificate
SSSL_PRIK_PATH = "".join([dirpath, "\\firmwSign\\testCert\\server.pkey"])
SSSL_CERT_PATH = "".join([dirpath, "\\firmwSign\\testCert\\server.cert"])

# firmware sign pricate key and certificate
SIGN_CERT_PATH = "".join([dirpath, "\\firmwSign\\testCert\\certificate.pem"])
SIGN_PRIV_PATH = "".join([dirpath, "\\firmwSign\\testCert\\private_key.pem"])
