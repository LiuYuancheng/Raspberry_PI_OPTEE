#!/usr/bin/env python

import base64

from Crypto import Random
from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]


class AESCipher:

    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        # iv = Random.new().read( AES.block_size )
        iv = "AAAAAAAAAAAAAAAA"
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        #return base64.b64encode( cipher.encrypt( raw ) )
        return cipher.encrypt( raw )

    def decrypt( self, enc ):
        #enc = base64.b64decode(enc)
        iv =  "AAAAAAAAAAAAAAAA"
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt(enc))


cipher = AESCipher('0123456789abcdef')
encrypted = cipher.encrypt('test text 123345')
with open('output', 'wb') as f: 
    f.write(encrypted)

data = None
with open('output', 'rb') as f: 
    data = f.read()

decrypted = cipher.decrypt(data)
print encrypted
print decrypted
