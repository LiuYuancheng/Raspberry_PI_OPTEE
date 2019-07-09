#!/usr/bin/python
# -----------------------------------------------------------------------------
# Name:        IOT_ATT.py
#
# Purpose:     This module is used to provide a SWATT calculator to get the
# 			   input file's swatt value.
# Author:      Mohamed Haroon Basheer, edit by LYC
#
# Created:     2019/05/06
# Copyright:
# License:
# -----------------------------------------------------------------------------
import os
import random
import string
#from uuid import getnode as get_mac
RAN_FLAG = True #Flag to decide wehter we ues Linear congruential generator(BSD)
DE_PUFF = 154946511204680

# -----------------------------------------------------------------------------
# Linear congruential generator(BSD) 
def bsd_rand(seed):
    """ Reference: https://rosettacode.org/wiki/Linear_congruential_generator """
    def rand():
        rand.seed = (1103515245*rand.seed + 12345) & 0x7fffffff
        return rand.seed
    rand.seed = seed
    return rand

# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
class swattCal(object):
    """ This module is used to provide a SWATT calculator to get the input file's 
        swatt value.
    """
    # -----------------------------------------------------------------------------
    def __init__(self):
        self.state = None
        self.puffVal = DE_PUFF  # DEFAULT PUFF VALUE FOR EACH DEVICE
        self.iterM = 0  # swatt iteration time.

    # -----------------------------------------------------------------------------
    def bitExtracted(self, number, k, s):
        """ Extract specified length of bits """
        return (((1 << k) - 1)  &  (number >> (s-1) ) )

    # -----------------------------------------------------------------------------
    def extract_CRpair(self, challenegeStr):
        """ Extract challenege response pair for the given key and iteration """
        #final = self.bitExtracted( <= this caused SWATT val different on different divice.
        #    get_mac(), 16, 1)  # UNIQUE PUFF VALUE FOR EACH DEVICE
        final = self.bitExtracted(self.puffVal, 16, 1)
        test = [(ord(k) ^ final) for k in challenegeStr]
        for idx in range(len(test)):
            if(idx != len(test)-1): test[idx] ^= test[idx+1]
            final += test[idx] << 2
        return final

    #-----------------------------------------------------------------------------
    def randomChallStr(self, stringLength=10):
        """Generate a random chanllenge string of fixed length """
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(stringLength))

    # -----------------------------------------------------------------------------
    def setKey(self, key,m):
        """RC4 Key Scheduling Algorithm (KSA)"""
        j, self.state, = 0, list(range(m)) #[n for n in range(m)]#fill with numnber ranging from 0 to 255
        for i in range(m):
            j = (j + self.state[i] + key[i % len(key)]) % m
            self.state[i], self.state[j] = self.state[j], self.state[i]

    # -----------------------------------------------------------------------------
    def setPuff(self, puff):
        """ Set the PUFF seed value. puff must be a int"""
        if not isinstance(puff, int):
            print("The puff<%s> must be a int type" % puff)
            return
        self.puffVal = puff

    # -----------------------------------------------------------------------------
    def setIterationNum(self, iterationNum):
        """ Set the SWATT iteration loop time"""
        if iterationNum<= 0: return
        self.iterM = iterationNum
        
    # -----------------------------------------------------------------------------
    def string_to_list(self, inputString):
        """Convert a string into a byte list"""
        return [ord(c) for c in inputString] #returns the corresponding unicode integer for the char for ex; a==97

    # -----------------------------------------------------------------------------
    def getSWATT(self, challengeStr, m, filePath):
        """ Calculate the file swatt value based on the input challenge string
            and the iterative count. 
        """
        if not os.path.exists(filePath):
            print("The file <%s> is not exist" % filePath)
            return None
        with open(filePath, "rb") as fh:
            self.setKey(self.string_to_list(challengeStr), m)
            cr_response = self.extract_CRpair(challengeStr)  # P(C)
            #init_cs = cr_response ^ m  # sigma(0)<--p(c) xor x0
            #pprev_cs = self.state[256]  # c[(j-2)mod 8]
            #prev_cs = self.state[257]  # c[(j-1)mod 8]
            #current_cs = self.state[258]  # c[j]
            pprev_cs, prev_cs, current_cs = self.state[256:259]
            init_seed = m  # set x(i-1)
            # print init_cs.bit_length(),bin(init_cs),init_cs

            iterNum = self.iterM if self.iterM > 0 else m
            for i in range(iterNum):
                swatt_seed = cr_response ^ init_seed  # y(i-1)=p(c) xor x(i-1)
                # (RC4i<<8)+c[(j-1)mod 8]
                Address = (self.state[i] << 8)+prev_cs
                #use python PRG to generate address Range
                if RAN_FLAG:
                    randGen = bsd_rand(Address)
                    Address = randGen()%128000+1
                else:
                    random.seed(Address)
                    Address = random.randint(1, 128000) #YC: why only check 128000 bytes? 
                # read the EEPROM Memory content
                fh.seek(Address)
                strTemp = fh.read(1)
                # print(Address)
                #calculate checksum at the location
                #if not strTemp: continue  # jump over the empty str ""
                # current_cs=current_cs+(ord(strTemp[0])^pprev_cs+state[i-1])
                num = ord(strTemp) if len(strTemp)!=0 else 0
                current_cs = current_cs + \
                    (num ^ pprev_cs+self.state[i-1])
                # extra seed for the SWATT
                init_seed = current_cs+swatt_seed
                # update current_cs
                current_cs = current_cs >> 1
                # update c[(j-2)mod 8] & c[(j-1)mod 8]
                pprev_cs = prev_cs
                prev_cs = current_cs
            #return current_cs
            return hex(hash(current_cs))

# -----------------------------------------------------------------------------
# Lib function test case(we will do this in the future.)
def testCase():

    firmwarePath = "".join([os.getcwd(), "\\firmwSign\\firmwareSample"])
    calculator = swattCal()
    print("Start test.")
    calculator.setPuff(1549465112)
    result = calculator.getSWATT("Testing", 300, firmwarePath)
    print(result)
    if result == '0x397d' and not RAN_FLAG:
        print("SWATT calcualtion test pass.(use defualt random)")
        return
    elif result == '0x3b0d' and  RAN_FLAG:
        print("SWATT calcualtion test pass.(use Linear congruential generator random)")
        return
    else:
        print("SWATT calculation test fail.")

if __name__ == '__main__':
    testCase()


