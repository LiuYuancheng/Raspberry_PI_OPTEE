#------------------------------------------------------------------------------
# Name:        Constants.py
#
# Purpose:     The constants which will be used in all the modules are set in 
#              this module. 
# Author:      Yuancheng Liu
#
# Created:     2019/07/05
# Copyright:   NUS – Singtel Cyber Security Research & Development Laboratory
# License:     YC @ NUS
#------------------------------------------------------------------------------

LOCAL_IP = '127.0.0.1'

# Defualt data received buffer size:
BUFFER_SIZE = 1024

# Data message dump and load tag
CMD_TYPE = 'C'.encode('utf-8')  # cmd type message used for contorl.
FILE_TYPE = 'F'.encode('utf-8') # file(bytes) type.

# Random bytes setting:
RAN_LEN = 4 # The random number/bytes length.

# SWA_TT setting:
SWATT_ITER  = 300 # Swatt calculation iteration count.