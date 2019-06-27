# Raspbian_OPTEE_AP
#Raspbian_OPTEE_AP
---
This project is aim to create a trust Client<=>Server program to verify whether a execuable program on Raspberry PI 3 has modified by other people. 

The main feature used in the project are:
- Set OPTEE on Rasperry PI mode 3(trustZone under Raspian);
- Client<=> Server communication: AES encryption/decryption by trustApplication.
- Calculate the executable program in IOT and calcualte the file's SWATT value independently in client and server, then do the comparasion.
- Get the execuable program execution information such as (cmd run the program, checked program process ID, execution user, related file Descriptor, memory size+offset, node info, system lib file name). Then send the information to server.


We follow benhaz1024's project[https://github.com/benhaz1024/raspbian-tee] to learn &amp; implement a trust APP.
When doing make need to install: sudo apt-install u-boot-tools 
To build a trust app we follow the example in : 
https://github.com/linaro-swg/hello_world
As the OS OPTEE official web only provide the light Linux for Raspberry PI. If we follow the instruction in the https://optee.readthedocs.io/building/devices/rpi3.html (As shown below)and get to the step6, we can run the “xtest” but the Linux OS can only provide few function for further usage. This document will provide the detail steps about how to set the Raspberry PI mode 3’s Raspbian system with OPTEE function

Step 1: Prepare the Raspberry PI mode 3 with Raspberry system installed: 
  - 1.1 Insert the 16GB SD card in the windows machine and use “SD Memory card formatter” to format the SD card.  Download the SD memory card formatter from https://www.sdcard.org/downloads/formatter/  and follow all the default setting. 
  - 1.2 Down load the Raspberry PI Raspbian OS(32-bit) from https://www.raspberrypi.org/downloads/raspbian/ 
  -  Download the FlashFlawless from https://www.balena.io/etcher/ and flash the Raspbian image in to the SD card, put the SD card in Raspberry PI to double confirm the it works normally.  
