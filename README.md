# Raspbian_OPTEE_Attestation_Program
### Introduction
This project is aimed to create a trust_Client by using the "ARM Trust Zone" technique to do the local file attestation and use it to communicate with the server program to verify whether a executable program on IOT gateway (Raspberry PI Mode 3) has been modified by attacker. 

###### **Main feature used in the project**

- Set Open Portable Trusted Execution Environment on Raspberry PI mode 3 (Trust Zone under Raspbian). 
- Client and Server communication: TCP with AES encryption/decryption by trust_Application. 
- Calculate the IOT file's SWATT value independently in both client's trust Zone and server part, then do the result comparison. 
- Get the running program's execution information under Raspbian such as program process ID, execution user, related file descriptor, memory size+offset, node info and related system lib file name. Then send all the information to server for further check.

###### Program executing flow diagram

![](doc/Design_flowChart/optee_client_server_2019_06_20.png)

###### Related project we followed/used/learn to finished the project
- [OPTEE trustZone on Rasperry PI Mode 3: OP-TEE](https://github.com/OP-TEE/optee_os)
- [Raspbian with OP-TEE Support: benhaz1024](https://github.com/benhaz1024/raspbian-tee)
- [Example of make a trustApplication: linaro-swg](https://github.com/linaro-swg/hello_world)
- [IOT SW-ATT file signature calculation](https://ieeexplore.ieee.org/document/8443995)
- [Linear congruential random generator](https://rosettacode.org/wiki/Linear_congruential_generator)
---
### Program Setup 

##### Step 1: Prepare Raspberry PI (mode 3) with Raspbian system installed: 
Dev Env:  Windows 10/7
1. Insert the 16GB SD card in the windows machine and use “SD Memory card formatter” to format the SD card. Download the SD memory card formatter from https://www.sdcard.org/downloads/formatter/ and follow all the default setting.
1. Download the Raspberry PI Raspbian OS(32-bit) from https://www.raspberrypi.org/downloads/raspbian/
1. Download the FlashFlawless from https://www.balena.io/etcher/ and flash the Raspbian image in to the SD card, put the SD card in Raspberry PI to double confirm it works normally. 

##### Step 2: Build the Raspbian with OPTEE enabled
1. Install the packages that need to be installed to start with to make OPTEE:
	```html
	$ sudo apt-get install android-tools-adb android-tools-fastboot autoconf \
        automake bc bison build-essential cscope curl device-tree-compiler \
        expect flex ftp-upload gdisk iasl libattr1-dev libc6:i386 libcap-dev \
        libfdt-dev libftdi-dev libglib2.0-dev libhidapi-dev libncurses5-dev \
        libpixman-1-dev libssl-dev libstdc++6:i386 libtool libz1:i386 make \
        mtools netcat python-crypto python-serial python-wand unzip uuid-dev \
        xdg-utils xterm xz-utils zlib1g-dev
	```
Follow the link <https://optee.readthedocs.io/building/devices/rpi3.html> to do the step 1 - 5. 
1. Download the Cross Build Toolchain [ AARCH64 & AARCH32 both needed, and AARCH32 must > 6.0 from linaro] from link: https://releases.linaro.org/components/toolchain/binaries/
![](doc/2019-05-29_095400.png)
1. Install the build tools package:
	```html
	$ sudo apt-install u-boot-tools
	```
1. Download the Raspbian with OPTEE support project and follow the steps in link: https://github.com/benhaz1024/raspbian-tee and set up the config file(Config.mk) as:
	```html
	export CROSS_COMPILE := /path/to/your/linaro/aarch32/bin/arm-linux-gnueabihf-
	export CROSS_COMPILE_AARCH64 := /path/to/your/linaro/aarch64/bin/aarch64-linux-gnu-
	```
##### Step 3: Create a new Trust Application and run in the Raspbian with OPTEE
1. Down load the OPTEE trust example from https://github.com/linaro-swg/hello_world and put the folder in the raspbian-optee folder. 
1. Define the toolchains and environment variables with all 32-bit setting and make:
	```html
	$ export TEEC_EXPORT=$PWD/../optee_client/out/export
	$ export HOST_CROSS_COMPILE=$[The arm-linux-gnueabihf position in <2.2>]/aarch32/bin/arm-linux-gnueabihf-
	$ export TA_CROSS_COMPILE=$[The arm-linux-gnueabihf position in <2.2>/aarch32/bin/arm-linux-gnueabihf-
	$ export TA_DEV_KIT_DIR=$PWD/../optee_os/out/arm/export-ta_arm32
	$ make
	```
1. Copy the file to the system and test: 1. Copy the **host\hello_world** to **\media\user\rootfs\bin** folder and copy the **ta\7aaaf200-2450-11e4-abe2-0002a5d5c51b.ta** to **\media\user\rootfs\lib\optee_armtz\** folder.

##### Step 4: Run the Trust_Client
1. Download the Trust_Client project and do the same thing as step3.

1. Build the Project and copy the TrustClient in the Raspberry PI SD card. 

1. Copy the server program in the home folder of the  Raspberry PI SD card

   File system structure: 

   ![](doc/2019-05-29_113640.png)

1. 

------

### Program execution

