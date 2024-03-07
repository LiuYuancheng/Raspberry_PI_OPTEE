# Trust Zone/Env (OPTEE) on Raspberry PI
**Project Design**: The primary objective of this project is aim to use the Raspberry PI to build a "trust IOT device" which use the ARM trust Zone technology to protect the critical data ( such communication channel encryption keys) and program (IoT firmware) against the information leakage and firmware attack. In this project we will use the lib OPTEE lib to build the Trusted Execution Environment (TEE) on a Raspberry PI and add our Firmware attestation code as a trust_Client running in the trust zone verify whether a executable program on IOT (Raspberry PI Mode 3) has been modified by attacker. 

The Trust Client contents 2 section: 

- Communication part: this part will running on the Normal World which used to send the information to the IoT control Hub. 
- Firmware attestation part: this part will running in the secure world which contents the RSA message encryption key, the firmware attestation algorithm code.



### Introduction 

With the development of reverse engineering, the hacker can easily get the source code if they got a Linux based IOT device and split part of the firmware code from then firmware file. For example in this example: we use pyInstaller to compile our program to a raspbian executable file and load the firmware in a raspberry PI to build a motion detection camera, when the hacker get a camera from some where, he can use the pyinstxtractor to unpackaged the firmware and use the uncompyle6 to decompile the fire to get some code. Then after analyze the source code, he can build his own malicious firmware program and implement firmware attack. Even we added the firmware attestation program in the IoT, the hacker can also decompile the firmware attestation to find some way to bypass it. 

Now we want to move the firmware attestation program into the raspberry PI's arm trust zone so the hacker is not able to decompile the firmware attestation program, we will also save the Arm chip's unique `Device identification UDID`  and our attestation message RSA encryption key in the trust zone so even the hacker clone all the things in another raspberry PI he can not do a replay attack: 

The ARM chip verification program will get the  ARM's `Device identification UDID` and compare with its record, if they are not match return the attestation fail. 

The attestation result will be encrypted in the trust environment with the encrypt key stored in the trust zone, so the hacker will not able to decrypt the message from the IoT hub server and do the MITM attack.



### Introduction

This project is aimed to create a trust_Client by using the "ARM Trust Zone" technique to do the local file attestation and use it to communicate with the server program to verify whether a executable program on IOT gateway (Raspberry PI Mode 3) has been modified by attacker. 





What is trust Zone

TrustZone is a technology developed by ARM Holdings that provides hardware-based security features on ARM-based processors. It creates two separate execution environments: the "Normal World" and the "Secure World". These environments run concurrently on the same processor, but with different levels of access and privileges.

1. **Normal World**: This is where the regular operating system (such as Android, Linux, or other RTOS) runs along with user applications. It operates in a non-secure state and has access to regular resources and memory.
2. **Secure World**: This is a separate, isolated environment that runs a trusted operating system, often called a "Secure Monitor" or "Secure Kernel". The Secure World has higher privileges and access to secure resources such as cryptographic functions, secure storage, and secure boot mechanisms. It ensures that critical system functions and sensitive data are protected from unauthorized access or tampering.

TrustZone technology enables secure boot, secure storage, secure communication channels, and secure execution environments for applications that require high levels of security, such as mobile payment systems, digital rights management (DRM), and enterprise security solutions. It provides a foundation for building trusted execution environments (TEEs) where sensitive operations can be performed with a high degree of assurance against attacks.



Relationship between trust zone and trust environment.

TrustZone technology is the underlying hardware-based security architecture developed by ARM, which provides the foundation for creating a Trusted Execution Environment (TEE). The TEE is a secure area within the TrustZone environment where trusted applications can run with higher levels of security and confidentiality.

Here's how they are related:

1. **TrustZone**: TrustZone divides the ARM processor into two separate worlds: Normal World and Secure World. TrustZone provides hardware-based isolation and protection mechanisms to ensure that the Secure World operates independently of the Normal World. It establishes a secure execution environment for critical security functions and trusted applications.
2. **Trusted Execution Environment (TEE)**: The TEE is a secure area within the Secure World of the TrustZone environment. It is a trusted operating environment that provides isolation and protection for sensitive operations and applications. TEE offers a secure runtime environment where trusted applications, such as secure payment solutions, digital rights management (DRM) systems, and secure authentication mechanisms, can run with confidentiality, integrity, and reliability.

In essence, TrustZone provides the hardware support necessary to create a secure execution environment, while the TEE utilizes this environment to run trusted applications and execute critical security functions. The TEE leverages the security features provided by TrustZone, such as hardware isolation, secure boot, secure storage, and secure communication channels, to ensure the confidentiality and integrity of sensitive data and operations.



































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

1. File system structure : 

![](doc/2019-05-29_113640.png)

------

#### Program Execution

##### Run the Trust_Client

1. Download the Trust_Client project and do the same thing as step3.

1. Build the Project and copy the TrustClient in the Raspberry PI SD card. 

1. Copy the server program in the home folder of the  Raspberry PI SD card

1. Copy the **host\hello_world** to **\media\user\rootfs\bin** folder 

1. Copy the **ta\ 7aaaf200-2450-11e4-abe2-0002a5d5c51b.ta** to **\media\user\rootfs\lib\optee_armtz** 

1. Boot the Raspberry PI and check the result:

   ![](doc/trustclientResult.png)

1. 

------

> Last edit by LiuYuancheng(liu_yuan_cheng@hotmail.com) at 30/01/2020

### 

