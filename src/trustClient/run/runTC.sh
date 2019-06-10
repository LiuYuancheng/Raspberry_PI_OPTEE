#!/bin/hash
echo "Start the trushClient..."

# Check whether the OPTEE driver is running in background.
pgrep -x tee-supplicant
ret=$?

if [ $ret -eq 0 ]; then
        echo "The OPTEE driver has started."
	sudo trustClient
else
        echo "OPTEE dirver not start.Run [sudo tee-supplicant &] to start first!"
fi