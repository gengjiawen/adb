#!/bin/bash -ex
# For this script to work, there must be at least one usb device attached.
# NOTE: This script will kill any running adb servers.
# If the script succeeds, the last line output will be "PASS"
DIR="$(dirname "$(pwd)/$0")"
export ADB_LIBUSB=1
. $DIR/one_device.sh
