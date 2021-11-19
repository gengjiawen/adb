#!/bin/bash -ex
DIR="$(dirname "$(pwd)/$0")"
export ADB_LIBUSB=1
. $DIR/one_device.sh
