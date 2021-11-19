#!/bin/bash -ex
# For this script to work, there must be at least one usb device attached.
ADB=$ANDROID_HOST_OUT/bin/adb

# Get device serial/usb
# This also tests the all devices mode of adb server.
pkill adb || true; sleep 1
SERIAL=$($ADB devices  -l | grep 'transport_id:' | head -1 | cut -d' ' -f1)
USB=$($ADB devices -l | grep 'transport_id:' | head -1 | tr -s ' ' | cut -d' ' -f3)

# TODO(b/207148500) Temporary workaround.
if [[ "$ADB_LIBUSB" == "1" ]]; then
  USB_PREFIX="usb:"
fi

echo "serial=$SERIAL usb=$USB"

# Test select by device serial
pkill adb || true; sleep 1
$ADB --one-device "$SERIAL" start-server
$ADB devices -l | grep "$SERIAL" || fail "Device not found"

# Test select by USB device address
pkill adb || true; sleep 1
$ADB --one-device "${USB_PREFIX}${USB}" start-server
$ADB devices -l | grep "${USB}" || fail "Device not found"

# Test device removed by --one-device
pkill adb || true; sleep 1
$ADB --one-device asdf1234 start-server
$ADB devices -l | grep "$SERIAL" && fail "Device should not appear"

echo PASS
