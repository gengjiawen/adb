---                                                                     
Title: ADB(1) MAN PAGE Version 1.0.41                                   
---  
<title>ADB(1)</title>

# NAME

**adb** — CLI Client for ADB (Android Debug Bridge) Server. 


# SYNOPSIS

**adb** [*GLOBAL_OPTIONS*] command [*COMMAND_OPTIONS*]


# DESCRIPTION

Connects to the ADB Server via its smart socket interface. Allows to send requests, receive responses, and manage lifecycle.

Tasks are performed via commands. Some commands are fulfilled directly by the server while others are forwarded toward the ADBD (ADB Daemon) running on the device.

# GLOBAL OPTIONS:

**-a**
: Listen on all network interfaces, not just localhost

**-d**
: Use USB device (error if multiple devices connected)

**-e**
: Use TCP/IP device (error if multiple TCP/IP devices available)

**-s *SERIAL***
: Use device with given serial (overrides $ANDROID_SERIAL)

**-t *ID***
: Use device with given transport id

**-H**
: Name of adb server host [default=localhost]

**-P**
: Port of adb server [default=5037]

**-L *SOCKET***
: Listen on given socket for adb server [default=tcp:localhost:5037]

**\-\-one-device *SERIAL*|*USB***
: Server will only connect to one USB device, specified by a serial number or USB device address (only with 'start-server' or 'server nodaemon').

**\-\-exit-on-write-error**
: Exit if stdout is closed


# GENERAL COMMANDS:

devices [**-l**]
: List connected devices

**-l**
: Use long output.

help
: Show this help message

version
: Show version num

# NETWORKING

connect ***HOST***[:***PORT***]
: Connect to a device via TCP/IP [default ***PORT***=5555].

disconnect [***HOST***[:***PORT***]]
: Disconnect from given TCP/IP device [default ***PORT***=5555], or all.

pair ***HOST***[:***PORT***] [***PAIRING_CODE***]
: Pair with a device for secure TCP/IP communication.

forward **\-\-list**
: List all forward socket connections.

forward [**--no-rebind**] ***LOCAL_REMOTE***

&nbsp;&nbsp;&nbsp;&nbsp;Forward socket connection using one of the followings.  
&nbsp;&nbsp;&nbsp;&nbsp;**tcp**:***PORT*** (local may be "tcp:0" to pick any open port.  
&nbsp;&nbsp;&nbsp;&nbsp;**localreserved**:***UNIX_DOMAIN_SOCKET_NAME***.  
&nbsp;&nbsp;&nbsp;&nbsp;**localfilesystem**:***UNIX_DOMAIN_SOCKET_NAME***.  
&nbsp;&nbsp;&nbsp;&nbsp;**jdwp**:<process pid> (remote only).  
&nbsp;&nbsp;&nbsp;&nbsp;**vsock**:***CID***:***PORT*** (remote only).  
&nbsp;&nbsp;&nbsp;&nbsp;**acceptfd**:***FD*** (listen only).  

forward **\-\-remove** ***LOCAL***
: Remove specific forward socket connection.

forward **\-\-remove-all**
: Remove all forward socket connections.

reverse **\-\-list**
: List all reverse socket connections from device.

reverse [**\-\-no-rebind**] ***REMOTE*** ***LOCAL*** \s\s

|    Reverse socket connection using one of the following

+ tcp:***PORT*** (***REMOTE*** may be "tcp:0" to pick any open port)

+ localabstract:***UNIX_DOMAIN_SOCKET_NAME***

+ localreserved:***UNIX_DOMAIN_SOCKET_NAME***

+ localfilesystem:***UNIX_DOMAIN_SOCKET_NAME***

reverse **\-\-remove** ***REMOTE***
: Remove specific reverse socket connection.

reverse **\-\-remove-all**
: Remove all reverse socket connections from device.


mdns ***SUBCOMMAND***
: Perform mDNS subcommands.

+ **check** Check if mdns discovery is available.

+ **services** List all discovered services.


# FILE TRANSFER:

push [**--sync**] [**-z** ***ALGORITHM***] [**-Z**] ***LOCAL***... ***REMOTE***
: Copy local files/directories to device.

**--sync**
: Only push files that are newer on the host than the device.

**-n**
: Dry run, push files to device without storing to the filesystem


     -z: enable compression with a specified algorithm (any/none/brotli/lz4/zstd)
     -Z: disable compression

 pull [-a] [-z ALGORITHM] [-Z] REMOTE... LOCAL
     copy files/dirs from device
     -a: preserve file timestamp and mode
     -z: enable compression with a specified algorithm (any/none/brotli/lz4/zstd)
     -Z: disable compression

 sync [-l] [-z ALGORITHM] [-Z] [all|data|odm|oem|product|system|system_ext|vendor]
     sync a local build from $ANDROID_PRODUCT_OUT to the device (default all)
     -n: dry run: push files to device without storing to the filesystem
     -l: list files that would be copied, but don't copy them
     -z: enable compression with a specified algorithm (any/none/brotli/lz4/zstd)
     -Z: disable compression

# SHELL:

shell [-e ESCAPE] [-n] [-Tt] [-x] [COMMAND...]
     run remote shell command (interactive shell if no command given)
     -e: choose escape character, or "none"; default '~'
     -n: don't read from stdin
     -T: disable pty allocation
     -t: allocate a pty if on a tty (-tt: force pty allocation)
     -x: disable remote exit codes and stdout/stderr separation

emu COMMAND              run emulator console command

# APP INSTALLATION (SEE ALSO `ADB SHELL CMD PACKAGE HELP`):

 install [-lrtsdg] [--instant] PACKAGE
     push a single package to the device and install it

 install-multiple [-lrtsdpg] [--instant] PACKAGE...
     push multiple APKs to the device for a single package and install them

 install-multi-package [-lrtsdpg] [--instant] PACKAGE...
     push one or more packages to the device and install them atomically
     -r: replace existing application
     -t: allow test packages
     -d: allow version code downgrade (debuggable packages only)
     -p: partial application install (install-multiple only)
     -g: grant all runtime permissions
     --abi ABI: override platform's default ABI
     --instant: cause the app to be installed as an ephemeral install app
     --no-streaming: always push APK to device and invoke Package Manager as separate steps
     --streaming: force streaming APK directly into Package Manager
     --fastdeploy: use fast deploy
     --no-fastdeploy: prevent use of fast deploy
     --force-agent: force update of deployment agent when using fast deploy
     --date-check-agent: update deployment agent when local version is newer and using fast deploy
     --version-check-agent: update deployment agent when local version has different version code and using fast deploy
     --local-agent: locate agent files from local source build (instead of SDK location)
     (See also `adb shell pm help` for more options.)

 uninstall [-k] PACKAGE
     remove this app package from the device
     '-k': keep the data and cache directories

# DEBUGGING:

bugreport [PATH]
     write bugreport to given PATH [default=bugreport.zip];
     if PATH is a directory, the bug report is saved in that directory.
     devices that don't support zipped bug reports output to stdout.
 jdwp                     list pids of processes hosting a JDWP transport

 logcat                   show device log (logcat --help for more)


# SECURITY:

 disable-verity           disable dm-verity checking on userdebug builds

 enable-verity            re-enable dm-verity checking on userdebug builds

 keygen FILE
     generate adb public/private key; private key stored in FILE,

# SCRIPTING:

 wait-for[-TRANSPORT]-STATE...
     wait for device to be in a given state
     STATE: device, recovery, rescue, sideload, bootloader, or disconnect
     TRANSPORT: usb, local, or any [default=any]

 get-state                print offline | bootloader | device

 get-serialno             print <serial-number>

 get-devpath              print <device-path>

 remount [-R]
      remount partitions read-write. if a reboot is required, -R will
      will automatically reboot the device.

 reboot [bootloader|recovery|sideload|sideload-auto-reboot]
     reboot the device; defaults to booting system image but
     supports bootloader and recovery too. sideload reboots
     into recovery and automatically starts sideload mode,
     sideload-auto-reboot is the same but reboots after sideloading.

 sideload OTAPACKAGE      sideload the given full OTA package

 root                     restart adbd with root permissions

 unroot                   restart adbd without root permissions

 usb                      restart adbd listening on USB

 tcpip PORT               restart adbd listening on TCP on PORT

# INTERNAL DEBUGGING:


start-server
: Ensure that there is a server running.

kill-server
: Kill the server if it is running.

reconnect
: Kick connection from host side to force reconnect.

reconnect device
: Kick connection from device side to force reconnect.

reconnect offline
: Reset offline/unauthorized devices to force reconnect.

# USB:

Only valid when running with libusb backend.

attach *SERIAL*
: Attach a detached USB device.

detach *SERIAL*
: Detach from a USB device to allow use by other processes.


# ENVIRONMENT VARIABLES

ADB_TRACE: Comma-separated list of debug info to log: all,adb,sockets,packets,rwx,usb,sync,sysdeps,transport,jdwp

ADB_VENDOR_KEYS: Colon-separated list of keys (files or directories)

ANDROID_SERIAL: Serial number to connect to (see -s)

ANDROID_LOG_TAGS: Tags to be used by logcat (see logcat --help)

ADB_LOCAL_TRANSPORT_MAX_PORT: Max emulator scan port (default 5585, 16 emus)

ADB_MDNS_AUTO_CONNECT: Comma-separated list of mdns services to allow auto-connect (default adb-tls-connect)

# BUGS

See Issue Tracker: <https://issuetracker.google.com/components/192795>

# AUTHORS

See OWNERS file in ADB AOSP repo.
