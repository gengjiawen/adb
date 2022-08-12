# ADB(1) MAN PAGE Version 1.0.41                                     

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
: List connected devices.  

**-l** : Use long output.

help  
&nbsp;&nbsp;&nbsp;&nbsp;Show this help message

version  
&nbsp;&nbsp;&nbsp;&nbsp;Show version num

# NETWORKING

connect ***HOST***[:***PORT***]  
&nbsp;&nbsp;&nbsp;&nbsp;Connect to a device via TCP/IP [default ***PORT***=5555].

disconnect [***HOST***[:***PORT***]]  
&nbsp;&nbsp;&nbsp;&nbsp;Disconnect from given TCP/IP device [default ***PORT***=5555], or all.

pair ***HOST***[:***PORT***] [***PAIRING_CODE***]   
&nbsp;&nbsp;&nbsp;&nbsp;Pair with a device for secure TCP/IP communication.

forward

**\-\-list**  
&nbsp;&nbsp;&nbsp;&nbsp;List all forward socket connections.

[**--no-rebind**] ***LOCAL_REMOTE***    
&nbsp;&nbsp;&nbsp;&nbsp;Forward socket connection using one of the followings.  

&nbsp;&nbsp;&nbsp;&nbsp;**tcp**:***PORT*** (local may be "tcp:0" to pick any open port.  
&nbsp;&nbsp;&nbsp;&nbsp;**localreserved**:***UNIX_DOMAIN_SOCKET_NAME***.  
&nbsp;&nbsp;&nbsp;&nbsp;**localfilesystem**:***UNIX_DOMAIN_SOCKET_NAME***.  
&nbsp;&nbsp;&nbsp;&nbsp;**jdwp**:**PROCESS PID** (remote only).  
&nbsp;&nbsp;&nbsp;&nbsp;**vsock**:***CID***:***PORT*** (remote only).  
&nbsp;&nbsp;&nbsp;&nbsp;**acceptfd**:***FD*** (listen only).

**\-\-remove** ***LOCAL***  
&nbsp;&nbsp;&nbsp;&nbsp;Remove specific forward socket connection.

**\-\-remove-all**  
&nbsp;&nbsp;&nbsp;&nbsp;Remove all forward socket connections.

reverse 

**\-\-list**  
: List all reverse socket connections from device.

[**\-\-no-rebind**] ***REMOTE*** ***LOCAL***.  
: Reverse socket connection using one of the following.  

&nbsp;&nbsp;&nbsp;&nbsp;tcp:***PORT*** (***REMOTE*** may be "tcp:0" to pick any open port).  
&nbsp;&nbsp;&nbsp;&nbsp;localabstract:***UNIX_DOMAIN_SOCKET_NAME***.  
&nbsp;&nbsp;&nbsp;&nbsp;localreserved:***UNIX_DOMAIN_SOCKET_NAME***.  
&nbsp;&nbsp;&nbsp;&nbsp;localfilesystem:***UNIX_DOMAIN_SOCKET_NAME***.

**\-\-remove** ***REMOTE***  
: Remove specific reverse socket connection.

**\-\-remove-all**  
: Remove all reverse socket connections from device.

mdns ***SUBCOMMAND***  
: Perform mDNS subcommands.  

**check**
: Check if mdns discovery is available.  

**services**
: List all discovered services.  


# FILE TRANSFER:

push [**--sync**] [**-z** ***ALGORITHM***] [**-Z**] ***LOCAL***... ***REMOTE***
: Copy local files/directories to device.

**--sync**
: Only push files that are newer on the host than the device.

**-n**
: Dry run, push files to device without storing to the filesystem.

**-z**
: enable compression with a specified algorithm (any/none/brotli/lz4/zstd).

**-Z**
: Disable compression.  

pull [**-a**] [**-z** ***ALGORITHM***] [**-Z**] ***REMOTE***... ***LOCAL***
: Copy files/dirs from device  

**-a**
: preserve file timestamp and mode.

**-z**
: enable compression with a specified algorithm (**any**/**none**/**brotli**/**lz4**/**zstd**)  

**-Z**
: disable compression  

sync [**-l**] [**-z** ***ALGORITHM***] [**-Z**] [**all**|**data**|**odm**|**oem**|**product**|**system**|**system_ext**|**vendor**]
: Sync a local build from $ANDROID_PRODUCT_OUT to the device (default all)  

**-n**
: Dry run. Push files to device without storing to the filesystem.    

**-l**
: List files that would be copied, but don't copy them.  

**-z**:
Enable compression with a specified algorithm (**any**/**none**/**brotli**/**lz4**/**zstd**)  

**-Z**:
Disable compression.  

# SHELL:

shell [**-e** ***ESCAPE***] [**-n**] [**-Tt**] [**-x**] [***COMMAND***...]
: Run remote shell command (interactive shell if no command given).

**-e**
: Choose escape character, or "**none**"; default '**~**'.

**-n**
: Don't read from stdin.

**-T**:
: Disable pty allocation.

**-t**:
: Allocate a pty if on a tty (-tt: force pty allocation).  

**-x**
: Disable remote exit codes and stdout/stderr separation.  

emu ***COMMAND***
: Run emulator console ***COMMAND***

# APP INSTALLATION 
(see also `adb shell cmd package help`):

install [**-lrtsdg**] [**--instant**] ***PACKAGE***
: Push a single package to the device and install it

install-multiple [**-lrtsdpg**] [**--instant**] ***PACKAGE***...
: Push multiple APKs to the device for a single package and install them

install-multi-package [**-lrtsdpg**] [**--instant**] ***PACKAGE***...
: Push one or more packages to the device and install them atomically

&nbsp;&nbsp;&nbsp;&nbsp;**-r**: replace existing application  
&nbsp;&nbsp;&nbsp;&nbsp;**-t**: allow test packages  
&nbsp;&nbsp;&nbsp;&nbsp;**-d**: allow version code downgrade (debuggable packages only)  
&nbsp;&nbsp;&nbsp;&nbsp;**-p**: partial application install (install-multiple only)  
&nbsp;&nbsp;&nbsp;&nbsp;**-g**: grant all runtime permissions  
&nbsp;&nbsp;&nbsp;&nbsp;**\-\-abi** ***ABI***: override platform's default ABI  
&nbsp;&nbsp;&nbsp;&nbsp;**\-\-instant**: cause the app to be installed as an ephemeral install app.  
&nbsp;&nbsp;&nbsp;&nbsp;**\-\-no-streaming**: always push APK to device and invoke Package Manager as separate steps.  
&nbsp;&nbsp;&nbsp;&nbsp;**\-\-streaming**: force streaming APK directly into Package Manager.  
&nbsp;&nbsp;&nbsp;&nbsp;**\-\-fastdeploy**: use fast deploy.  
&nbsp;&nbsp;&nbsp;&nbsp;**\-\-no-fastdeploy**: prevent use of fast deploy.  
&nbsp;&nbsp;&nbsp;&nbsp;**\-\-force-agent**: force update of deployment agent when using fast deploy.  
&nbsp;&nbsp;&nbsp;&nbsp;**\-\-date-check-agent**: update deployment agent when local version is newer and using fast deploy.  
&nbsp;&nbsp;&nbsp;&nbsp;**\-\-version-check-agent**: update deployment agent when local version has different version code and using fast deploy.  
&nbsp;&nbsp;&nbsp;&nbsp;**\-\-local-agent**: locate agent files from local source build (instead of SDK location). See also `adb shell pm help` for more options.  

uninstall [**-k**] ***PACKAGE***
: Remove this app package from the device

**-k**
: Keep the data and cache directories.

# DEBUGGING:

bugreport [***PATH***]
: Write bugreport to given PATH [default=bugreport.zip]; if PATH is a directory, the bug report is saved in that directory. devices that don't support zipped bug reports output to stdout.

jdwp
: List pids of processes hosting a JDWP transport.

logcat
: Show device log (logcat --help for more).


# SECURITY:

disable-verity
: Disable dm-verity checking on userdebug builds.

enable-verity
: Re-enable dm-verity checking on userdebug builds.

keygen ***FILE***
: Generate adb public/private key; private key stored in ***FILE***.

# SCRIPTING:

wait-for[-***TRANSPORT***]-***STATE***...
:  Wait for device to be in a given state.

&nbsp;&nbsp;&nbsp;&nbsp;***STATE***: device, recovery, rescue, sideload, bootloader, or disconnect.  
&nbsp;&nbsp;&nbsp;&nbsp;***TRANSPORT***: usb, local, or any [default=any]

get-state
: Print offline | bootloader | device

get-serialno
: Print ***SERIAL_NUMBER***.

get-devpath
: Print  ***DEVICE_PATH***.

remount [**-R**]
: Remount partitions read-write.

**-R**
: Automatically reboot the device.

reboot [**bootloader**|**recovery**|**sideload**|**sideload-auto-reboot**]
: Reboot the device; defaults to booting system image but supports **bootloader** and **recovery** too. 

**sideload**
: Reboots into recovery and automatically starts sideload mode.

**sideload-auto-reboot**
: Same as **sideload** but reboots after sideloading.


sideload ***OTAPACKAGE***
: Sideload the given full OTA package ***OTAPACKAGE***

root
: Restart adbd with root permissions.

unroot
: Restart adbd without root permissions.

usb
: Restart adbd listening on USB.

tcpip ***PORT***
: Restart adbd listening on TCP on ***PORT***.

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

attach ***SERIAL***
: Attach a detached USB device identified by its ***SERIAL*** number.

detach ***SERIAL***
: Detach from a USB device identified by its ***SERIAL*** to allow use by other processes.


# ENVIRONMENT VARIABLES

$ADB_TRACE
: Comma-separated list of debug info to log: all,adb,sockets,packets,rwx,usb,sync,sysdeps,transport,jdwp.

$ADB_VENDOR_KEYS
: Colon-separated list of keys (files or directories).

$ANDROID_SERIAL
: Serial number to connect to (see -s).

$ANDROID_LOG_TAGS
: Tags to be used by logcat (see logcat --help).

$ADB_LOCAL_TRANSPORT_MAX_PORT
: Max emulator scan port (default 5585, 16 emus).

$ADB_MDNS_AUTO_CONNECT
: Comma-separated list of mdns services to allow auto-connect (default adb-tls-connect).

# BUGS

See Issue Tracker: <https://issuetracker.google.com/components/192795>

# AUTHORS

See OWNERS file in ADB AOSP repo.
