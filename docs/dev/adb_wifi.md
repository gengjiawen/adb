# Architecture of *ADB Wifi*

ADB has always had the capability to communicate with a Device over TCP. However
the process involved is convoluted and results in an insecure channel.
The steps are as follows.

1. Connect Device via USB cable.
2. Accept Workstation's public key in the Device UI dialog (pairing).
3. Request adbd to open a TCP server socket
```
$ adb tcpip 5555
```
4. Retrieve Device's Wi-Fi IP address
```
IP=`adb shell ip route | awk '{print $9}'`
```
5. Finally, connect over TCP
```
$ adb connect $IP:5555
```

After all these steps, adb server is communicating
with adbd over TCP in clear.
This means all traffic can be eavesdropped. Besides all packets being visible,
it is a vulnerability where an attacker can examine AUTH packets and use a replay
attack if the challenge issued by adbd was to repeat itself.


## The two problems *ADB Wifi* solves

*ADB Wifi* allows a user to pair a Device and a Workstation in a single step, without
requiring prior USB connection.

Moreover, *ADB Wifi* uses TLS to make sure all adb packets are encrypted
which avoids both eavesdropping and AUTH replay attack.

## How *ADB Wifi* works

*ADB Wifi* revolves around four capabilities.

- Pair without the user having to click "Allow debugging".
- Encrypt ADB traffic.
- Advertise services over the network.
- Auto-connect to paired Devices.

### Pairing

A Workstation and a Device are considered *paired* if the Workstation's public key
is in the Device's `/data/misc/adb/adb_keys`/ `/adb_keys` files (keystore). After pairing, the
Workstation can be trusted by the Device because the Workstation
can use its private key to answer the challenges from the Device (and the Device can verify
answer using keys from the keystore until a matching public key is found).

To pair, *ADB Wifi* uses a Pairing Server running on the Device.
The Pairing Server communicates using RSA 2048-bit encryption (in a x509 certificate).
Trust is bootstrapped using a shared secret, seeded either by a six digits number (pairing code)
or a 10 digits number (qrcode pairing). How the shared secret is exchanged is explained further down.

### Encrypted traffic

After pairing, and if user has toggled "Wireless debugging", adbd listen on
a TCP server socket (port picked at random). This is not the same as the legacy `tcpip` socket. The
legacy socket greets a communication attempts with an A_AUTH packet whereas
this socket opens communication with A_STLS which means all traffic will be
TLS encrypted (and authentication is different as well).

All this traffic is handled by the TLSServer which is forwarded to adbd's fdevent.
When users toggle "Wireless Debugging", they start and stop the TLSServer.

### Network Advertising (mDNS)

All of the elements previously mentioned advertise their presence on the network
via mDNS. Three service types are used.

- `_adb._tcp`: This is the legacy TCP service started via `adb tcpip <PORT>`.
- `_adb-tls-pairing._tcp`: The service advertised when the Device pairing server is active.
- `_adb-tls-connect._tcp`: The service advertised when the Device TLSServer is active.

Note that all services instances are published by the Device (adb server is merely a consumer
of mDNS packets). Both `_adb._tcp` and `_adb-tls-connect._tcp` are published directly
by adbd while `_adb-tls-pairing._tcp` is published via NsdServiceInfo.

#### mDNS Service Instance names

An instance name prefix is usually `adb-` followed by property `ro.serialno` plus a suffix added
by the mdns backend.

The Pairing Server is special but due to specific usage described below. Its
service instance name changes whether it is intended to be used with a pairing code
or a qrcode.

- Pairing code: `adb-`<`prop(persist.adb.wifi.guid)`>`-`< MDSN backend suffix > (e.g.: `adb-43081FDAS000VS-QXjCrW`)
- QR code: `studio-`< RANDOM-10> (e.g: `studio-58m*7E2fq4`)

### Auto-connect

When adb server starts, it also starts mDNS service discovery for all three service types.
Any service instance of type `_adb-tls-connect` being published results in a connection attempt.
If the Device was previously paired, TLS authentication will succeed and the Device is made
available to the Workstation.

# CLI tools

*ADB Wifi* can be set up and monitored via command line.

### mdns check
`$ adb mdns check` tells the user which adb server's mDNS stack is active and its version.

```
$ adb mdns check
mdns daemon version [Openscreen discovery 0.0.0]
```

### mdns services
`$ adb mdns services` lists all supported mdns services instances discovered and still active,
followed by their service type and their resolved IPv4 address/port. e.g.:
```
$ adb mdns services
List of discovered mdns services
adb-14141FDF600081         _adb._tcp	          192.168.86.38:5555
adb-14141FDF600081-QXjCrW  _adb-tls-pairing._tcp  192.168.86.38:33861
adb-14141FDF600081-TnSdi9  _adb-tls-connect._tcp  192.168.86.38:33015
studio-g@<xeYnap/          _adb-tls-pairing._tcp  192.168.86.39:55861
```

### pair

If a user starts a Pairing Server on the Device (via
`Settings > System > Developer options > Wireless debugging > Pair device with pairing code`), they
are presented with both a pairing code and the IPv4:port of the Wi-fi interface. In this case
the vector to exchange the TLS secret is the user who reads on the Device then type the pairing code on the Workstation
(we will see below there is another type of vector available).

![](adb_wifi_assets/pairing_dialog.png)

With the Pairing Server active, *ADB Wifi* is entirely configurable from the command-line, as follows.

```
$ adb pair 192.168.86.38:43811
Enter pairing code: 515109
$ adb connect 192.168.86.34:44643
$ adb devices
List of devices attached
adb-43081FDAS000VS-QXjCrW._adb-tls-connect._tcp	device
```

# Android Studio

## Pair with code
Android Studio automates pairing with a pairing code thanks to its GUI.
The peculiarity compared to the CLI method
is that it relies on mDNS to detect Devices with an active Pairing Server.
To this effect, Studio polls adb server for service instances of type `_adb-tls-pairing`.

## Pair with QR code
Studio also introduces a QR Code system which is just an easy way to share
the pairing code between the Workstation and the Device.

When a user click on "Pair Device Using Wi-Fi", they are shown a QRCode. e.g:

![](adb_wifi_assets/qrcode.png)

In the example code above Studio generated a qrcode containing the string `WIFI:T:ADB;S:studio-g@<xeYnap/;P:(Aq+v9>Cx>!/;;`. There are two parts in this string.

First Studio requested a specific service instance name for `_adb-tls-pairing._tcp`. The Device has a special Camera qrcode handler which when it sees
`WIFI:T:ADB` starts a Pairing Server with the requested instance name. This is done so Studio can tell which phone just scanned the qrcode
(here the instance name requested is `studio-g@<xeYnap/`).

The second part is the password to use with the Pairing Server (here: `;P:(Aq+v9>Cx>!/;;`).
This is the second shared secret vector we mentioned earlier. Here the code is generated
by Studio and read by the Device's camera.
