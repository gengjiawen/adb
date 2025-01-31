```
This file tries to document file-related requests a client can make
to the ADB server of an adbd daemon. See the OVERVIEW.TXT document
to understand what's going on here. See the SERVICES.TXT to learn more
about the other requests that are possible.

SYNC SERVICES:


Requesting the sync service ("sync:") using the protocol as described in
SERVICES.TXT sets the connection in sync mode. This mode is a binary mode that
differs from the regular adb protocol. The connection stays in sync mode until
explicitly terminated (see below).

After the initial "sync:" command is sent, the server must respond with either
"OKAY" or "FAIL" as per the usual protocol.

In sync mode both the server and the client will frequently use eight-byte
packets to communicate. In this document these are called sync requests and sync
responses. The first four bytes constitute an id that specifies the sync request.
It is represented by four ASCII bytes in order to make them more human-readable
when debugging. The last four bytes are a Little-Endian integer, with various
uses. This number shall be called "length" below. In fact, all binary integers
are Little-Endian in the sync mode. Sync mode is implicitly exited after each
sync request, and normal adb communication follows as described in SERVICES.TXT.

The following sync requests are accepted:
LIST - List the files in a folder
RECV - Retrieve a file from device
SEND - Send a file to device
STAT - Stat a file

All of the sync requests above must be followed by "length": the number of
bytes containing a utf-8 string with a remote filename.

LIST:
Lists files in the directory specified by the remote filename. The server will
respond with zero or more directory entries or "dents".

The directory entries will be returned in the following form
1. A four-byte sync response id "DENT"
2. A four-byte integer representing file mode.
3. A four-byte integer representing file size.
4. A four-byte integer representing last modified time.
5. A four-byte integer representing file name length.
6. length number of bytes containing an utf-8 string representing the file
   name.

When a sync response "DONE" is received the listing is done.

SEND:
The remote file name is split into two parts separated by the last
comma (","). The first part is the actual path, while the second is a decimal
encoded file mode containing the permissions of the file on device.

Note that some file types will be deleted before the copying starts, and if
the transfer fails. Some file types will not be deleted, which allows
  adb push disk_image /some_block_device
to work.

After this the actual file is sent in chunks. Each chunk has the following
format.
A sync request with id "DATA" and length equal to the chunk size. After
follows chunk size number of bytes. This is repeated until the file is
transferred. Each chunk must not be larger than 64k.

When the file is transferred a sync request "DONE" is sent, where length is set
to the last modified time for the file. The server responds to this last
request (but not to chunk requests) with an "OKAY" sync response (length can
be ignored).


RECV:
Retrieves a file from device to a local file. The remote path is the path to
the file that will be returned. Just as for the SEND sync request the file
received is split up into chunks. The sync response id is "DATA" and length is
the chunk size. After follows chunk size number of bytes. This is repeated
until the file is transferred. Each chunk will not be larger than 64k.

When the file is transferred a sync response "DONE" is retrieved where the
length can be ignored.
```