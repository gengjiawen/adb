# How to enable ADB traces for bug reports

## 1. Set the environment variable

### On Darwin/Linux

Add the following line to `~/.bashrc`. 

```
ADB_TRACE=all
```

### On Windows

Add the global variable via the `System Properties` window.
In the `Advanced` tab, click on `Environment Variables`. Add the Variable/
Value to the `User variable` list.

## 2. Cycle adb server

Shutdown adb server via command `adb kill-server`. Close the current terminal,
open a new one, and start adb server via `adb server`. Optionnaly, if you want
to see the traces live, you can use `adb server nodaemon`.

## 3. Locate the log files

### On Darwin/Linux

The log files are located in `$TMPDIR` which is almost always `/tmp/`. Log files
are create on a per pid basis, `adb<PID>.log`.

### On Windows

The log files are located in `%TEMP%` which is often `C:\Users\<uid>\AppData\Local\Temp`.
The filename is always `adb.log`.
