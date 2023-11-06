# How to enable ADB traces for bug reports

### 1. Set the environment variable `ADB_TRACE` to `1`.

On Darwin/Linux, add the following line to `~/.bashrc`. 

```
ADB_TRACE=1
```

On Windows, add the global variable via the `System Properties` window.
In the `Advanced` tab, click on `Environment Variables`. Add the Variable/
Value to the `User variable` list.

### 2. Cycle adb server

Shutdown adb server via command `adb kill-server`. Close the current terminal,
open a new one and start adb server via `adb server`. Optionnaly, if you want
to see the trace live, you can use `adb server nodaemon`.



