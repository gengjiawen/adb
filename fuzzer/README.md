# Fuzzers for adb module

## Plugin Design Considerations
The fuzzer plugins for adb are designed based on the understanding of the
source code and try to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzers.

adb supports the following parameters:
1. Shell Protocol Id (parameter name: `id`)
2. Basic Command (parameter name: `basicCommand`)
3. Scripting Command (parameter name: `scriptingCommand`)
4. Networking Command (parameter name: `networkingCommand`)
5. MDNS Option (parameter name: `mdnsOption`)
6. Internal Debugging Command (parameter name: `internalDebuggingCommand`)
7. Usb Command (parameter name: `usbCommand`)
8. Security Command (parameter name: `securityCommand`)
9. File Transfer Command (parameter name: `fileTransferCommand`)
10. Basic Shell Command (parameter name: `basicShellCommand`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `id` | 0.`ShellProtocol::kIdStdin` 1.`ShellProtocol::kIdStdout` 2.`ShellProtocol::kIdStderr` 3. `ShellProtocol::kIdExit` 4. `ShellProtocol::kIdCloseStdin` 5. `ShellProtocol::kIdWindowSizeChange` 6. `ShellProtocol::kIdInvalid`| Value obtained from FuzzedDataProvider|
| `basicCommand` | 0.`help` 1.`--version` 2.`devices` 3. `disconnect`| Value obtained from FuzzedDataProvider|
| `scriptingCommand` | 0.`get-state` 1.`get-serialno` 2.`get-devpath` 3. `usb` 4. `root` 5. `unroot` 6. `remount` 7. `reboot`| Value obtained from FuzzedDataProvider|
| `networkingCommand` | 0.`forward` 1.`reverse`| Value obtained from FuzzedDataProvider|
| `mdnsOption` | 0.`check` 1.`services`| Value obtained from FuzzedDataProvider|
| `internalDebuggingCommand` | 0.`start-server` 1.`kill-server` 2.`reconnect`| Value obtained from FuzzedDataProvider|
| `usbCommand` | 0.`attach` 1.`detach`| Value obtained from FuzzedDataProvider|
| `securityCommand` | 0.`disable-verity` 1.`enable-verity`| Value obtained from FuzzedDataProvider|
| `securityCommand` | 0.`disable-verity` 1.`enable-verity`| Value obtained from FuzzedDataProvider|
| `fileTransferCommand` | 0.`push` 1.`pull`| Value obtained from FuzzedDataProvider|
| `basicShellCommand` | 0.`ps` 1.`dumpsys` 2.`getprop` 3.`ip` 4.`netstat`| Value obtained from FuzzedDataProvider|

This also ensures that the plugins are always deterministic for any given input.

##### Maximize utilization of input data
The plugins feed the entire input data to the module.
This ensures that the plugins tolerate any kind of input (empty, huge,
malformed, etc) and dont `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build adb_shellServiceProtocol_fuzzer and adb_cmd_fuzzer binaries

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) adb_shellServiceProtocol_fuzzer
  $ mm -j$(nproc) adb_cmd_fuzzer
```
#### Steps to run
To run on host
```
  $ $ANDROID_HOST_OUT/fuzz/x86_64/adb_shellServiceProtocol_fuzzer/adb_shellServiceProtocol_fuzzer
  $ $ANDROID_HOST_OUT/fuzz/x86_64/adb_cmd_fuzzer/adb_cmd_fuzzer
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
