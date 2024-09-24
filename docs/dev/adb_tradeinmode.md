# Architecture of *ADB Trade-In Mode*

After a device is factory reset it boots into the SetUp Wizard (SUW). On user builds, and
user builds only, SUW enables ADB in a specialized "trade-in mode" (TIM). This is a highly
restricted ADB designed to faciliate automated diagnostics.

TIM is controlled by the `service.adb.tradeinmode` property. If the property is set to 1 when adbd
starts, then adbd will lower its SELinux context to a highly restricted policy (`adb_tradeinmode`).
This policy restricts adbd to effectively one command: `adb shell tradeinmode`. It also disables
authorization.

On user builds, as mentioned, SUW orchestrates enabling ADB and setting the
`service.adb.tradeinmode` property. This also starts a trade-in mode daemon which automatically
kills ADB once the device is provisioned, setting `service.adb.tradeinmode` to 0 as well. If for
some reason adbd fails to enter trade-in mode (and it was supposed to), then it sets the property
to `service.adb.tradeinmode` to -1, and adbd is stopped by a trigger in adbd.rc.

On userdebug builds, TIM is not enabled by default since adb is already available. This means the
authorization dialog is still present. However, TIM can still be manually tested with the following
command sequence:
1. `adb root`
2. `adb shell setprop service.adb.tradeinmode 1`
3. `adb unroot`

Unlike user builds, if entering TIM fails, then userdebug adbd will simply restart without TIM
enabled.

## Enabling Trade-In Mode

Trade-in Mode is enabled at the first screen of Setup Wizard. SUW is responsible for calling into
the ITradeInMode service in system\_server, which then sets the appropriate properties to start
ADB, and then starts the watchdog to stop ADB when SUW or device provisioning is complete.

## Trade-In Mode commands

When ADB is in trade-in mode, the only allowed command is `adb shell tradeinmode` plus arguments.
On userdebug or eng builds, `adb root` is also allowed.

The tradeinmode shell command has two arguments:
 - `getstatus [-challenge CHALLENGE]`: Returns diagnostic information about the device, optionally
   with an attestation challenge.
 - `enter`: Bypasses setup and enters Android in an evaluation mode. A factory reset is forced on
   next boot.

## service.adb.tradeinmode values
 - `-1`: Failed to start TIM.
 - `0`: TIM is not enabled.
 - `1`: TIM is enabled.
 - `2`: "adb shell tradeinmode enter" was used, which enables adbd past SUW but
        also guarantees a factory reset on reboot.
