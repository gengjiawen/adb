# adb benchmark manual

## Pre-requisites

```
$ source build/envsetup.sh
$ lunch aosp_arm-eng
```

## Common error
> adb benchmark has a dependency on `development/python-packages/adb`.

Without it, attempting to run will result in an error. Running `lunch` setups `PYTHONPATH` properly.

```
$ ./benchmark_device.py
Traceback (most recent call last):
  File "/Volumes/aosp/aosp-main-with-phones/packages/modules/adb/./benchmark_device.py", line 24, in <module>
    import adb
ModuleNotFoundError: No module named 'adb'
```

## Sample run (Pixel 8, USB 3 cable)

```
$ ./benchmark_device.py
sink 100MiB: 10 runs: median 27.00 MiB/s, mean 26.39 MiB/s, stddev: 1.11 MiB/s
source 100MiB: 10 runs: median 36.97 MiB/s, mean 37.05 MiB/s, stddev: 0.46 MiB/s
push 100MiB: 10 runs: median 331.96 MiB/s, mean 329.81 MiB/s, stddev: 14.67 MiB/s
pull 100MiB: 10 runs: median 34.55 MiB/s, mean 33.57 MiB/s, stddev: 2.54 MiB/s
```

