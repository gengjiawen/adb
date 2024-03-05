#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import print_function

import contextlib
import hashlib
import io
import os
import posixpath
import random
import re
import shlex
import shutil
import signal
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import proto.devices_pb2 as proto_devices
import proto.app_processes_pb2 as proto_track_app
import re

from datetime import datetime

import adb

def requires_non_root(func):
    def wrapper(self, *args):
        was_root = self.device.shell(['id', '-un'])[0].strip() == 'root'
        if was_root:
            self.device.unroot()
            self.device.wait()

        try:
            func(self, *args)
        finally:
            if was_root:
                self.device.root()
                self.device.wait()

    return wrapper


class DeviceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.device = adb.get_device()





def compute_md5(string):
    hsh = hashlib.md5()
    hsh.update(string)
    return hsh.hexdigest()


class HostFile(object):
    def __init__(self, handle, checksum):
        self.handle = handle
        self.checksum = checksum
        self.full_path = handle.name
        self.base_name = os.path.basename(self.full_path)


class DeviceFile(object):
    def __init__(self, checksum, full_path):
        self.checksum = checksum
        self.full_path = full_path
        self.base_name = posixpath.basename(self.full_path)


def make_random_host_files(in_dir, num_files):
    min_size = 1 * (1 << 10)
    max_size = 16 * (1 << 10)

    files = []
    for _ in range(num_files):
        file_handle = tempfile.NamedTemporaryFile(dir=in_dir, delete=False)

        size = random.randrange(min_size, max_size, 1024)
        rand_str = os.urandom(size)
        file_handle.write(rand_str)
        file_handle.flush()
        file_handle.close()

        md5 = compute_md5(rand_str)
        files.append(HostFile(file_handle, md5))
    return files


def make_random_device_files(device, in_dir, num_files, prefix='device_tmpfile'):
    min_size = 1 * (1 << 10)
    max_size = 16 * (1 << 10)

    files = []
    for file_num in range(num_files):
        size = random.randrange(min_size, max_size, 1024)

        base_name = prefix + str(file_num)
        full_path = posixpath.join(in_dir, base_name)

        device.shell(['dd', 'if=/dev/urandom', 'of={}'.format(full_path),
                      'bs={}'.format(size), 'count=1'])
        dev_md5, _ = device.shell(['md5sum', full_path])[0].split()

        files.append(DeviceFile(dev_md5, full_path))
    return files











class DevicesListing(DeviceTest):

    serial = subprocess.check_output(['adb', 'get-serialno']).strip().decode("utf-8")

    def test_track_app_appinfo(self):
        subprocess.check_output(['adb', 'install', '-t', 'test_device_apks/adb1.apk']).strip().decode("utf-8")
        subprocess.check_output(['adb', 'install', '-t', 'test_device_apks/adb2.apk']).strip().decode("utf-8")
        subprocess.check_output(['adb', 'shell', 'am', 'start', '-W', 'adb.test.app1/.MainActivity']).strip().decode("utf-8")
        subprocess.check_output(['adb', 'shell', 'am', 'start', '-W', 'adb.test.app2/.MainActivity']).strip().decode("utf-8")
        subprocess.check_output(['adb', 'shell', 'am', 'start', '-W', 'adb.test.app1/.OwnProcessActivity']).strip().decode("utf-8")
        with subprocess.Popen(['adb', 'track-app', '--proto-binary'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:

            output_size = int(proc.stdout.read(4).decode("utf-8"), 16)
            proto = proc.stdout.read(output_size)

            apps = proto_track_app.AppProcesses()
            apps.ParseFromString(proto)

            foundAdbAppDefProc = False
            foundAdbAppOwnProc = False
            for app in apps.process:
                if (app.process_name == "adb.test.process.name"):
                    foundAdbAppDefProc = True
                    self.assertTrue(app.debuggable)
                    self.assertTrue("adb.test.app1" in app.package_names)
                    self.assertTrue("adb.test.app2" in app.package_names)

                if (app.process_name == "adb.test.own.process"):
                    foundAdbAppOwnProc = True
                    self.assertTrue(app.debuggable)
                    self.assertTrue("adb.test.app1" in app.package_names)

            self.assertTrue(foundAdbAppDefProc)
            self.assertTrue(foundAdbAppOwnProc)
            proc.terminate()




if __name__ == '__main__':
    random.seed(0)
    unittest.main()
