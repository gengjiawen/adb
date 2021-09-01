/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <fuzzer/FuzzedDataProvider.h>
#include "client/commandline.h"

using namespace std;
const char* kBasicCommandArray[] = {"help", "--version", "devices", "disconnect"};
const char* kScriptingCommandArray[] = {"get-state", "get-serialno", "get-devpath", "usb",
                                        "root",      "unroot",       "remount",     "reboot"};
const char* kNetworkingCommandArray[] = {"forward", "reverse"};
const char* kMdnsOptionArray[] = {"check", "services"};
const char* kInternalDebuggingCommandArray[] = {"start-server", "kill-server", "reconnect"};
const char* kUsbCommandArray[] = {"attach", "detach"};
const char* kSecurityCommandArray[] = {"disable-verity", "enable-verity"};
const char* kFileTransferCommandArray[] = {"push", "pull"};
const char* kBasicShellCommandArray[] = {"ps", "dumpsys", "getprop", "ip", "netstat"};

const char* kHostPath = "/fuzz/x86_64/adb_cmd_fuzzer/data/fileTransferData/";
const char* kAppName = "HelloWorld.apk";
const char* kAppPackageName = "com.example.helloworldapp";
const char* kDevicePath = "/sdcard/";
const size_t kMaxBufferSize = 128;

string exec(const char* cmd) {
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        return string();
    }
    array<char, kMaxBufferSize> buffer;
    string result;
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

void removeSubstrs(string& s, const string& p) {
    size_t n = p.length();
    for (size_t i = s.find(p); i != string::npos; i = s.find(p)) {
        s.erase(i, n);
    }
}

static inline void removeNewlineFromString(string& str) {
    // Remove newline from the string
    str.erase(remove(str.begin(), str.end(), '\n'), str.end());
}

string getFirstSerialNumber(string str) {
    removeNewlineFromString(str);
    // Remove 'List of devices attached' from the string
    string substring = "List of devices attached";
    removeSubstrs(str, substring);

    if (str.empty()) {
        return string();
    }

    string serialNumber = str.substr(0, str.find(' '));
    return serialNumber;
}

string getHostPath() {
    string cmdOut = exec("echo $ANDROID_HOST_OUT");
    removeNewlineFromString(cmdOut);
    return cmdOut + kHostPath;
}

void process(const uint8_t* data, size_t size) {
    bool isDeviceAvailable = false;
    string serialNumber = "";
    FuzzedDataProvider dataProvider(data, size);

    string cmdOut = exec("adb devices -l");
    if (!cmdOut.empty()) {
        serialNumber = getFirstSerialNumber(cmdOut);
        if (!serialNumber.empty()) {
            isDeviceAvailable = true;
        }
    }

    vector<char*> argv;
    vector<string> strings;
    if (isDeviceAvailable) {
        strings.push_back("-s");
        strings.push_back(serialNumber);
    }
    size_t choice = dataProvider.ConsumeIntegralInRange<size_t>(0, 12);
    switch (choice) {
        case 0: {  // Basic command
            string command = dataProvider.PickValueInArray(kBasicCommandArray);
            strings.push_back(command);
            break;
        }
        case 1: {  // Scripting command
            string command = dataProvider.PickValueInArray(kScriptingCommandArray);
            if (isDeviceAvailable || !(command == kScriptingCommandArray[6])) {
                strings.push_back(command);
            }
            break;
        }
        case 2: {  // Networking command
            string command = dataProvider.PickValueInArray(kNetworkingCommandArray);
            strings.push_back(command);
            strings.push_back("--list");
            break;
        }
        case 3: {  // Mdns command
            string option = dataProvider.PickValueInArray(kMdnsOptionArray);
            strings.push_back("mdns");
            strings.push_back(option);
            break;
        }
        case 4: {  // Internal debugging command
            string command = dataProvider.PickValueInArray(kInternalDebuggingCommandArray);
            strings.push_back(command);
            break;
        }
        case 5: {  // Bugreport command
            if (isDeviceAvailable) {
                strings.push_back("bugreport");
            }
            break;
        }
        case 6: {  // Logcat command
            if (isDeviceAvailable) {
                strings.push_back("logcat");
                strings.push_back("-c");
            }
            break;
        }
        case 7: {  // Usb command
            string option = dataProvider.PickValueInArray(kUsbCommandArray);
            strings.push_back("usb");
            strings.push_back(option);
            break;
        }
        case 8: {  // Security command
            string command = dataProvider.PickValueInArray(kSecurityCommandArray);
            strings.push_back(command);
            break;
        }
        case 9: {  // File transfer command
            string command = dataProvider.PickValueInArray(kFileTransferCommandArray);
            strings.push_back(command);
            string hostPath = getHostPath();
            if (dataProvider.ConsumeBool()) {
                hostPath = std::tmpnam(nullptr);
            }
            strings.push_back(command == kFileTransferCommandArray[0] ? hostPath : kDevicePath);
            strings.push_back(command == kFileTransferCommandArray[0] ? kDevicePath : hostPath);
            break;
        }
        case 10: {  // Install command
            string appPath = getHostPath() + string(kAppName);
            if (dataProvider.ConsumeBool()) {
                appPath = std::tmpnam(nullptr) + string(".apk");
            }
            strings.push_back("install");
            strings.push_back(appPath);
            break;
        }
        case 11: {  // Uninstall command
            if (isDeviceAvailable) {
                strings.push_back("uninstall");
                strings.push_back(kAppPackageName);
            }
            break;
        }
        case 12: {  // Shell command
            if (isDeviceAvailable) {
                strings.push_back("shell");
                string command = dataProvider.PickValueInArray(kBasicShellCommandArray);
                strings.push_back(command);
            }
            break;
        }
        default: {
            break;
        }
    };

    argv.reserve(strings.size());
    for (auto& s : strings) {
        argv.push_back(&s[0]);
    }
    setenv("ADB_SERVER_SOCKET", "tcp:5037", 0 /* overwrite */);
    adb_commandline(argv.size(), const_cast<const char**>(argv.data()));
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    process(data, size);
    return 0;
}
