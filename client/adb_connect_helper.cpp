/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "client/adb_connect_helper.h"

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include "adb_utils.h"
#include "socket_spec.h"
#include "sysdeps.h"
#include "transport.h"

namespace mdns {

namespace {

auto& connect_queue = *new BlockingQueue<std::packaged_task<std::string(void)>>();

void adb_connect(const std::string& address, std::string* response) {
    if (address.empty()) {
        *response = "empty address";
        return;
    }

    LOG(INFO) << "connection requested to '" << address << "'";
    std::string prefix_addr;

    // If address does not match any socket type, it should default to TCP.
    if (address.starts_with("vsock:") || address.starts_with("localfilesystem:")) {
        prefix_addr = address;
    } else {
        prefix_addr = "tcp:" + address;
    }

    unique_fd fd;
    int port;
    std::string serial;

    socket_spec_connect(&fd, prefix_addr, &port, &serial, response);
    if (fd.get() == -1) {
        return;
    }
    auto reconnect = [prefix_addr](atransport* t) {
        std::string response;
        unique_fd fd;
        int port;
        std::string serial;
        socket_spec_connect(&fd, prefix_addr, &port, &serial, &response);
        if (fd == -1) {
            LOG(INFO) << "reconnect failed: " << response;
            return ReconnectResult::Retry;
        }
        // This invokes the part of register_socket_transport() that needs to be
        // invoked if the atransport* has already been setup. This eventually
        // calls atransport->SetConnection() with a newly created Connection*
        // that will in turn send the CNXN packet.
        return init_socket_transport(t, std::move(fd), port, 0) >= 0 ? ReconnectResult::Success
                                                                     : ReconnectResult::Retry;
    };

    int error;
    if (!register_socket_transport(std::move(fd), serial, port, 0, std::move(reconnect), false,
                                   &error)) {
        if (error == EALREADY) {
            *response = android::base::StringPrintf("already connected to %s", serial.c_str());
        } else if (error == EPERM) {
            *response = android::base::StringPrintf("failed to authenticate to %s", serial.c_str());
        } else {
            *response = android::base::StringPrintf("failed to connect to %s", serial.c_str());
        }
    } else {
        *response = android::base::StringPrintf("connected to %s", serial.c_str());
    }
}

void connect_thread() {
    LOG(INFO) << "adb connection thread started";
    adb_thread_setname("adb connect");
    while (true) {
        connect_queue.PopAll([](const std::packaged_task<std::string(void)>& t) {
            const_cast<std::packaged_task<std::string(void)>&>(t)();
        });
    }
}

}  // namespace

std::future<std::string> PostAdbConnectionRequest(const std::string& address) {
    static std::once_flag once;
    std::call_once(once, [&]() { std::thread(connect_thread).detach(); });

    std::packaged_task<std::string(void)> task([address]() {
        std::string response;
        adb_connect(address, &response);
        return response;
    });
    auto result = task.get_future();

    connect_queue.Push(std::move(task));
    return result;
}

}  // namespace mdns
