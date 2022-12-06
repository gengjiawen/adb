/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define TRACE_TAG TRANSPORT

#include "command_connection.h"

#include <android-base/stringprintf.h>

#include "adb.h"
#include "adb_unique_fd.h"
#include "sysdeps.h"
#include "transport.h"

namespace {

// CommandConnection is a FdConnection whose FD is connected to the stdin and stdout of a command
// process.
struct CommandConnection : public FdConnection {
    CommandConnection(unique_fd fd, Process process)
        : FdConnection(std::move(fd)), process_(std::move(process)) {}

    ~CommandConnection() override = default;

    void Close() override {
        FdConnection::Close();
        process_.kill();
        process_.wait();
    }

    Process process_;
};

std::unique_ptr<CommandConnection> create_command_connection(const std::string& command) {
    int socket_fds[2];
    if (adb_socketpair(socket_fds)) {
        return nullptr;
    }
    unique_fd fd_parent(socket_fds[0]), fd_child(socket_fds[1]);
    auto child = adb_launch_process("/bin/sh", {"-c", command}, {}, fd_child.get(), fd_child.get());
    if (!child) {
        return nullptr;
    }
    return std::make_unique<CommandConnection>(std::move(fd_parent), std::move(child));
}

}  // namespace

void connect_command(const std::string& command, std::string* response) {
    auto connection = create_command_connection(command);
    if (!connection) {
        *response = "Failed to launch a command process.";
        return;
    }

    auto reconnect = [command](atransport* t) {
        auto connection = create_command_connection(command);
        if (!connection) {
            D("Failed to launch a command process.");
            return ReconnectResult::Retry;
        }
        return init_socket_transport(t, std::move(connection), 0, 0) >= 0 ? ReconnectResult::Success
                                                                          : ReconnectResult::Retry;
    };

    std::string serial = "command:" + command;
    int error = 0;
    if (!register_socket_transport(std::move(connection), serial, 0, 0, std::move(reconnect), false,
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
    return;
}
