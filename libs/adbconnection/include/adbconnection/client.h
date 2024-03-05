/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <stdint.h>
#include <sys/types.h>

#include <android-base/unique_fd.h>

extern "C" {

struct AdbConnectionClientContext;

enum AdbConnectionClientInfoType {
  pid,
  debuggable,
  profileable,
  architecture,
};

struct AdbConnectionClientInfo {
  AdbConnectionClientInfoType type;
  union {
    uint64_t pid;
    bool debuggable;
    bool profileable;
    struct {
      const char* name;
      size_t size;
    } architecture;
  } data;
};

// Construct a context and connect to adbd.
// Returns null if we fail to connect to adbd.
// Note this is an apex interface as it's loaded by ART.
AdbConnectionClientContext* adbconnection_client_new(
    const AdbConnectionClientInfo* const* info_elems, size_t info_count);

// Update the apex client with the new name of the process. Nothing is transferred to the server.
// You need to call adbconnection_client_send_update to transmit the latest state to adbd
void adbconnection_client_on_process_named(const char* process_name);

// Update the apex client when a package name is added to the current process. Nothing is
// transferred to the server. You need to call adbconnection_client_send_update to transmit the
// latest state to adbd
void adbconnection_client_on_application_added(const char* package_name);

// Update the apex client when the app state changes (e.g.: Waiting for debugger). Nothing is
// transferred to the server. You need to call adbconnection_client_send_update to transmit the
// latest state to adbd
void adbconnection_client_on_set_state(int state);

// Update the apex client when app process uid is known. This is not the value from getuid() but
// rather the value massaged by Framework via PER_USER_RANGE and USER_SYSTEM. Nothing is transferred
// to the server. You need to call adbconnection_client_send_update to transmit the latest state to
// adbd
void adbconnection_client_on_user_id_known(int uid);

// Check if the client has something to send to the server. If it does,
// adbconnection_client_send_update  should be called.
bool adbconnection_client_has_pending_update();

// Write the latest appinfo state so adbd receives it.
void adbconnection_client_send_update(AdbConnectionClientContext* ctx);

void adbconnection_client_destroy(AdbConnectionClientContext* ctx);

// Get an fd which can be polled upon to detect when a jdwp socket is available.
// You do not own this fd. Do not close it.
int adbconnection_client_pollfd(AdbConnectionClientContext* ctx);

// Receive a jdwp client fd.
// Ownership is transferred to the caller of this function.
int adbconnection_client_receive_jdwp_fd(AdbConnectionClientContext* ctx);
}
