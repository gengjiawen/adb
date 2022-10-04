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

#pragma once

#include "socket.h"

#include <inttypes.h>
#include <optional>

class localsocket : public asocket {
    localsocket();
    virtual ~localsocket();

    virtual int enqueue(apacket::payload_type data);
    virtual void ready();
    virtual void shutdown();
    virtual void close();

  private:
  private:
    /* flag: set when the socket's peer has closed
     * but packets are still queued for delivery
     */
    bool closing = false;

    // flag: set when the socket failed to write, so the socket will not wait to
    // write packets and close directly.
    bool has_write_error = false;

    /* flag: quit adbd when both ends close the
     * local service socket
     */
    int exit_on_close = 0;

    fdevent* fde = nullptr;
    int fd = -1;

    // Queue of data that we've received from our peer, and are waiting to write into fd.
    IOVector packet_queue;
    // End Local socket fields

    // The number of bytes that have been acknowledged by the other end if delayed_ack is available.
    // This value can go negative: if we have a MAX_PAYLOAD's worth of bytes available to send,
    // we'll send out a full packet.
    std::optional<int64_t> available_send_bytes;
};