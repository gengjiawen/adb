/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef __ADB_SOCKET_H
#define __ADB_SOCKET_H

#include <stddef.h>

#include <deque>
#include <memory>
#include <optional>
#include <string>

#include "adb_unique_fd.h"
#include "fdevent/fdevent.h"
#include "types.h"

class atransport;

/* An asocket represents one half of a connection between a local and
   remote entity.  A local asocket is bound to a file descriptor.  A
   remote asocket is bound to the protocol engine.

   Example (two local_sockets) :

                                   ASOCKET(THIS)
              ┌────────────────────────────────────────────────┐
┌──┐ write(3) │  ┌─────┐                      enqueue()        │
│  │◄─────────┼──┤Queue├─────────────◄────────────┐            │
│fd│          │  └─────┘                          ▲            │
│  ├──────────►─────────────────┐                 │            │
└──┘ read(3)  └─────────────────┼─────────────────┼────────────┘
                       outgoing │                 │ incoming
              ┌─────────────────▼─────────────────▲────────────┐  read(3)  ┌──┐
              │                 │                 └────────────┼─────────◄─┤  │
              │                 │                      ┌─────┐ │           │fd│
              │                 └─────────────────────►│Queue├─┼─────────►─┤  │
              │                enqueue()               └─────┘ │  write(3) └──┘
              └────────────────────────────────────────────────┘
                                 ASOCKET(PEER)

    Note that sockets can be peered regardless of their kind. A remote socket can be peered with
    a smart socket, a local socket can be peered with a remote socket and so on.
 */
class asocket {
  public:
    // the unique identifier for this asocket
    unsigned id = 0;

    int fd = -1;

    // the asocket we are connected to
    asocket* peer = nullptr;

    /* enqueue is called by our peer when it has data
     * for us.  It should return 0 if we can accept more
     * data or 1 if not.  If we return 1, we must call
     * peer->ready() when we once again are ready to
     * receive data.
     */
    virtual int enqueue(apacket::payload_type data) = 0;

    /* ready is called by the peer when it is ready for
     * us to send data via enqueue again
     */
    virtual void ready() = 0;

    /* shutdown is called by the peer before it goes away.
     * the socket should not do any further calls on its peer.
     * Always followed by a call to close. Optional, i.e. can be NULL.
     */
    virtual void shutdown() = 0;

    /* close is called by the peer when it has gone away.
     * we are not allowed to make any further calls on the
     * peer once our close method is called.
     */
    virtual void close() = 0;

    /* A socket is bound to atransport */
    atransport* transport = nullptr;

    size_t get_max_payload() const;

  protected:
    asocket(){};
    virtual ~asocket(){};
};

class RemoteSocket : public asocket {
  public:
    explicit RemoteSocket(int file_descriptor) { this->fd = file_descriptor; }

    int enqueue(apacket::payload_type data) override;
    void ready() override;
    void shutdown() override;
    void close() override;

  private:
    apacket* get_apacket(void);
};

class LocalSocket : public asocket {
  public:
    explicit LocalSocket(int file_descriptor) { this->fd = file_descriptor; }

    int enqueue(apacket::payload_type data) override;
    void ready() override;
    void shutdown() override;
    void close() override;

    enum class SocketFlushResult {
        Destroyed,
        TryAgain,
        Completed,
    };
    SocketFlushResult Flush_incoming();

    fdevent* fde = nullptr;

    // The number of bytes that have been acknowledged by the other end if delayed_ack is available.
    // This value can go negative: if we have a MAX_PAYLOAD's worth of bytes available to send,
    // we'll send out a full packet.
    std::optional<int64_t> available_send_bytes;

  private:
    /* flag: set when the socket's peer has closed
     * but packets are still queued for delivery
     * TODO: This should be a boolean.
     */
    bool closing = false;

    // flag: set when the socket failed to write, so the socket will not wait to
    // write packets and close directly.
    bool has_write_error = false;

    /* flag: quit adbd when both ends close the
     * local service socket
     */
    bool exit_on_close = false;

    // Queue of data that we've received from our peer, and are waiting to write into fd.
    IOVector packet_queue;
    // End Local socket fields

    bool Flush_outgoing();

    void Destroy();
};

LocalSocket* find_local_socket(unsigned local_id, unsigned remote_id);
void install_local_socket(LocalSocket* s);
void remove_socket(asocket *s);
void close_all_sockets(atransport *t);

void local_socket_ack(asocket* s, std::optional<int32_t> acked_bytes);

LocalSocket* create_local_socket(unique_fd fd);
LocalSocket* create_local_service_socket(std::string_view destination, atransport* transport);

asocket *create_remote_socket(unsigned id, atransport *t);
void connect_to_remote(asocket* s, std::string_view destination);

#if ADB_HOST
void connect_to_smartsocket(asocket *s);
#endif

// Internal functions that are only made available here for testing purposes.
namespace internal {

#if ADB_HOST
bool parse_host_service(std::string_view* out_serial, std::string_view* out_command,
                        std::string_view service);
#endif

}  // namespace internal

#endif  // __ADB_SOCKET_H
