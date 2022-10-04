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

#include "localsocket.h"

int localsocket::enqueue(apacket::payload_type data) {
    D("LS(%d): enqueue %zu", id, data.size());

    s->packet_queue.append(std::move(data));
    switch (local_socket_flush_incoming(s)) {
        case SocketFlushResult::Destroyed:
            return -1;

        case SocketFlushResult::TryAgain:
            return 1;

        case SocketFlushResult::Completed:
            return 0;
    }

    return !packet_queue.empty();
}

void localsocket::ready() {
    // far side is ready for data, pay attention to readable events
    fdevent_add(fde, FDE_READ);
}

void localsocket::shutdown() {}

// The standard (RFC 1122 - 4.2.2.13) says that if we call close on a
// socket while we have pending data, a TCP RST should be sent to the
// other end to notify it that we didn't read all of its data. However,
// this can result in data that we've successfully written out to be dropped
// on the other end. To avoid this, instead of immediately closing a
// socket, call shutdown on it instead, and then read from the file
// descriptor until we hit EOF or an error before closing.
static void deferred_close(unique_fd fd) {
    // Shutdown the socket in the outgoing direction only, so that
    // we don't have the same problem on the opposite end.
    adb_shutdown(fd.get(), SHUT_WR);
    auto callback = [](fdevent* fde, unsigned event, void* arg) {
        auto socket_info = static_cast<ClosingSocket*>(arg);
        if (event & FDE_READ) {
            ssize_t rc;
            char buf[BUFSIZ];
            while ((rc = adb_read(fde->fd.get(), buf, sizeof(buf))) > 0) {
                continue;
            }

            if (rc == -1 && errno == EAGAIN) {
                // There's potentially more data to read.
                auto duration = std::chrono::steady_clock::now() - socket_info->begin;
                if (duration > 1s) {
                    LOG(WARNING) << "timeout expired while flushing socket, closing";
                } else {
                    return;
                }
            }
        } else if (event & FDE_TIMEOUT) {
            LOG(WARNING) << "timeout expired while flushing socket, closing";
        }

        // Either there was an error, we hit the end of the socket, or our timeout expired.
        fdevent_destroy(fde);
        delete socket_info;
    };

    ClosingSocket* socket_info = new ClosingSocket{
            .begin = std::chrono::steady_clock::now(),
    };

    fdevent* fde = fdevent_create(fd.release(), callback, socket_info);
    fdevent_add(fde, FDE_READ);
    fdevent_set_timeout(fde, 1s);
}

// be sure to hold the socket list lock when calling this
static void local_socket_destroy(asocket* s) {
    int exit_on_close = s->exit_on_close;

    D("LS(%d): destroying fde.fd=%d", s->id, s->fd);

    deferred_close(fdevent_release(s->fde));

    remove_socket(s);
    delete s;

    if (exit_on_close) {
        D("local_socket_destroy: exiting");
        exit(1);
    }
}

void localsocket::close() {
    D("entered local_socket_close. LS(%d) fd=%d", id, fd);
    std::lock_guard<std::recursive_mutex> lock(local_socket_list_lock);
    if (s->peer) {
        D("LS(%d): closing peer. peer->id=%d peer->fd=%d", s->id, s->peer->id, s->peer->fd);
        /* Note: it's important to call shutdown before disconnecting from
         * the peer, this ensures that remote sockets can still get the id
         * of the local socket they're connected to, to send a CLOSE()
         * protocol event. */
        if (s->peer->shutdown) {
            s->peer->shutdown(s->peer);
        }
        s->peer->peer = nullptr;
        s->peer->close(s->peer);
        s->peer = nullptr;
    }

    /* If we are already closing, or if there are no
    ** pending packets, destroy immediately
    */
    if (s->closing || s->has_write_error || s->packet_queue.empty()) {
        int id = s->id;
        local_socket_destroy(s);
        D("LS(%d): closed", id);
        return;
    }

    /* otherwise, put on the closing list
     */
    D("LS(%d): closing", s->id);
    s->closing = true;
    fdevent_del(s->fde, FDE_READ);
    remove_socket(s);
    D("LS(%d): put on socket_closing_list fd=%d", s->id, s->fd);
    local_socket_closing_list.push_back(s);
    CHECK_EQ(FDE_WRITE, s->fde->state & FDE_WRITE);
}
