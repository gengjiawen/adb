/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#include <linux/usb/functionfs.h>
#include <sys/eventfd.h>

#include <algorithm>
#include <array>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

#include <asyncio/AsyncIO.h>

#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/parsebool.h>
#include <android-base/properties.h>
#include <android-base/thread_annotations.h>

#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "daemon/property_monitor.h"
#include "daemon/usb_ffs.h"
#include "sysdeps.h"
#include "sysdeps/chrono.h"
#include "transfer_id.h"
#include "transport.h"
#include "types.h"

#include <android-base/unique_fd.h>

// Not all USB controllers support operations larger than 16k, so don't go above that.
// Also, each submitted operation does an allocation in the kernel of that size, so we want to
// minimize our queue depth while still maintaining a deep enough queue to keep the USB stack fed.
static constexpr size_t kUsbReadQueueDepth = 8;
static constexpr size_t kUsbReadSize = 4 * PAGE_SIZE;

static constexpr size_t kUsbWriteQueueDepth = 8;
static constexpr size_t kUsbWriteSize = 4 * PAGE_SIZE;

template <class Payload>
struct IoBlock {
    bool pending = false;
    struct iocb control = {};
    Payload payload;

    TransferId id() const { return TransferId::from_value(control.aio_data); }
};

using IoReadBlock = IoBlock<Block>;
using IoWriteBlock = IoBlock<std::shared_ptr<Block>>;

struct ScopedAioContext {
    ScopedAioContext() = default;
    ~ScopedAioContext() { reset(); }

    ScopedAioContext(ScopedAioContext&& move) { reset(move.release()); }
    ScopedAioContext(const ScopedAioContext& copy) = delete;

    ScopedAioContext& operator=(ScopedAioContext&& move) {
        reset(move.release());
        return *this;
    }
    ScopedAioContext& operator=(const ScopedAioContext& copy) = delete;

    static ScopedAioContext Create(size_t max_events) {
        aio_context_t ctx = 0;
        if (io_setup(max_events, &ctx) != 0) {
            PLOG(FATAL) << "failed to create aio_context_t";
        }
        ScopedAioContext result;
        result.reset(ctx);
        return result;
    }

    aio_context_t release() {
        aio_context_t result = context_;
        context_ = 0;
        return result;
    }

    void reset(aio_context_t new_context = 0) {
        if (context_ != 0) {
            io_destroy(context_);
        }

        context_ = new_context;
    }

    aio_context_t get() { return context_; }

  private:
    aio_context_t context_ = 0;
};

class UsbFfsConnection : public Connection {
  public:
    UsbFfsConnection(unique_fd control, unique_fd read, unique_fd write,
                     std::promise<void> destruction_notifier);


    ~UsbFfsConnection();

    virtual bool Write(std::unique_ptr<apacket> packet) override final;
    void Start() override final { StartMonitor(); }
    void Stop() override final;

    virtual bool DoTlsHandshake(RSA* key, std::string* auth_key) override final {
        // TODO: support TLS for usb connections.
        LOG(FATAL) << "Not supported yet.";
        return false;
    }

  private:
    void StartMonitor();
    void StartWorker();
    void StopWorker();
    void PrepareReadBlock(IoReadBlock* block, uint64_t id);
    IoReadBlock CreateReadBlock(uint64_t id);
    void ReadEvents();
    bool HandleRead(TransferId id, int64_t size);
    bool ProcessRead(IoReadBlock* block);
    bool SubmitRead(IoReadBlock* block);
    void HandleWrite(TransferId id);
    IoWriteBlock CreateWriteBlock(Block&& payload, uint64_t id);
    IoWriteBlock CreateWriteBlock(std::shared_ptr<Block> payload, size_t offset, size_t len,
                                  uint64_t id);

    void SubmitWrites() REQUIRES(write_mutex_);
    void HandleError(const std::string& error);
    const char* to_string(enum usb_functionfs_event_type type);

    std::thread monitor_thread_;

    bool worker_started_;
    std::thread worker_thread_;

    std::atomic<bool> stopped_;
    std::promise<void> destruction_notifier_;
    std::once_flag error_flag_;

    unique_fd worker_event_fd_;
    unique_fd monitor_event_fd_;

    ScopedAioContext aio_context_;
    unique_fd control_fd_;
    unique_fd read_fd_;
    unique_fd write_fd_;

    bool connection_started_ = false;
    std::optional<amessage> incoming_header_;
    IOVector incoming_payload_;

    std::array<IoReadBlock, kUsbReadQueueDepth> read_requests_;
    IOVector read_data_;

    // ID of the next request that we're going to send out.
    size_t next_read_id_ = 0;

    // ID of the next packet we're waiting for.
    size_t needed_read_id_ = 0;

    std::mutex write_mutex_;
    std::deque<IoWriteBlock> write_requests_ GUARDED_BY(write_mutex_);
    size_t next_write_id_ GUARDED_BY(write_mutex_) = 0;
    size_t writes_submitted_ GUARDED_BY(write_mutex_) = 0;

    static constexpr int kInterruptionSignal = SIGUSR1;
};
