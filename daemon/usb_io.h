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
#include <android-base/unique_fd.h>

#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "daemon/property_monitor.h"
#include "daemon/usb_ffs.h"
#include "sysdeps.h"
#include "sysdeps/chrono.h"
#include "transfer_id.h"
#include "transport.h"
#include "types.h"

using android::base::StringPrintf;

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

class IUsbIoContext {
    public:
      virtual ~IUsbIoContext() = 0;
      static std::unique_ptr<IUsbIoContext> Init(unique_fd read_fd, unique_fd write_fd);
      virtual bool SubmitReadRequests() = 0;
      virtual bool ProcessEvents(atransport* transport) = 0;
      virtual bool SubmitWrites() = 0;
      virtual void NotifyWorkerEventFd() = 0;
      virtual bool WaitForIORequest() = 0;
      virtual bool ProcessWriteRequest(std::unique_ptr<apacket> packet) = 0;
};
