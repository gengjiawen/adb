/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define TRACE_TAG USB

#include <sys/utsname.h>

#include "daemon/usb.h"

const char* UsbFfsConnection::to_string(enum usb_functionfs_event_type type) {
    switch (type) {
        case FUNCTIONFS_BIND:
            return "FUNCTIONFS_BIND";
        case FUNCTIONFS_UNBIND:
            return "FUNCTIONFS_UNBIND";
        case FUNCTIONFS_ENABLE:
            return "FUNCTIONFS_ENABLE";
        case FUNCTIONFS_DISABLE:
            return "FUNCTIONFS_DISABLE";
        case FUNCTIONFS_SETUP:
            return "FUNCTIONFS_SETUP";
        case FUNCTIONFS_SUSPEND:
            return "FUNCTIONFS_SUSPEND";
        case FUNCTIONFS_RESUME:
            return "FUNCTIONFS_RESUME";
    }
}

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

bool UsbFfsConnection::IsIouringSupported() {
    struct utsname uts;
    unsigned int major, minor;

    std::string prop = android::base::GetProperty("service.adb.root", "");

    if (prop == "0") {
        LOG(INFO) << "service.adb.root is false";
        return false;
    }

    if (!(getuid() == 0)) {
        LOG(INFO) << "adbd does not have root access";
        return false;
    }

    LOG(INFO) << "adbd is running as root";
    struct rlimit limit;

    int ret = getrlimit(RLIMIT_MEMLOCK, &limit);
    if (ret == 0) {
        LOG(INFO) << "rlim_cur: " << limit.rlim_cur
                  << " rlim_max:: " << limit.rlim_max;
    } else {
        PLOG(ERROR) << "getrlimit failed";
    }

    if ((uname(&uts) != 0) || (sscanf(uts.release, "%u.%u", &major, &minor) != 2)) {
        PLOG(ERROR) << "Could not parse the kernel version from uname. "
                        << " io_uring not supported";
        return false;
    }

    // We will only support kernels from 5.6 onwards as IOSQE_ASYNC flag and
    // IO_URING_OP_READ/WRITE opcodes were introduced only on 5.6 kernel
    if (major >= 5) {
        if (major == 5 && minor < 6) {
            return false;
        }
    } else {
        return false;
    }

    LOG(INFO) << "IsIouringSupported - true";
    return true;
}

UsbFfsConnection::UsbFfsConnection(unique_fd control, unique_fd read, unique_fd write,
                                   std::promise<void> destruction_notifier)
  : worker_started_(false), worker_write_started_(false),
  stopped_(false),
  destruction_notifier_(std::move(destruction_notifier)),
  control_fd_(std::move(control)) {
    LOG(INFO) << "UsbFfsConnection constructed";

    monitor_event_fd_.reset(eventfd(0, EFD_CLOEXEC));
    if (monitor_event_fd_ == -1) {
      PLOG(FATAL) << "failed to create eventfd";
    }

    //io_context_ = IUsbIoContext::Init(std::move(read), std::move(write), IsIouringSupported());
    io_context_ = IUsbIoContext::Init(std::move(read), std::move(write), IsIouringSupported());

    //iou_context_ = IUsbIoContext::Init_iou(std::move(write), IsIouringSupported());
}

void UsbFfsConnection::HandleError(const std::string& error) {
  std::call_once(error_flag_, [&]() {
    if (transport_) {
      transport_->HandleError(error);
    }

    if (!stopped_) {
      Stop();
    }
  });
}

void UsbFfsConnection::StopWorker() {
  if (!worker_started_) {
    return;
  }

  pthread_t worker_thread_handle = worker_thread_.native_handle();
  while (true) {
    int rc = pthread_kill(worker_thread_handle, kInterruptionSignal);
    if (rc != 0) {
      LOG(ERROR) << "failed to send interruption signal to worker: " << strerror(rc);
      break;
    }

    std::this_thread::sleep_for(100ms);

    rc = pthread_kill(worker_thread_handle, 0);
    if (rc == 0) {
      continue;
    } else if (rc == ESRCH) {
      break;
    } else {
      LOG(ERROR) << "failed to send interruption signal to worker: " << strerror(rc);
    }
  }

  worker_thread_.join();

  if (!worker_write_started_) {
    return;
  }
  // Debug
  pthread_t worker_write_thread_handle = worker_write_thread_.native_handle();
  while (true) {
    int rc = pthread_kill(worker_write_thread_handle, kInterruptionSignal);
    if (rc != 0) {
      LOG(ERROR) << "failed to send interruption signal to worker: " << strerror(rc);
      break;
    }

    std::this_thread::sleep_for(100ms);

    rc = pthread_kill(worker_write_thread_handle, 0);
    if (rc == 0) {
      continue;
    } else if (rc == ESRCH) {
      break;
    } else {
      LOG(ERROR) << "failed to send interruption signal to worker: " << strerror(rc);
    }
  }

  worker_write_thread_.join();
}

void UsbFfsConnection::StartWorker() {
  CHECK(!worker_started_);
  worker_started_ = true;
  worker_thread_ = std::thread([this]() {
    adb_thread_setname("UsbFfs-worker");
    LOG(INFO) << "UsbFfs-worker thread spawned";

    if (!io_context_->SubmitReadRequests()) {
        HandleError("SubmitReadRequests failed");
        return;
    }

    while (!stopped_) {
      if (!io_context_->WaitForIORequest()) {
          LOG(FATAL) << "WaitForIORequest failed";
      }

      if (!io_context_->ProcessEvents(transport_)) {
          HandleError("ProcessEvents Failed");
      }
#if 1
      if (!io_context_->SubmitWrites()) {
          HandleError("SubmitWrites Failed");
      }
#endif
    }
  });
}

void UsbFfsConnection::StartWriteWorker() {
  CHECK(!worker_write_started_);
  worker_write_started_ = true;
  worker_write_thread_ = std::thread([this]() {
    adb_thread_setname("UsbFfs-write-worker");
    LOG(INFO) << "UsbFfs-write-worker thread spawned";

    while (!stopped_) {
      if (!iou_context_->WaitForIORequest()) {
          LOG(FATAL) << "WaitForIORequest failed";
          //LOG(ERROR) << "WaitForIORequest failed";
          continue;
      }

      if (!iou_context_->ProcessEvents(transport_)) {
          HandleError("ProcessEvents Failed");
      }

      if (!iou_context_->SubmitWrites()) {
          HandleError("SubmitWrites Failed");
      }
    }
  });
}



void UsbFfsConnection::StartMonitor() {
  // This is a bit of a mess.
  // It's possible for io_submit to end up blocking, if we call it as the endpoint
  // becomes disabled. Work around this by having a monitor thread to listen for functionfs
  // lifecycle events. If we notice an error condition (either we've become disabled, or we
  // were never enabled in the first place), we send interruption signals to the worker thread
  // until it dies, and then report failure to the transport via HandleError, which will
  // eventually result in the transport being destroyed, which will result in UsbFfsConnection
  // being destroyed, which unblocks the open thread and restarts this entire process.
  static std::once_flag handler_once;
  std::call_once(handler_once, []() { signal(kInterruptionSignal, [](int) {}); });

  monitor_thread_ = std::thread([this]() {
    adb_thread_setname("UsbFfs-monitor");
    LOG(INFO) << "UsbFfs-monitor thread spawned";

    bool bound = false;
    bool enabled = false;
    bool running = true;
    while (running) {
      adb_pollfd pfd[2] = {
        { .fd = control_fd_.get(), .events = POLLIN, .revents = 0 },
        { .fd = monitor_event_fd_.get(), .events = POLLIN, .revents = 0 },
      };

      // If we don't see our first bind within a second, try again.
      int timeout_ms = bound ? -1 : 1000;

      int rc = TEMP_FAILURE_RETRY(adb_poll(pfd, 2, timeout_ms));
      if (rc == -1) {
        PLOG(FATAL) << "poll on USB control fd failed";
      } else if (rc == 0) {
        LOG(WARNING) << "timed out while waiting for FUNCTIONFS_BIND, trying again";
        break;
      }

      if (pfd[1].revents) {
        // We were told to die.
        break;
      }

      struct usb_functionfs_event event;
      rc = TEMP_FAILURE_RETRY(adb_read(control_fd_.get(), &event, sizeof(event)));
      if (rc == -1) {
        PLOG(FATAL) << "failed to read functionfs event";
      } else if (rc == 0) {
        LOG(WARNING) << "hit EOF on functionfs control fd";
        break;
      } else if (rc != sizeof(event)) {
        LOG(FATAL) << "read functionfs event of unexpected size, expected "
                   << sizeof(event) << ", got " << rc;
      }

      LOG(INFO) << "USB event: "
                << to_string(static_cast<usb_functionfs_event_type>(event.type));

      switch (event.type) {
        case FUNCTIONFS_BIND:
          if (bound) {
            LOG(WARNING) << "received FUNCTIONFS_BIND while already bound?";
            running = false;
            break;
          }

          if (enabled) {
            LOG(WARNING) << "received FUNCTIONFS_BIND while already enabled?";
            running = false;
            break;
          }

          bound = true;
          break;

        case FUNCTIONFS_ENABLE:
          if (!bound) {
            LOG(WARNING) << "received FUNCTIONFS_ENABLE while not bound?";
            running = false;
            break;
          }

          if (enabled) {
            LOG(WARNING) << "received FUNCTIONFS_ENABLE while already enabled?";
            running = false;
            break;
          }

          enabled = true;
          StartWorker();
          //StartWriteWorker();
          break;

        case FUNCTIONFS_DISABLE:
          if (!bound) {
            LOG(WARNING) << "received FUNCTIONFS_DISABLE while not bound?";
          }

          if (!enabled) {
            LOG(WARNING) << "received FUNCTIONFS_DISABLE while not enabled?";
          }

          enabled = false;
          running = false;
          break;

        case FUNCTIONFS_UNBIND:
          if (enabled) {
            LOG(WARNING) << "received FUNCTIONFS_UNBIND while still enabled?";
          }

          if (!bound) {
            LOG(WARNING) << "received FUNCTIONFS_UNBIND when not bound?";
          }

          bound = false;
          running = false;
          break;

        case FUNCTIONFS_SETUP: {
          LOG(INFO) << "received FUNCTIONFS_SETUP control transfer: bRequestType = "
                    << static_cast<int>(event.u.setup.bRequestType)
                    << ", bRequest = " << static_cast<int>(event.u.setup.bRequest)
                    << ", wValue = " << static_cast<int>(event.u.setup.wValue)
                    << ", wIndex = " << static_cast<int>(event.u.setup.wIndex)
                    << ", wLength = " << static_cast<int>(event.u.setup.wLength);

          if ((event.u.setup.bRequestType & USB_DIR_IN)) {
            LOG(INFO) << "acking device-to-host control transfer";
            ssize_t rc = adb_write(control_fd_.get(), "", 0);
            if (rc != 0) {
              PLOG(ERROR) << "failed to write empty packet to host";
              break;
            }
          } else {
            std::string buf;
            buf.resize(event.u.setup.wLength + 1);

            ssize_t rc = adb_read(control_fd_.get(), buf.data(), buf.size());
            if (rc != event.u.setup.wLength) {
              LOG(ERROR)
                  << "read " << rc
                  << " bytes when trying to read control request, expected "
                  << event.u.setup.wLength;
            }

            LOG(INFO) << "control request contents: " << buf;
            break;
          }
        }
      }
    }

    StopWorker();
    HandleError("monitor thread finished");
  });
}

void UsbFfsConnection::Stop() {
  if (stopped_.exchange(true)) {
    return;
  }
  stopped_ = true;

  io_context_->NotifyWorkerEventFd();
  //iou_context_->NotifyWorkerEventFd();

  uint64_t notify = 1;
  ssize_t rc = adb_write(monitor_event_fd_.get(), &notify, sizeof(notify));
  if (rc < 0) {
    PLOG(FATAL) << "failed to notify monitor eventfd to stop UsbFfsConnection";
  }

  CHECK_EQ(static_cast<size_t>(rc), sizeof(notify));
}


bool UsbFfsConnection::Write(std::unique_ptr<apacket> packet) {
    return io_context_->ProcessWriteRequest(std::move(packet));
    //return iou_context_->ProcessWriteRequest(std::move(packet));
}

UsbFfsConnection::~UsbFfsConnection() {
  LOG(INFO) << "UsbFfsConnection being destroyed";
  Stop();
  monitor_thread_.join();

  // We need to explicitly close our file descriptors before we notify our destruction,
  // because the thread listening on the future will immediately try to reopen the endpoint.
  io_context_.reset();
  //iou_context_.reset();
  control_fd_.reset();
  destruction_notifier_.set_value();
}

static void usb_ffs_open_thread() {
    adb_thread_setname("usb ffs open");

    // When the device is acting as a USB host, we'll be unable to bind to the USB gadget on kernels
    // that don't carry a downstream patch to enable that behavior.
    //
    // This property is copied from vendor.sys.usb.adb.disabled by an init.rc script.
    //
    // Note that this property only disables rebinding the USB gadget: setting it while an interface
    // is already bound will do nothing.
    static const char* kPropertyUsbDisabled = "sys.usb.adb.disabled";
    PropertyMonitor prop_mon;
    prop_mon.Add(kPropertyUsbDisabled, [](std::string value) {
        // Return false (i.e. break out of PropertyMonitor::Run) when the property != 1.
        return android::base::ParseBool(value) == android::base::ParseBoolResult::kTrue;
    });

    while (true) {
        unique_fd control;
        unique_fd bulk_out;
        unique_fd bulk_in;
        if (!open_functionfs(&control, &bulk_out, &bulk_in)) {
            std::this_thread::sleep_for(1s);
            continue;
        }

        if (android::base::GetBoolProperty(kPropertyUsbDisabled, false)) {
            LOG(INFO) << "pausing USB due to " << kPropertyUsbDisabled;
            prop_mon.Run();
            LOG(INFO) << "resuming USB";
        }

        atransport* transport = new atransport();
        transport->serial = "UsbFfs";
        std::promise<void> destruction_notifier;
        std::future<void> future = destruction_notifier.get_future();
        transport->SetConnection(std::make_unique<UsbFfsConnection>(
                std::move(control), std::move(bulk_out), std::move(bulk_in),
                std::move(destruction_notifier)));
        register_transport(transport);
        future.wait();
    }
}

void usb_init() {
    std::thread(usb_ffs_open_thread).detach();
}
