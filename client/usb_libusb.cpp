/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "libusb_utils.h"
#include "sysdeps.h"

#include "client/usb.h"

#include <stdint.h>
#include <stdlib.h>

#if defined(__linux__)
#include <sys/inotify.h>
#include <unistd.h>
#endif

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <libusb/libusb.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/thread_annotations.h>

using namespace std::chrono_literals;

using android::base::ScopedLockAssertion;
using android::base::StringPrintf;

using unique_device = std::unique_ptr<libusb_device, DeviceDeleter>;

static libusb_hotplug_callback_handle hotplug_handle;

struct LibusbConnection;

static auto& hotplug_queue = *new BlockingQueue<std::pair<libusb_hotplug_event, libusb_device*>>();

LIBUSB_CALL int hotplug_callback(libusb_context*, libusb_device* device, libusb_hotplug_event event,
                                 void*);
namespace libusb {
int usb_init() {
    VLOG(USB) << "initializing libusb...";
    int rc = libusb_init(nullptr);  // We're not passing in the context because
                                    // we don't care about that resource (given
                                    // the situation wherein the driver is
                                    // unloaded only when the process exits (as
                                    // a result of `kill-server`).

    if (rc != 0) {
        LOG(WARNING) << "failed to initialize libusb: " << libusb_error_name(rc);
        return rc;
    }

    // Register the hotplug callback.
    rc = libusb_hotplug_register_callback(
            nullptr,
            static_cast<libusb_hotplug_event>(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
                                              LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT),
            LIBUSB_HOTPLUG_ENUMERATE, LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY,
            LIBUSB_CLASS_PER_INTERFACE, hotplug_callback, nullptr, &hotplug_handle);

    if (rc != LIBUSB_SUCCESS) {
        LOG(WARNING) << "failed to register libusb hotplug callback";
        return rc;
    }

    // Spawn a thread for libusb_handle_events.
    std::thread([]() {
        adb_thread_setname("libusb");
        while (true) {
            libusb_handle_events(nullptr);
        }
    }).detach();
    return LIBUSB_SUCCESS;
}

}  // namespace libusb
