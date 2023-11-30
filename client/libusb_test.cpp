/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <gtest/gtest.h>

#include "client/libusb_utils.h"

namespace libusb {

// Example callback when USB devices come online.
int LIBUSB_CALL hotplug_bind(struct libusb_context* /*unused*/, struct libusb_device* /*unused*/,
                             libusb_hotplug_event event, void* /* unused*/) {
    EXPECT_EQ(event, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED);
    return LIBUSB_SUCCESS;
}

// Initialization succeeds on all three platforms.
TEST(libusb_utils, test_init_succeeds) {
    struct libusb_context* context;
    const int rc = libusb_init(&context);
    EXPECT_EQ(rc, LIBUSB_SUCCESS);

    libusb_exit(context);
}

// Baseline for hotplug support.
TEST(libusb_utils, test_hotplug) {
    struct libusb_context* context;
    int rc = libusb_init(&context);
#ifdef _WIN32
    LOG(WARNING) << libusb_error_name(rc);
    EXPECT_EQ(rc, LIBUSB_SUCCESS);  // Windows incorrectly reports success.

    rc = libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG);
    EXPECT_EQ(rc, LIBUSB_SUCCESS);  // In reality, Windows does not support hotplug (TBD).
#elif __linux__
    EXPECT_EQ(rc, LIBUSB_SUCCESS);
#elif __APPLE__
    EXPECT_EQ(rc, LIBUSB_SUCCESS);
#else
    EXPECT_TRUE(0);  // We do not support any other platforms.
#endif

    libusb_exit(context);
}

// Test libusb registration.
TEST(libusb_utils, test_bind_registration) {
    struct libusb_context* context;
    int rc = libusb_init(&context);
#ifndef _WIN32
    EXPECT_EQ(rc, LIBUSB_SUCCESS);
#else
    LOG(WARNING) << libusb_error_name(rc);
#endif

    libusb_hotplug_callback_handle hbind;
    rc = libusb_hotplug_register_callback(
            context, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED,
            0,                         // flags
            LIBUSB_HOTPLUG_MATCH_ANY,  // e.g: vendor_id:product_id  are:
            // 0451:d010 TI (Samsung)
            // 18d1:4ee7 google
            LIBUSB_HOTPLUG_MATCH_ANY,  // product_id
            LIBUSB_HOTPLUG_MATCH_ANY,  // class_id
            hotplug_bind,
            nullptr,  // user-data
            &hbind);

#ifdef _WIN32
    LOG(WARNING) << libusb_error_name(rc) << " " << hbind;
    EXPECT_NE(rc, LIBUSB_SUCCESS);
#else
    EXPECT_EQ(rc, LIBUSB_SUCCESS);
    libusb_hotplug_deregister_callback(context, hbind);
#endif

    libusb_exit(context);
}

// Test the libusbutils interface.
TEST(libusb_utils, test_libusbutils) {
    const int result = usb_init();
#if __linux__
    EXPECT_TRUE(result == 0);
#elif __WIN32
    EXPECT_TRUE(result != 0);  // hotplug is unsupported on Windows platforms
#elif __APPLE__
    EXPECT_TRUE(result == 0);
#else
    EXPECT_TRUE(0);  // We do not support any other platforms.
#endif
}
}  // namespace libusb
