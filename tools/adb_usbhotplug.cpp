// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <assert.h>
#include <libusb/libusb.h>
#include <stdio.h>
#include <stdlib.h>

int runs = 0;
libusb_device_handle* dev_handle = nullptr;

// Callback when USB devices come online.
static int LIBUSB_CALL hotplug_attach(struct libusb_context* ctx, struct libusb_device* dev,
                                      libusb_hotplug_event event, void* user_data) {
    assert(event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED);

    struct libusb_device_descriptor desc;
    int rc = libusb_get_device_descriptor(dev, &desc);

    if (rc != LIBUSB_SUCCESS) {
        fprintf(stderr, "Error getting device descriptor\n");
    } else {
        printf("Device attached: %04x:%04x\n", desc.idVendor, desc.idProduct);
    }

    rc = libusb_open(dev, &dev_handle);
    if (rc != LIBUSB_SUCCESS) {
        printf("Failure opening: libusb_open() error: %d", rc);
        return LIBUSB_ERROR_OTHER;
    }

    ++runs;

    return LIBUSB_SUCCESS;
}

// Callback when USB devices go offline.
static int LIBUSB_CALL hotplug_detach(libusb_context* ctx, libusb_device* dev,
                                      libusb_hotplug_event event, void* user_data) {
    assert(event == LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT);

    struct libusb_device_descriptor desc;
    int rc = libusb_get_device_descriptor(dev, &desc);
    if (rc != LIBUSB_SUCCESS) {
        fprintf(stderr, "Error getting device descriptor\n");
        return LIBUSB_ERROR_OTHER;
    }

    printf("Device detached: %04x:%04x\n", desc.idVendor, desc.idProduct);

    if (dev_handle) {
        libusb_close(dev_handle);
        dev_handle = nullptr;
    }

    ++runs;

    return LIBUSB_SUCCESS;
}

int main(int argc, char* argv[]) {
    // 0451:d010 TI (Samsung)
    // 18d1:4ee7 google
    const int vendor_id =
            (argc > 1) ? static_cast<int>(strtol(argv[1], nullptr, 0)) : LIBUSB_HOTPLUG_MATCH_ANY;
    const int product_id =
            (argc > 2) ? static_cast<int>(strtol(argv[2], nullptr, 0)) : LIBUSB_HOTPLUG_MATCH_ANY;
    int class_id =
            (argc > 3) ? static_cast<int>(strtol(argv[3], NULL, 0)) : LIBUSB_HOTPLUG_MATCH_ANY;

    struct libusb_context* context;
    int rc = libusb_init(&context);
    if (rc != LIBUSB_SUCCESS) {
        printf("Failed to initialize libusb: %s\n", libusb_error_name(rc));
        return EXIT_FAILURE;
    }

    if (!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) {
        printf("HOTPLUG capabilities are not supported on this platform\n");
        libusb_exit(context);
    }

    libusb_hotplug_callback_handle handle[2];
    rc = libusb_hotplug_register_callback(context, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED,
                                          0,  // flags
                                          vendor_id, product_id, class_id, hotplug_attach,
                                          nullptr,  // user-data
                                          &handle[0]);
    if (rc != LIBUSB_SUCCESS) {
        fprintf(stderr, "Error registering attach callback!\n");
        libusb_exit(context);
        return EXIT_FAILURE;
    }

    rc = libusb_hotplug_register_callback(context, LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
                                          0,  // flags
                                          vendor_id, product_id, class_id, hotplug_detach,
                                          nullptr,  // user-data
                                          &handle[1]);

    if (rc != LIBUSB_SUCCESS) {
        fprintf(stderr, "Error registering detach callback!\n");
        libusb_exit(context);
        return EXIT_FAILURE;
    }

    assert(handle[0] && handle[1]);

    while (runs < 5) {
        rc = libusb_handle_events(nullptr);
        if (rc != LIBUSB_SUCCESS) {
            printf("libusb_handle_events() failed: %s\n", libusb_error_name(rc));
        }
    }

    if (handle[0]) {
        libusb_hotplug_deregister_callback(context, handle[0]);
    }
    if (handle[1]) {
        libusb_hotplug_deregister_callback(context, handle[1]);
    }
    if (dev_handle) {
        libusb_close(dev_handle);
    }

    libusb_exit(context);

    return EXIT_SUCCESS;
}
