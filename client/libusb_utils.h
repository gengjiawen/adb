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

#include "sysdeps.h"

#include "client/usb.h"

#include <stdint.h>
#include <stdlib.h>

#if defined(__linux__)
#include <sys/inotify.h>
#include <unistd.h>
#endif

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <libusb/libusb.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "adb_utils.h"
#include "transfer_id.h"

using android::base::StringPrintf;

#define LOG_ERR(out, fmt, ...)                                               \
    do {                                                                     \
        std::string __err = android::base::StringPrintf(fmt, ##__VA_ARGS__); \
        LOG(ERROR) << __err;                                                 \
        *out = std::move(__err);                                             \
    } while (0)

// RAII wrappers for libusb.
struct ConfigDescriptorDeleter {
    void operator()(libusb_config_descriptor* desc) { libusb_free_config_descriptor(desc); }
};

using unique_config_descriptor = std::unique_ptr<libusb_config_descriptor, ConfigDescriptorDeleter>;

struct DeviceDeleter {
    void operator()(libusb_device* d) { libusb_unref_device(d); }
};

using unique_device = std::unique_ptr<libusb_device, DeviceDeleter>;

struct DeviceHandleDeleter {
    void operator()(libusb_device_handle* h) { libusb_close(h); }
};

using unique_device_handle = std::unique_ptr<libusb_device_handle, DeviceHandleDeleter>;

static std::string get_device_address(libusb_device* device) {
    uint8_t ports[7];
    int port_count = libusb_get_port_numbers(device, ports, 7);
    if (port_count < 0) return "";

    std::string address = StringPrintf("%d-%d", libusb_get_bus_number(device), ports[0]);
    for (int port = 1; port < port_count; ++port) {
        address += StringPrintf(".%d", ports[port]);
    }

    return address;
}

static std::string get_device_address(libusb_device* device);
#if defined(__linux__)
static std::string get_device_serial_path(libusb_device* device) {
    std::string address = get_device_address(device);
    std::string path = StringPrintf("/sys/bus/usb/devices/%s/serial", address.c_str());
    return path;
}
#endif

struct LibusbConnection : public Connection {
    struct ReadBlock {
        LibusbConnection* self = nullptr;
        libusb_transfer* transfer = nullptr;
        Block block;
        bool active = false;
    };

    struct WriteBlock {
        LibusbConnection* self;
        libusb_transfer* transfer;
        Block block;
        TransferId id;
    };

    explicit inline LibusbConnection(unique_device device)
        : device_(std::move(device)), device_address_(get_device_address(device_.get())) {}

    ~LibusbConnection() { Stop(); }

    void HandlePacket(amessage& msg, std::optional<Block> payload);

    void Cleanup(ReadBlock* read_block) REQUIRES(read_mutex_);

    bool MaybeCleanup(ReadBlock* read_block) REQUIRES(read_mutex_);

    static void LIBUSB_CALL header_read_cb(libusb_transfer* transfer);

    static void LIBUSB_CALL payload_read_cb(libusb_transfer* transfer);

    static void LIBUSB_CALL write_cb(libusb_transfer* transfer);

    bool DoTlsHandshake(RSA*, std::string*) final;

    void CreateRead(ReadBlock* read, bool header);

    void SubmitRead(ReadBlock* read, size_t length);

    void SubmitWrite(Block&& block) REQUIRES(write_mutex_);

    bool Write(std::unique_ptr<apacket> packet) final;

    std::optional<libusb_device_descriptor> GetDeviceDescriptor();

    bool FindInterface(libusb_device_descriptor* device_desc);

    std::string GetUsbDeviceAddress() const;

    std::string GetSerial();

    bool OpenDevice(std::string* error);

    void CancelReadTransfer(ReadBlock* read_block) REQUIRES(read_mutex_);

    void CloseDevice();

    bool StartImpl(std::string* error);

    void OnError(const std::string& error);

    virtual bool Attach(std::string* error) override final;

    virtual bool Detach(std::string* error) override final;

    virtual void Reset() override final;

    virtual void Start() override final;

    virtual void Stop() override final;

    static std::optional<std::shared_ptr<LibusbConnection>> Create(unique_device device) {
        auto connection = std::make_unique<LibusbConnection>(std::move(device));
        if (!connection) {
            LOG(FATAL) << "failed to construct LibusbConnection";
        }

        auto device_desc = connection->GetDeviceDescriptor();
        if (!device_desc) {
            VLOG(USB) << "ignoring device " << connection->GetUsbDeviceAddress()
                      << ": not an adb interface. (GetDeviceDescriptor)";
            return {};
        }

        if (!connection->FindInterface(&device_desc.value())) {
            VLOG(USB) << "ignoring device " << connection->GetUsbDeviceAddress()
                      << ": not an adb interface. (FindInterface)";
            return {};
        }

#if defined(__linux__)
        std::string device_serial;
        if (android::base::ReadFileToString(get_device_serial_path(connection->device_.get()),
                                            &device_serial)) {
            connection->serial_ = android::base::Trim(device_serial);
        } else {
            // We don't actually want to treat an unknown serial as an error because
            // devices aren't able to communicate a serial number in early bringup.
            // http://b/20883914
            connection->serial("<unknown>");
        }
#else
        // We need to open the device to get its serial on Windows and OS X.
        std::string error;
        if (!connection->OpenDevice(&error)) {
            VLOG(USB) << "ignoring device " << connection->GetUsbDeviceAddress()
                      << ": not an adb interface. (OpenDevice)";
            return {};
        }
        connection->serial(connection->GetSerial());
        connection->CloseDevice();
#endif
        if (!transport_server_owns_device(connection->GetUsbDeviceAddress(),
                                          connection->serial())) {
            VLOG(USB) << "ignoring device " << connection->GetUsbDeviceAddress() << " serial "
                      << connection->serial() << ": this server owns '"
                      << transport_get_one_device() << "'";
            return {};
        }

        return connection;
    }

    inline std::string serial() const { return serial_; }
    inline void serial(const std::string& s) { serial_ = s; }

  private:
    unique_device device_;
    unique_device_handle device_handle_;
    std::string device_address_;
    std::string serial_ = "<unknown>";

    uint32_t interface_num_;
    uint8_t write_endpoint_;
    uint8_t read_endpoint_;

    std::mutex read_mutex_;
    ReadBlock header_read_ GUARDED_BY(read_mutex_);
    ReadBlock payload_read_ GUARDED_BY(read_mutex_);
    std::optional<amessage> incoming_header_ GUARDED_BY(read_mutex_);
    IOVector incoming_payload_ GUARDED_BY(read_mutex_);

    std::mutex write_mutex_;
    std::unordered_map<TransferId, std::unique_ptr<WriteBlock>> writes_ GUARDED_BY(write_mutex_);
    std::atomic<size_t> next_write_id_ = 0;

    std::once_flag error_flag_;
    std::atomic<bool> terminated_ = false;
    std::atomic<bool> detached_ = false;
    std::condition_variable destruction_cv_;

    size_t zero_mask_ = 0;
};

static std::atomic<int> connecting_devices(0);

void hotplug_thread();

namespace libusb {
int usb_init();
}  // namespace libusb
