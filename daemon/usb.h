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

#include "daemon/usb_io.h"

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

    void HandleError(const std::string& error);
    const char* to_string(enum usb_functionfs_event_type type);

    std::thread monitor_thread_;

    bool worker_started_;
    std::thread worker_thread_;

    std::atomic<bool> stopped_;
    std::promise<void> destruction_notifier_;
    std::once_flag error_flag_;

    unique_fd monitor_event_fd_;

    std::unique_ptr<IUsbIoContext> io_context_;
    unique_fd control_fd_;
    unique_fd read_fd_;
    unique_fd write_fd_;

    static constexpr int kInterruptionSignal = SIGUSR1;
};
