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

#include "restart_service.h"

#include <gtest/gtest.h>

#include <chrono>
#include <ctime>
#include <string>
#include <thread>

#include <android-base/properties.h>

#include "services.h"
#include "sysdeps.h"

class RestartServiceTest : public ::testing::Test {
  public:
    virtual void TearDown() override { command_fd_.reset(); }

    // Public access for the tests.
    unique_fd command_fd_;
};

// Test successful execution of tcp restart.
TEST_F(RestartServiceTest, RestartTcpServiceValidPortSuccess) {
    srand(time(NULL));
    const int port = 1000 + rand() % 999;
    auto exec_tcp_restart = [&port, this]() {
        this->command_fd_ = create_service_thread(
                "tcp", std::bind(restart_tcp_service, std::placeholders::_1, port));
        EXPECT_GE(this->command_fd_, 0);
    };

    std::thread t(exec_tcp_restart);

    // Wait for tcp restart execution to process.
    t.join();

    // Check for no timeout.
    char buf[8];
    sprintf(buf, "%d", port);
    EXPECT_EQ(android::base::WaitForProperty("service.adb.tcp.port", buf, std::chrono::seconds(2)),
              true);
}

// Test failure path of  tcp restart.
TEST_F(RestartServiceTest, RestartTcpServiceInvalidPortFailure) {
    const int port = -5;
    auto exec_tcp_restart = [&port, this]() {
        this->command_fd_ = create_service_thread(
                "tcp", std::bind(restart_tcp_service, std::placeholders::_1, port));
        EXPECT_GE(this->command_fd_, 0);
    };

    std::thread t(exec_tcp_restart);

    // Wait for tcp restart execution to process.
    t.join();

    // Check for timeout.
    char buf[8];
    sprintf(buf, "%d", port);
    EXPECT_EQ(android::base::WaitForProperty("service.adb.tcp.port", buf, std::chrono::seconds(2)),
              false);
}

// Test successful execution of usb restart.
TEST_F(RestartServiceTest, RestartUsbServiceSuccess) {
    srand(time(NULL));
    auto exec_usb_restart = []() {
        const unique_fd command_fd = create_service_thread("usb", restart_usb_service);
        EXPECT_GE(command_fd, 0);
    };

    std::thread t(exec_usb_restart);

    // Wait for usb restart to complete.
    t.join();

    char buf[8];
    const int port(0);
    sprintf(buf, "%d", port);
    EXPECT_EQ(android::base::WaitForProperty("service.adb.tcp.port", buf, std::chrono::seconds(2)),
              true);
}
