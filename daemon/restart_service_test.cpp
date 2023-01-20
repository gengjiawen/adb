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

#include "restart_service.h"

#include <time.h>
#include <string>

#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>

#include "services.h"
#include "sysdeps.h"
#include "test_utils.h"

using namespace test_utils;

class RestartServiceTest : public ::testing::Test {
  public:
    virtual void TearDown() override { command_fd_.reset(); }

    // Public access for the tests.
    unique_fd command_fd_;
};

// Test successful execution of tcp restart.
TEST_F(RestartServiceTest, RestartTcpServiceValidPortSuccess) {
    srand(time(nullptr));
    const int port = 1000 + rand() % 999;

    command_fd_ = create_service_thread(
            "tcp", std::bind(restart_tcp_service, std::placeholders::_1, port));
    EXPECT_GE(command_fd_.get(), 0);
    test_utils::ExpectLinesEqual(
            ReadRaw(command_fd_),
            {android::base::StringPrintf("restarting in TCP mode port: %d", port)});

    EXPECT_EQ(android::base::GetProperty("service.adb.tcp.port", ""), std::to_string(port));

    command_fd_.reset();
}

// Test failure path of  tcp restart.
TEST_F(RestartServiceTest, RestartTcpServiceInvalidPortFailure) {
    const int port = -5;
    command_fd_ = create_service_thread(
            "tcp", std::bind(restart_tcp_service, std::placeholders::_1, port));
    EXPECT_GE(command_fd_, 0);
    test_utils::ExpectLinesEqual(ReadRaw(command_fd_),
                                 {android::base::StringPrintf("invalid port %d", port)});
    EXPECT_NE(android::base::GetProperty("service.adb.tcp.port", ""), std::to_string(port));

    command_fd_.reset();
}

// Test successful execution of usb restart.
TEST_F(RestartServiceTest, RestartUsbServiceSuccess) {
    srand(time(nullptr));
    command_fd_ = create_service_thread("usb", restart_usb_service);
    EXPECT_GE(command_fd_, 0);

    test_utils::ExpectLinesEqual(ReadRaw(command_fd_),
                                 {android::base::StringPrintf("restarting in USB mode")});

    EXPECT_EQ(android::base::GetProperty("service.adb.tcp.port", ""), "0");
    command_fd_.reset();
}
