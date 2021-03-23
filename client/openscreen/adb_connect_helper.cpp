/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "client/openscreen/adb_connect_helper.h"

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include "client/openscreen/platform/task_runner.h"
#include "transport.h"

namespace mdns {

namespace {

AdbOspTaskRunner* sAutoConnectTaskRunner = nullptr;

}  // namespace

void PostAdbConnectionRequest(const std::string& service_name, const std::string& reg_type) {
    static std::once_flag once;
    std::call_once(once, [&]() { sAutoConnectTaskRunner = new AdbOspTaskRunner(false); });

    sAutoConnectTaskRunner->PostTask([service_name, reg_type] {
        std::string mdns_instance =
                android::base::StringPrintf("%s.%s", service_name.c_str(), reg_type.c_str());
        std::string response;
        connect_device(mdns_instance, &response);
        LOG(VERBOSE) << "Attempted connection to " << mdns_instance << " err=[" << response << "]";
    });
}

}  // namespace mdns
