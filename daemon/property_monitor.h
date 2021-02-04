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

#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

using PropertyMonitorCallback = bool(std::string value);

#if !defined(__ANDROID__)
struct prop_info;
#endif

struct PropertyMonitorData {
    std::function<PropertyMonitorCallback> callback;
    const prop_info* prop_info;
    uint32_t serial;
    bool called;
};

// This class is thread-unsafe: all operations must be guarded by mutexes if they can occur on
// different threads.
struct PropertyMonitor {
    PropertyMonitor() = default;
    ~PropertyMonitor() = default;

    // Register a callback on a specified property.
    // Multiple callbacks can be registered on the same property.
    void Add(std::string property, std::function<PropertyMonitorCallback> callback);

    // Run the PropertyMonitor indefinitely.
    //
    // This will run until a callback returns false. If a callback returns false, this does not
    // return immediately: it will run the other callbacks for changed properties first.
    void Run();

    // Run the PropertyMonitor once.
    //
    // This performs one cycle of checking for property changes.
    // If a callback returns false, it will return false after finishing with the other properties.
    // Otherwise, returns true.
    bool RunOnce();

  private:
    std::vector<std::pair<std::string, PropertyMonitorData>> properties_;
    uint32_t last_serial_ = 0;
};
