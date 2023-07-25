/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <android-base/logging.h>

/*
 * Logging facility for adbd. The severity filter is refreshed during runtime so there is not need
 * to restart adbd to change the log level. Severity is set via debug.adbd.logging property.
 */
namespace adb {
enum class LogType {
    Connection,
    Service,
    Shell,
    COUNT,
};

bool is_adbd_logging_enabled(LogType type);

#define ADBD_LOG(type) ::adb::is_adbd_logging_enabled(::adb::LogType::type) && LOG(INFO)

}  // namespace adb
