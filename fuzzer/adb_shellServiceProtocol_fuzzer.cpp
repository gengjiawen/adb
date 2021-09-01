/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <fuzzer/FuzzedDataProvider.h>
#include "shell_protocol.h"
#include "sysdeps.h"

constexpr ShellProtocol::Id kShellProtocolId[] = {
        ShellProtocol::kIdStdin,  ShellProtocol::kIdStdout,     ShellProtocol::kIdStderr,
        ShellProtocol::kIdExit,   ShellProtocol::kIdCloseStdin, ShellProtocol::kIdWindowSizeChange,
        ShellProtocol::kIdInvalid};
constexpr size_t kMaxVectorSize = 100;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    int32_t fds[2] = {};
    adb_socketpair(fds);
    int32_t readFd = fds[0];
    int32_t writeFd = fds[1];

    std::unique_ptr<ShellProtocol> writeProtocol = std::make_unique<ShellProtocol>(writeFd);
    std::unique_ptr<ShellProtocol> readProtocol = std::make_unique<ShellProtocol>(readFd);
    if (!writeProtocol && !readProtocol) {
        return 0;
    }

    FuzzedDataProvider dataProvider(data, size);
    ShellProtocol::Id id = dataProvider.PickValueInArray(kShellProtocolId);
    std::vector<uint8_t> dataVector = dataProvider.ConsumeBytes<uint8_t>(kMaxVectorSize);

    memcpy(writeProtocol->data(), dataVector.data(), dataVector.size());
    writeProtocol->Write(id, dataVector.size());
    readProtocol->Read();
    readProtocol->id();
    readProtocol->data_length();

    adb_close(readFd);
    adb_close(writeFd);
    return 0;
}
