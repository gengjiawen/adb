/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <string>
#include <vector>

#include "file_sync_protocol.h"
#include "transport.h"

typedef void(sync_ls_cb)(unsigned mode, uint64_t size, uint64_t time, const char* name);

struct copyinfo;

enum class TransferDirection {
    push,
    pull,
};

struct ProgressCallbacks {
    virtual ~ProgressCallbacks() = default;

    virtual void Printf(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3))) {}
    virtual void Println(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3))) {}

    virtual void Error(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3)));
    virtual void Warning(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3)));

    virtual void ComputeExpectedTotalBytes(const std::vector<copyinfo>& file_list) {}
    virtual void SetExpectedTotalBytes(uint64_t expected_total_bytes) {}

    virtual void NewTransfer() {}
    virtual void RecordBytesTransferred(size_t bytes) {}
    virtual void RecordFilesTransferred(size_t files) {}
    virtual void RecordFilesSkipped(size_t files) {}
    virtual void ReportProgress(const std::string& file, uint64_t file_copied_bytes,
                                uint64_t file_total_bytes) {}
    virtual void ReportTransferRate(const std::string& file, TransferDirection direction) {}
    virtual void ReportOverallTransferRate(TransferDirection direction) {}
};

class SyncConnection {
  public:
    SyncConnection(std::unique_ptr<ProgressCallbacks> pc);
    ~SyncConnection();

    bool HaveSendRecv2() const { return have_sendrecv_v2_; }
    bool HaveSendRecv2Brotli() const { return have_sendrecv_v2_brotli_; }
    bool HaveSendRecv2LZ4() const { return have_sendrecv_v2_lz4_; }
    bool HaveSendRecv2Zstd() const { return have_sendrecv_v2_zstd_; }
    bool HaveSendRecv2DryRunSend() const { return have_sendrecv_v2_dry_run_send_; }

    // Resolve a compression type which might be CompressionType::Any to a specific compression
    // algorithm.
    CompressionType ResolveCompressionType(CompressionType compression) const;

    const FeatureSet& Features() const { return *features_; }

    bool IsValid() { return fd >= 0; }

    void RecordFileSent(std::string from, std::string to);
    bool SendRequest(int id, const std::string& path);
    bool SendSend2(std::string_view path, mode_t mode, CompressionType compression, bool dry_run);
    bool SendRecv2(const std::string& path, CompressionType compression);
    bool SendStat(const std::string& path);
    bool SendLstat(const std::string& path);
    bool FinishStat(struct stat* st);
    bool Ls(const std::string& path, const std::function<sync_ls_cb>& callback);
    bool SendSmallFile(const std::string& path, mode_t mode, const std::string& lpath,
                       const std::string& rpath, unsigned mtime, const char* data,
                       size_t data_length, bool dry_run);
    bool SendLargeFile(const std::string& path, mode_t mode, const std::string& lpath,
                       const std::string& rpath, unsigned mtime, CompressionType compression,
                       bool dry_run);
    bool SendLargeFileLegacy(const std::string& path, mode_t mode, const std::string& lpath,
                             const std::string& rpath, unsigned mtime);
    bool ReportCopyFailure(const std::string& from, const std::string& to, const syncmsg& msg);
    void CopyDone() { deferred_acknowledgements_.pop_front(); }
    void ReportDeferredCopyFailure(const std::string& msg);
    bool ReadAcknowledgements(bool read_all = false);

    bool Recv(const char* rpath, const char* lpath, const char* name,
              uint64_t expected_size, CompressionType compression);

    // TODO: add a char[max] buffer here, to replace syncsendbuf...
    unique_fd fd;
    size_t max;

    std::unique_ptr<ProgressCallbacks> pc_;

  private:
    std::deque<std::pair<std::string, std::string>> deferred_acknowledgements_;
    Block acknowledgement_buffer_;
    const FeatureSet* features_ = nullptr;
    bool have_stat_v2_;
    bool have_ls_v2_;
    bool have_sendrecv_v2_;
    bool have_sendrecv_v2_brotli_;
    bool have_sendrecv_v2_lz4_;
    bool have_sendrecv_v2_zstd_;
    bool have_sendrecv_v2_dry_run_send_;

    bool SendQuit();
    bool WriteOrDie(const std::string& from, const std::string& to, const void* data,
                    size_t data_length);

    bool RecvV1(const char* rpath, const char* lpath, const char* name, uint64_t expected_size);
    bool RecvV2(const char* rpath, const char* lpath, const char* name, uint64_t expected_size,
                CompressionType compression);

    bool SendLs(const std::string& path);
    bool FinishLs(const std::function<sync_ls_cb>& callback);
};

bool do_sync_ls(const char* path);
bool do_sync_push(const std::vector<const char*>& srcs, const char* dst, bool sync,
                  CompressionType compression, bool dry_run);
bool do_sync_pull(const std::vector<const char*>& srcs, const char* dst, bool copy_attrs,
                  CompressionType compression, const char* name = nullptr);

bool do_sync_sync(const std::string& lpath, const std::string& rpath, bool list_only,
                  CompressionType compression, bool dry_run);
