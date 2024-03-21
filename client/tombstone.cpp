/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include "file_sync_client.h"

#include "commandline.h"
#include "fastdeploycallbacks.h"
#include "tombstone.h"

#include <getopt.h>
#include <time.h>
#include <unistd.h>

using android::base::StringPrintf;

[[noreturn]] void usage(bool error) {
    fprintf(stderr, R"(usage: adb tombstone [OPTION]

Downloads tombstones from the device and symbolizes them.
Paths to symbolized tombstones are written to stdout.
Requires Android 15 or later, or a rooted device.

Arguments:
  -h, --help                   print this message
  --debug-file-directory PATH  specify the path to a symbols directory;
                               may be specified multiple times;
                               must contain a .build-id subdirectory conforming to
                               https://fedoraproject.org/wiki/RolandMcGrath/BuildID
                               (default: $ANDROID_PRODUCT_OUT/symbols if set)
  -o DIR                       write tombstones to specified directory
                               (default: current directory)
  -f                           monitor for new tombstones after downloading
                               existing tombstones instead of exiting;
                               may not be reliable before Android 15
  -n N                         download N most recent existing tombstones
                               (default: 0 if -f specified, otherwise 3)
)");
    exit(error);
}

void symbolize_tombstone(SyncConnection& sc, std::string output_dir,
                         const std::vector<std::string>& debug_file_directories, std::string name) {
    std::string device_pb = "/data/tombstones/" + name;

    struct stat st;
    if (!sc.Lstat(device_pb, &st)) {
        fprintf(stderr, "%s: remote lstat failed\n", device_pb.c_str());
        return;
    }

    // Unfortunately the adb protocol does not send us st_mtim.tv_nsec, so retrieve it via the
    // shell. This works at least as far back as Marshmallow, which was also before protobuf
    // tombstones were introduced. Fall back to 0 if it fails.
    std::vector<char> stat_out_vec;
    if (capture_shell_command(("stat -c %y " + device_pb).c_str(), &stat_out_vec, nullptr) == 0) {
        std::string stat_out(stat_out_vec.begin(), stat_out_vec.end());
        size_t dot = stat_out.find('.');
        if (dot != std::string::npos) {
            errno = 0;
            st.st_mtim.tv_nsec = strtoull(stat_out.c_str() + dot + 1, nullptr, 10);
            if (errno != 0) {
                st.st_mtim.tv_nsec = 0;
            }
        }
    }

    struct tm tm;
    if (!localtime_r(&st.st_mtime, &tm)) {
        fprintf(stderr, "%s: localtime_r: %s\n", device_pb.c_str(), strerror(errno));
        return;
    }
    std::string host_base =
            StringPrintf("%s" OS_PATH_SEPARATOR_STR "tombstone_%04d-%02d-%02d-%02d-%02d-%02d-%03ld",
                         output_dir.c_str(), tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                         tm.tm_hour, tm.tm_min, tm.tm_sec, st.st_mtim.tv_nsec / 1000000);
    std::string host_pb = host_base + ".pb";
    sc.Recv(device_pb.c_str(), host_pb.c_str(), nullptr, 0, CompressionType::Any);

    std::vector<const char *> args;
    args.push_back("pbtombstone");
    for (const std::string& dir : debug_file_directories) {
        args.push_back("--debug-file-directory");
        args.push_back(dir.c_str());
    }
    args.push_back(host_pb.c_str());

    std::string host_txt = host_base + ".txt";
    int host_txt_fd = unix_open(host_txt.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (host_txt_fd < 0) {
      fprintf(stderr, "%s: open: %s\n", host_txt.c_str(), strerror(errno));
      return;
    }
    int pid = fork();
    if (pid == 0) {
        dup2(host_txt_fd, STDOUT_FILENO);
        execvp("pbtombstone", const_cast<char *const *>(args.data()));

        fprintf(stderr, "%s: unable to start pbtombstone: %s\n", host_pb.c_str(), strerror(errno));
        _exit(1);
    }
    unix_close(host_txt_fd);

    int wstatus;
    if (waitpid(pid, &wstatus, 0) < 0 || !WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        fprintf(stderr, "%s: pbtombstone failed\n", host_pb.c_str());
    }

    printf("%s\n", host_txt.c_str());
}

struct TombstoneLogcatStandardStreamsCallback : StandardStreamsCallbackInterface {
    TombstoneLogcatStandardStreamsCallback(std::function<void(std::string)> symbolize)
        : symbolize_(symbolize) {}

    bool OnStdout(const char* buffer, size_t length) {
        for (size_t i = 0; i < length; i++) {
            char c = buffer[i];
            if (c == '\n') {
                ProcessLine(line_);
                line_.clear();
            } else {
                line_.append(1, c);
            }
        }
        return true;
    }

    bool OnStderr(const char* buffer, size_t length) {
        return OnStream(nullptr, stderr, buffer, length, false);
    }

    void ProcessLine(const std::string& line) {
        const char *prefix = "Tombstone written to: ";
        size_t pos = line.find(prefix);
        if (pos != std::string::npos) {
            symbolize_(line.substr(pos + strlen(prefix)) + ".pb");
        }
    }

    int Done(int status) {
        return status;
    }

    std::string line_;
    std::function<void(std::string)> symbolize_;
};

int adb_tombstone(int argc, const char** argv) {
    std::vector<std::string> debug_file_directories;
    std::string output_dir;
    bool follow = false;
    int num_existing_tombstones = -1;

    static struct option long_options[] = {
            {"debug-file-directory", required_argument, 0, 0},
            {"help", no_argument, 0, 'h'},
            {},
    };
    int c;
    while ((c = getopt_long(argc, const_cast<char**>(argv), "fhn:o:", long_options, 0)) != -1) {
        switch (c) {
            case 0:
                debug_file_directories.push_back(optarg);
                break;

            case 'f':
                follow = true;
                break;

            case 'n':
                num_existing_tombstones = atoi(optarg);
                break;

            case 'o':
                output_dir = optarg;
                break;

            case 'h':
                usage(false);
                break;

            case '?':
                usage(true);
                break;
        }
    }

    if (optind != argc) {
        usage(true);
    }

    if (num_existing_tombstones == -1) {
        num_existing_tombstones = follow ? 0 : 3;
    }

    if (output_dir.empty()) {
        char cwd[4096];
        if (!getcwd(cwd, 4096)) {
            fprintf(stderr, "getcwd: %s\n", strerror(errno));
            return 1;
        }
        output_dir = cwd;
    }

    if (const char *out = getenv("ANDROID_PRODUCT_OUT")) {
        debug_file_directories.push_back(StringPrintf("%s" OS_PATH_SEPARATOR_STR "symbols", out));
    }

    SyncConnection sc(std::make_unique<ProgressCallbacks>());
    if (!sc.IsValid()) return 1;

    if (num_existing_tombstones) {
        struct pbtombstone {
            std::string name;
            uint64_t mtime;
        };
        std::vector<pbtombstone> pbtombstones;
        sc.Ls("/data/tombstones",
              [&](unsigned mode, uint64_t size, uint64_t mtime, const char* name) {
                  std::string name_s = name;
                  if (!name_s.ends_with(".pb")) return;
                  pbtombstones.push_back({name_s, mtime});
              });
        std::sort(pbtombstones.begin(), pbtombstones.end(),
                  [](const pbtombstone& a, const pbtombstone& b) { return a.mtime < b.mtime; });
        size_t i = 0;
        if (pbtombstones.size() > static_cast<size_t>(num_existing_tombstones)) {
            i = pbtombstones.size() - num_existing_tombstones;
        }
        for (; i != pbtombstones.size(); ++i) {
            symbolize_tombstone(sc, output_dir, debug_file_directories, pbtombstones[i].name);
        }
        if (pbtombstones.empty() && !follow) {
            fprintf(stderr, "no tombstones found, or tombstones inaccessible\n");
        }
    }

    // There's a race here between reading the file list and starting logcat that could cause us to
    // miss tombstones. It could be fixed by starting logcat first and only reading the file list
    // once logcat has opened the log, but there doesn't seem to be a way to make logcat notify us
    // when it opens the log.
    if (follow) {
        TombstoneLogcatStandardStreamsCallback callback([&](std::string name) {
            symbolize_tombstone(sc, output_dir, debug_file_directories, name);
        });
        return send_shell_command("logcat -T1 -s tombstoned -b main", false, &callback);
    }

    return 0;
}
