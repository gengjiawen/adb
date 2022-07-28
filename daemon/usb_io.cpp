#include "daemon/usb_io.h"

struct ScopedAioContext {
    ScopedAioContext() = default;
    ~ScopedAioContext() { reset(); }

    ScopedAioContext(ScopedAioContext&& move) { reset(move.release()); }
    ScopedAioContext(const ScopedAioContext& copy) = delete;

    ScopedAioContext& operator=(ScopedAioContext&& move) {
        reset(move.release());
        return *this;
    }
    ScopedAioContext& operator=(const ScopedAioContext& copy) = delete;

    static ScopedAioContext Create(size_t max_events) {
        aio_context_t ctx = 0;
        if (io_setup(max_events, &ctx) != 0) {
            PLOG(FATAL) << "failed to create aio_context_t";
        }
        ScopedAioContext result;
        result.reset(ctx);
        return result;
    }

    aio_context_t release() {
        aio_context_t result = context_;
        context_ = 0;
        return result;
    }

    void reset(aio_context_t new_context = 0) {
        if (context_ != 0) {
            io_destroy(context_);
        }

        context_ = new_context;
    }

    aio_context_t get() { return context_; }

  private:
    aio_context_t context_ = 0;
};

class UsbIoContext : public IUsbIoContext {
    public:
      UsbIoContext();
      virtual bool SubmitReadRequests() = 0;
      virtual bool ProcessEvents(atransport* transport) = 0;
      virtual bool SubmitWrites() = 0;
      void NotifyWorkerEventFd() override;
      bool WaitForIORequest() override;
      bool ProcessWriteRequest(std::unique_ptr<apacket> packet) override;

    protected:
      virtual IoReadBlock CreateReadBlock(uint64_t id) = 0;
      virtual IoWriteBlock CreateWriteBlock(std::shared_ptr<Block> payload, size_t offset, size_t len,
                                          uint64_t id) = 0;
      virtual void PrepareReadBlock(IoReadBlock* block, uint64_t id) = 0;
      virtual bool SubmitIO(int num_blocks, IoReadBlock* block) = 0;

      virtual bool HandleRead(TransferId id, int64_t size, atransport* transport) = 0;

      bool ProcessRead(IoReadBlock* block, atransport* transport);
      void HandleWrite(TransferId id);

      // ID of the next request that we're going to send out.
      size_t next_read_id_ = 0;

      // ID of the next packet we're waiting for.
      size_t needed_read_id_ = 0;

      std::optional<amessage> incoming_header_;
      IOVector incoming_payload_;

      std::mutex write_mutex_;
      std::deque<IoWriteBlock> write_requests_ GUARDED_BY(write_mutex_);
      size_t next_write_id_ GUARDED_BY(write_mutex_) = 0;
      size_t writes_submitted_ GUARDED_BY(write_mutex_) = 0;

      unique_fd worker_event_fd_;

      bool connection_started_ = false;

      unique_fd read_fd_;
      unique_fd write_fd_;
      std::array<IoReadBlock, kUsbReadQueueDepth> read_requests_;
};

UsbIoContext::UsbIoContext() {
    worker_event_fd_.reset(eventfd(0, EFD_CLOEXEC));
    if (worker_event_fd_ == -1) {
        PLOG(FATAL) << "failed to create eventfd";
    }

    LOG(INFO) << "UsbIoContext Constructor - worker_event_fd initialized: "
              << worker_event_fd_.get();
}

bool UsbIoContext::WaitForIORequest() {
      uint64_t dummy;
      ssize_t rc = adb_read(worker_event_fd_.get(), &dummy, sizeof(dummy));
      if (rc == -1) {
        PLOG(ERROR) << "failed to read from eventfd";
        return false;
      } else if (rc == 0) {
        LOG(ERROR) << "hit EOF on eventfd";
        return false;
      }
      return true;
}

void UsbIoContext::NotifyWorkerEventFd() {
  uint64_t notify = 1;
  ssize_t rc = adb_write(worker_event_fd_.get(), &notify, sizeof(notify));
  if (rc < 0) {
    PLOG(FATAL) << "failed to notify worker eventfd to stop UsbFfsConnection";
  }
  CHECK_EQ(static_cast<size_t>(rc), sizeof(notify));
}

bool UsbIoContext::ProcessWriteRequest(std::unique_ptr<apacket> packet) {
  LOG(DEBUG) << "USB write: " << dump_header(&packet->msg);
  auto header = std::make_shared<Block>(sizeof(packet->msg));
  memcpy(header->data(), &packet->msg, sizeof(packet->msg));

  std::lock_guard<std::mutex> lock(write_mutex_);
  write_requests_.push_back(
      CreateWriteBlock(std::move(header), 0, sizeof(packet->msg), next_write_id_++));
  if (!packet->payload.empty()) {
    // The kernel attempts to allocate a contiguous block of memory for each write,
    // which can fail if the write is large and the kernel heap is fragmented.
    // Split large writes into smaller chunks to avoid this.
    auto payload = std::make_shared<Block>(std::move(packet->payload));
    size_t offset = 0;
    size_t len = payload->size();

    while (len > 0) {
      size_t write_size = std::min(kUsbWriteSize, len);
      write_requests_.push_back(
          CreateWriteBlock(payload, offset, write_size, next_write_id_++));
      len -= write_size;
      offset += write_size;
    }
  }

  // Wake up the worker thread to submit writes.
  uint64_t notify = 1;
  ssize_t rc = adb_write(worker_event_fd_.get(), &notify, sizeof(notify));
  if (rc < 0) {
    PLOG(FATAL) << "failed to notify worker eventfd to submit writes";
  }

  return true;
}

bool UsbIoContext::ProcessRead(IoReadBlock* block, atransport* transport) {
  if (!block->payload.empty()) {
    if (!incoming_header_.has_value()) {
      if (block->payload.size() != sizeof(amessage)) {
        LOG(ERROR) << "received packet of unexpected length while reading header";
        return false;
      }
      amessage& msg = incoming_header_.emplace();
      memcpy(&msg, block->payload.data(), sizeof(msg));
      LOG(DEBUG) << "USB read:" << dump_header(&msg);
      incoming_header_ = msg;
    } else {
      size_t bytes_left = incoming_header_->data_length - incoming_payload_.size();
      if (block->payload.size() > bytes_left) {
        LOG(ERROR) << "received too many bytes while waiting for payload";
        return false;
      }
      incoming_payload_.append(std::move(block->payload));
    }

    if (incoming_header_->data_length == incoming_payload_.size()) {
      auto packet = std::make_unique<apacket>();
      packet->msg = *incoming_header_;

      // TODO: Make apacket contain an IOVector so we don't have to coalesce.
      packet->payload = std::move(incoming_payload_).coalesce();
      transport->HandleRead(std::move(packet));

      incoming_header_.reset();
      // reuse the capacity of the incoming payload while we can.
      auto free_block = incoming_payload_.clear();
      if (block->payload.capacity() == 0) {
        block->payload = std::move(free_block);
      }
    }
  }

 return true;
}

void UsbIoContext::HandleWrite(TransferId id) {
  std::lock_guard<std::mutex> lock(write_mutex_);
  auto it =
      std::find_if(write_requests_.begin(), write_requests_.end(), [id](const auto& req) {
        return static_cast<uint64_t>(req.id()) == static_cast<uint64_t>(id);
      });

  CHECK(it != write_requests_.end());

  write_requests_.erase(it);
  size_t outstanding_writes = --writes_submitted_;
  LOG(DEBUG) << "USB write: reaped, down to " << outstanding_writes
            << " write_requests_ vector size: " << write_requests_.size()
            << " Write success for id: " << static_cast<uint64_t>(id);
}

class IouringContext final : public UsbIoContext {
    public:
        IouringContext(unique_fd read_fd, unique_fd write_fd);
        ~IouringContext();

        bool SubmitReadRequests() override;
        bool ProcessEvents(atransport* transport) override;
        bool SubmitWrites() override;

    protected:
        IoReadBlock CreateReadBlock(uint64_t id) override;
        IoWriteBlock CreateWriteBlock(std::shared_ptr<Block> payload, size_t offset, size_t len,
                                          uint64_t id) override;
        void PrepareReadBlock(IoReadBlock* block, uint64_t id) override;
        bool SubmitIO(int num_blocks, IoReadBlock* block = nullptr) override;

        bool HandleRead(TransferId id, int64_t size, atransport* transport) override;

    private:
        std::unique_ptr<struct io_uring> ring_;
};

IouringContext::IouringContext(unique_fd read_fd, unique_fd write_fd) {
    read_fd_ = std::move(read_fd);
    write_fd_ = std::move(write_fd);

    ring_ = std::make_unique<struct io_uring>();
    int ret = io_uring_queue_init(kUsbReadQueueDepth + kUsbWriteQueueDepth, ring_.get(), 0);
    if (ret) {
      PLOG(FATAL) << "io_uring_queue_init failed with ret: " << ret;
    }

    ret = io_uring_register_eventfd(ring_.get(), worker_event_fd_.get());
    if (ret) {
      PLOG(FATAL) << "io_uring_register_eventfd failed with ret: " << ret;
    }

    LOG(INFO) << "IouringContext initialized";
}

IouringContext::~IouringContext() {
    io_uring_queue_exit(ring_.get());
    read_fd_.reset();
    write_fd_.reset();
}

bool IouringContext::SubmitReadRequests() {
    for (size_t i = 0; i < kUsbReadQueueDepth; ++i) {
        read_requests_[i] = CreateReadBlock(next_read_id_++);
    }

    if (!SubmitIO(kUsbReadQueueDepth)) {
        return false;
    }

    return true;
}

IoReadBlock IouringContext::CreateReadBlock(uint64_t id) {
    IoReadBlock block;
    PrepareReadBlock(&block, id);
    return block;
}

void IouringContext::PrepareReadBlock(IoReadBlock* block, uint64_t id) {
  if (block->payload.capacity() >= kUsbReadSize) {
    block->payload.resize(kUsbReadSize);
  } else {
    block->payload = Block(kUsbReadSize);
  }

  block->io_uring = true;
  struct io_uring_sqe* sqe = io_uring_get_sqe(ring_.get());
  if (!sqe) {
      LOG(FATAL) << "Failed to get SQE during PrepareReadBlock";
  }
  io_uring_prep_read(sqe, read_fd_.get(), block->payload.data(),
                      block->payload.size(), 0);
  sqe->user_data = block->iou_data.id = static_cast<uint64_t>(TransferId::read(id));
  //sqe->flags |= (IOSQE_ASYNC);
  LOG(DEBUG) << "READ: Submit-read block with sqe-id: " << sqe->user_data
            << " block->iou_data.id: " << block->iou_data.id
            << " Value: " << id;
  block->pending = true;
}

bool IouringContext::SubmitIO(int num_blocks, IoReadBlock*) {
  int ret = io_uring_submit(ring_.get());
  if (ret != num_blocks) {
    LOG(ERROR) << "io_uring_submit failed ret: " << ret
               << " Expected: " << num_blocks;
    return false;
  }

  return true;
}

bool IouringContext::ProcessEvents(atransport* transport) {
  size_t kMaxEvents = kUsbReadQueueDepth + kUsbWriteQueueDepth;

  while (kMaxEvents) {
      struct io_uring_cqe *cqe;

      int ret = io_uring_cq_ready(ring_.get());
      if (ret <= 0) {
          return true;
      }

      ret = io_uring_peek_cqe(ring_.get(), &cqe);
      if (ret) {
          if (ret == -EAGAIN || ret == -EINTR) {
              LOG(ERROR) << "io_uring_peek_cqe returned: " << ret
                         << " retrying completion-queue";
              usleep(1);
              continue;
          }
          if (ret != -EAGAIN) {
              LOG(ERROR) << "io_uring_peek_cqe failed with ret: " << ret;
              return false;
          }
          return true;
      }

      TransferId id = TransferId::from_value(cqe->user_data);
      LOG(DEBUG) << "CQE received with cqe_id: " << cqe->user_data
                << " Value: " << id.id
                << " cqe->res: " << cqe->res;

      if (cqe->res < 0) {
          if (!connection_started_ && (ret == -EPIPE || cqe->res  == -EPIPE) &&
              id.direction == TransferDirection::READ) {
              uint64_t read_idx = id.id % kUsbReadQueueDepth;
              io_uring_cqe_seen(ring_.get(), cqe);
              PrepareReadBlock(&read_requests_[read_idx], id.id);
              if (!SubmitIO(1)) {
                  return false;
              }
              kMaxEvents -= 1;
              continue;
          } else {
              if (cqe->res == -ECANCELED || cqe->res == -EAGAIN || cqe->res == -EINTR) {
                  uint64_t index;
                  io_uring_cqe_seen(ring_.get(), cqe);
                  if (id.direction == TransferDirection::READ) {
                      index = id.id % kUsbReadQueueDepth;
                      PrepareReadBlock(&read_requests_[index], id.id);
                  } else {
                      index = id.id % kUsbWriteQueueDepth;
                      LOG(ERROR) << "Received write error: " << cqe->res;
                      return false;
                  }

                  LOG(INFO) << "I/O failed with: " << cqe->res << " retrying again";
                  if (!SubmitIO(1)) {
                      return false;
                  }
                  kMaxEvents -= 1;
                  continue;
              }
              std::string error =
                StringPrintf("%s %" PRIu64 " failed with error %s",
                         id.direction == TransferDirection::READ ? "read" : "write",
                         id.id, strerror(cqe->res));
              LOG(ERROR) << error;
              return false;
          }
      }

      size_t io_size = cqe->res;
      io_uring_cqe_seen(ring_.get(), cqe);

      if (id.direction == TransferDirection::READ) {
          connection_started_ = true;
          if (!HandleRead(id, io_size, transport)) {
              return false;
          }
      } else {
          HandleWrite(id);
      }

      kMaxEvents -= 1;
  }

  return true;
}

bool IouringContext::HandleRead(TransferId id, int64_t size, atransport* transport) {
  uint64_t read_idx = id.id % kUsbReadQueueDepth;
  IoReadBlock* block = &read_requests_[read_idx];
  block->pending = false;
  block->payload.resize(size);

  // Notification for completed reads can be received out of order.
  if (block->id().id != needed_read_id_) {
    LOG(VERBOSE) << "read " << block->id().id << " completed while waiting for "
                 << needed_read_id_;
    return true;
  }

  int num_blocks_to_submit = 0;
  for (uint64_t id = needed_read_id_;; ++id) {
    size_t read_idx = id % kUsbReadQueueDepth;
    IoReadBlock* current_block = &read_requests_[read_idx];
    if (current_block->pending) {
      break;
    }
    if (!ProcessRead(current_block, transport)) {
      return false;
    }

    num_blocks_to_submit += 1;
    PrepareReadBlock(current_block, block->id().id + kUsbReadQueueDepth);
    ++needed_read_id_;
  }

  // Submit the I/O in one shot
  if (!SubmitIO(num_blocks_to_submit)) {
      return false;
  }
  return true;
}

IoWriteBlock IouringContext::CreateWriteBlock(std::shared_ptr<Block> payload, size_t offset, size_t len,
                                          uint64_t id) {
  auto block = IoWriteBlock();
  block.payload = std::move(payload);

  block.iou_data.id = static_cast<uint64_t>(TransferId::write(id));
  block.iou_data.data = reinterpret_cast<void*>(block.payload->data() + offset);
  block.iou_data.len = len;
  block.pending = false;
  block.io_uring = true;

  LOG(DEBUG) << "WRITE: Submit-write"
            << " block.iou_data.id: " << block.iou_data.id
            << " Value: " << id;

  return block;
}

bool IouringContext::SubmitWrites() {
  std::lock_guard<std::mutex> lock(write_mutex_);

  if (writes_submitted_ == kUsbWriteQueueDepth) {
    return true;
  }

  ssize_t writes_to_submit = std::min(kUsbWriteQueueDepth - writes_submitted_,
                                      write_requests_.size() - writes_submitted_);
  CHECK_GE(writes_to_submit, 0);
  if (writes_to_submit == 0) {
    return true;
  }

  for (int i = 0; i < writes_to_submit; ++i) {
    auto& block = write_requests_[writes_submitted_ + i];
    CHECK(!block.pending);

    struct io_uring_sqe* sqe = io_uring_get_sqe(ring_.get());
    if (!sqe) {
      LOG(ERROR) << "Failed to get SQE";
      return false;
    }

    io_uring_prep_write(sqe, write_fd_.get(), block.iou_data.data,
                        block.iou_data.len, 0);
    sqe->user_data = block.iou_data.id;
    //sqe->flags |= (IOSQE_ASYNC);
    block.pending = true;
  }

  writes_submitted_ += writes_to_submit;

  if (!SubmitIO(writes_to_submit)) {
    LOG(ERROR) << "Failed to submit writes";
    return false;
  }

  return true;
}

class AioContext final : public UsbIoContext {
    public:
        AioContext(unique_fd read_fd, unique_fd write_fd);
        ~AioContext();

        bool SubmitReadRequests() override;
        bool ProcessEvents(atransport* transport) override;
        bool SubmitWrites() override;

    protected:
        IoReadBlock CreateReadBlock(uint64_t id) override;
        IoWriteBlock CreateWriteBlock(std::shared_ptr<Block> payload, size_t offset, size_t len,
                                          uint64_t id) override;
        void PrepareReadBlock(IoReadBlock* block, uint64_t id) override;
        bool SubmitIO(int num_blocks, IoReadBlock* block = nullptr) override;
        bool HandleRead(TransferId id, int64_t size, atransport* transport) override;

        ScopedAioContext aio_context_;
};

AioContext::AioContext(unique_fd read_fd, unique_fd write_fd) {
    read_fd_ = std::move(read_fd);
    write_fd_ = std::move(write_fd);
    aio_context_ = ScopedAioContext::Create(kUsbReadQueueDepth + kUsbWriteQueueDepth);
}

AioContext::~AioContext() {
    aio_context_.reset();
    read_fd_.reset();
    write_fd_.reset();
}

bool AioContext::SubmitReadRequests() {
    for (size_t i = 0; i < kUsbReadQueueDepth; ++i) {
        read_requests_[i] = CreateReadBlock(next_read_id_++);
        if (!SubmitIO(1, &read_requests_[i])) {
            return false;
        }
    }

    return true;
}

IoReadBlock AioContext::CreateReadBlock(uint64_t id) {
    IoReadBlock block;
    PrepareReadBlock(&block, id);

    block.control.aio_rw_flags = 0;
    block.control.aio_lio_opcode = IOCB_CMD_PREAD;
    block.control.aio_reqprio = 0;
    block.control.aio_fildes = read_fd_.get();
    block.control.aio_offset = 0;
    block.control.aio_flags = IOCB_FLAG_RESFD;
    block.control.aio_resfd = worker_event_fd_.get();
    return block;
}

void AioContext::PrepareReadBlock(IoReadBlock* block, uint64_t id) {
  block->pending = false;
  if (block->payload.capacity() >= kUsbReadSize) {
    block->payload.resize(kUsbReadSize);
  } else {
    block->payload = Block(kUsbReadSize);
  }
  block->control.aio_data = static_cast<uint64_t>(TransferId::read(id));
  block->control.aio_buf = reinterpret_cast<uintptr_t>(block->payload.data());
  block->control.aio_nbytes = block->payload.size();
}

bool AioContext::SubmitIO(int num_blocks, IoReadBlock* block) {
  block->pending = true;
  CHECK(num_blocks == 1);

  struct iocb* iocb = &block->control;
  if (io_submit(aio_context_.get(), 1, &iocb) != 1) {
    PLOG(ERROR) << "Failed to submit read";
    return false;
  }

  return true;
}

bool AioContext::ProcessEvents(atransport* transport) {
  static constexpr size_t kMaxEvents = kUsbReadQueueDepth + kUsbWriteQueueDepth;
  struct io_event events[kMaxEvents];
  struct timespec timeout = {.tv_sec = 0, .tv_nsec = 0};
  int rc = io_getevents(aio_context_.get(), 0, kMaxEvents, events, &timeout);
  if (rc == -1) {
    PLOG(ERROR) << "io_getevents failed while reading";
    return false;
  }

  for (int event_idx = 0; event_idx < rc; ++event_idx) {
    auto& event = events[event_idx];
    TransferId id = TransferId::from_value(event.data);

    if (event.res < 0) {
      // On initial connection, some clients will send a ClearFeature(HALT) to
      // attempt to resynchronize host and device after the adb server is killed.
      // On newer device kernels, the reads we've already dispatched will be cancelled.
      // Instead of treating this as a failure, which will tear down the interface and
      // lead to the client doing the same thing again, just resubmit if this happens
      // before we've actually read anything.
      if (!connection_started_ && event.res == -EPIPE &&
          id.direction == TransferDirection::READ) {
        uint64_t read_idx = id.id % kUsbReadQueueDepth;
        if (!SubmitIO(1, &read_requests_[read_idx])) {
            return false;
        }
        continue;
      } else {
        std::string error =
            StringPrintf("%s %" PRIu64 " failed with error %s",
                         id.direction == TransferDirection::READ ? "read" : "write",
                         id.id, strerror(-event.res));
        LOG(ERROR) << error;
        return false;
      }
    }

    if (id.direction == TransferDirection::READ) {
      connection_started_ = true;
      if (!HandleRead(id, event.res, transport)) {
        return false;
      }
    } else {
      HandleWrite(id);
    }
  }

  return true;
}

bool AioContext::HandleRead(TransferId id, int64_t size, atransport* transport) {
  uint64_t read_idx = id.id % kUsbReadQueueDepth;
  IoReadBlock* block = &read_requests_[read_idx];
  block->pending = false;
  block->payload.resize(size);

  // Notification for completed reads can be received out of order.
  if (block->id().id != needed_read_id_) {
    LOG(VERBOSE) << "read " << block->id().id << " completed while waiting for "
                 << needed_read_id_;
    return true;
  }

  for (uint64_t id = needed_read_id_;; ++id) {
    size_t read_idx = id % kUsbReadQueueDepth;
    IoReadBlock* current_block = &read_requests_[read_idx];
    if (current_block->pending) {
      break;
    }
    if (!ProcessRead(current_block, transport)) {
      return false;
    }

    PrepareReadBlock(current_block, current_block->id().id + kUsbReadQueueDepth);
    if (!SubmitIO(1, current_block)) {
      return false;
    }

    ++needed_read_id_;
  }

  return true;
}

IoWriteBlock AioContext::CreateWriteBlock(std::shared_ptr<Block> payload, size_t offset, size_t len,
                                          uint64_t id) {
  auto block = IoWriteBlock();
  block.payload = std::move(payload);
  block.control.aio_data = static_cast<uint64_t>(TransferId::write(id));
  block.control.aio_rw_flags = 0;
  block.control.aio_lio_opcode = IOCB_CMD_PWRITE;
  block.control.aio_reqprio = 0;
  block.control.aio_fildes = write_fd_.get();
  block.control.aio_buf = reinterpret_cast<uintptr_t>(block.payload->data() + offset);
  block.control.aio_nbytes = len;
  block.control.aio_offset = 0;
  block.control.aio_flags = IOCB_FLAG_RESFD;
  block.control.aio_resfd = worker_event_fd_.get();
  return block;
}

bool AioContext::SubmitWrites() {
  std::lock_guard<std::mutex> lock(write_mutex_);

  if (writes_submitted_ == kUsbWriteQueueDepth) {
    return true;
  }

  ssize_t writes_to_submit = std::min(kUsbWriteQueueDepth - writes_submitted_,
                                      write_requests_.size() - writes_submitted_);
  CHECK_GE(writes_to_submit, 0);
  if (writes_to_submit == 0) {
    return true;
  }

  struct iocb* iocbs[kUsbWriteQueueDepth];
  for (int i = 0; i < writes_to_submit; ++i) {
    CHECK(!write_requests_[writes_submitted_ + i].pending);
    write_requests_[writes_submitted_ + i].pending = true;
    iocbs[i] = &write_requests_[writes_submitted_ + i].control;
    LOG(VERBOSE) << "submitting write_request " << static_cast<void*>(iocbs[i]);
  }

  writes_submitted_ += writes_to_submit;

  int rc = io_submit(aio_context_.get(), writes_to_submit, iocbs);
  if (rc == -1) {
    PLOG(ERROR) << "failed to submit write requests";
    return false;
  } else if (rc != writes_to_submit) {
    LOG(FATAL) << "failed to submit all writes: wanted to submit " << writes_to_submit
               << ", actually submitted " << rc;
  }

  return true;
}

#if 0
std::unique_ptr<IUsbIoContext> IUsbIoContext::Init_iou(unique_fd write_fd, bool io_uring) {
    LOG(INFO) << "init_iou: " << io_uring;
    return std::unique_ptr<IUsbIoContext>(new IouringContext(std::move(write_fd)));
}
#endif

std::unique_ptr<IUsbIoContext> IUsbIoContext::Init(unique_fd read_fd, unique_fd write_fd, bool io_uring) {
    //io_uring = false;
#if 1
    if (io_uring) {
        return std::unique_ptr<IUsbIoContext>(new IouringContext(std::move(read_fd), std::move(write_fd)));
    }
#endif
    return std::unique_ptr<IUsbIoContext>(new AioContext(std::move(read_fd), std::move(write_fd)));
    LOG(INFO) << "Init: " << io_uring;
    //return std::unique_ptr<IUsbIoContext>(new AioContext(std::move(read_fd)));
}

IUsbIoContext::~IUsbIoContext() {}
