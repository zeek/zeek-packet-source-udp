/**
 * A UDP packet receiver using liburing. Needs kernel 6.1 or later, I think.
 */
#include "packet_receiver_io_uring.h"
#include "packet_source_debug.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <liburing.h>
#include <liburing/io_uring.h>
#include <sys/mman.h>
#include <sys/socket.h>

namespace zeek::packetsource::udp {

IOUringPacketReceiver::IOUringPacketReceiver(int fd, size_t sq_entries,
                                             size_t cq_entries, size_t buffers,
                                             size_t buf_shift)
    : fd(fd), sq_entries(sq_entries), cq_entries(cq_entries), buffers(buffers),
      buf_shift(buf_shift), buf_size(1 << buf_shift) {

  // SO_TIMESTAMP is in effect. Make enough room. Might want to inject this?
  msg.msg_controllen = CMSG_LEN(sizeof(struct timeval));

  // Allocate room for the CQ entries.
  cqes.resize(cq_entries);
}

IOUringPacketReceiver::~IOUringPacketReceiver() {
  UDPSOURCE_DEBUG("Teardown...");
  if (mapped != MAP_FAILED)
    munmap(mapped, buf_ring_size);

  io_uring_queue_exit(&ring);
}

namespace {

// return 0 on success, otherwise -1
int add_recvmsg_multishot(struct io_uring *ring, struct msghdr *msg,
                          int fdidx) {
  // Get the first sqe (submission queue entry) and setup
  // a multishot recvmsg operation.
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  if (!sqe) {
    io_uring_submit(ring);
    sqe = io_uring_get_sqe(ring);
  }

  if (!sqe)
    return -1;

  io_uring_prep_recvmsg_multishot(sqe, fdidx, msg, /*flags=*/0);
  sqe->flags |= IOSQE_FIXED_FILE;
  sqe->flags |= IOSQE_BUFFER_SELECT;
  sqe->buf_group = 0;

  return 0;
}
} // namespace

bool IOUringPacketReceiver::Open() {
  UDPSOURCE_DEBUG("Opening...");
  int ret;
  int flags = 0;

  struct io_uring_params params = {
      .sq_entries = static_cast<uint32_t>(sq_entries),
      .cq_entries = static_cast<uint32_t>(cq_entries),
  };

  UDPSOURCE_DEBUG("io_uring_queue_init_params() with sq=%zu cq=%zu", sq_entries,
                  cq_entries);

  if (io_uring_queue_init_params(sq_entries, &ring, &params) < 0) {
    fprintf(stderr, "init_uring_queue_init_params() failed: %s",
            strerror(errno));
    return false;
  }

  buf_ring_size = (sizeof(io_uring_buf) + buf_size) * buffers;
  UDPSOURCE_DEBUG("mmap() with buf_ring_size=%zu bytes", buf_ring_size);

  mapped = mmap(NULL, buf_ring_size, PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

  if (mapped == MAP_FAILED) {
    fprintf(stderr, "mmap() failed: %s (%d)", strerror(errno), errno);
    return false;
  }

  buf_ring = static_cast<struct io_uring_buf_ring *>(mapped);
  buffer_base = reinterpret_cast<std::byte *>(buf_ring) +
                sizeof(struct io_uring_buf) * buffers;

  io_uring_buf_ring_init(buf_ring);

  struct io_uring_buf_reg reg = {
      .ring_addr = reinterpret_cast<uint64_t>(buf_ring),
      .ring_entries = static_cast<uint32_t>(buffers),
      .bgid = 0,
  };

  ret = io_uring_register_buf_ring(&ring, &reg, 0);
  if (ret != 0) {
    fprintf(stderr, "io_uring_register_buf_ring() failed: %s\n",
            strerror(errno));
    return false;
  }

  for (size_t i = 0; i < buffers; i++) {
    std::byte *buf = buffer_base + i * buf_size;
    io_uring_buf_ring_add(buf_ring, buf, buf_size, i,
                          io_uring_buf_ring_mask(buffers), i);
  }

  io_uring_buf_ring_advance(buf_ring, buffers);

  // Register fd as a file for IOSQE_FIXED_FILE usage.
  ret = io_uring_register_files(&ring, &fd, 1);
  if (ret < 0) {
    fprintf(stderr, "io_uring_register_files() failed: %s\n", strerror(errno));
    return false;
  }

  // Submit our first (and only) OP.
  if (add_recvmsg_multishot(&ring, &msg, /*fdidx=*/0) < 0) {
    fprintf(stderr, "add_recvmsg_multishot() failed: %s (%d)\n",
            strerror(errno), errno);
    return false;
  }

  ret = io_uring_submit(&ring);
  UDPSOURCE_DEBUG("io_uring_submit() ret=%d", ret);

  return ret == 1;
}

bool IOUringPacketReceiver::NextPacket(RawPacket *pkt) {

  if (n > 0 && i < n) { // have some packets left in cqes. Fetch them.
    auto *cqe = cqes[i];

    if (cqe->res < 0) {
      fprintf(stderr,
              "IOUringPacketReceiver::NextPacket(): cqe with error: "
              "n=%zu i=%zu cqe->res=%d errno=%s\n",
              n, i, cqe->res, strerror(-cqe->res));
      ++i;
      return false;
    }

    uint16_t bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    std::byte *buf = buffer_base + (bid << buf_shift);

    io_uring_recvmsg_out *out = io_uring_recvmsg_validate(buf, cqe->res, &msg);
    UDPSOURCE_DEBUG("cqe->res=%d cqe->flags=0x%02x bid=%d buf=%p out=%p",
                    cqe->res, cqe->flags, bid, buf, out);

    // Parse out.
    if (out) {
      // Get timestamp into RawPacket.
      struct cmsghdr *cmsg = io_uring_recvmsg_cmsg_firsthdr(out, &msg);
      for (; cmsg != nullptr;
           cmsg = io_uring_recvmsg_cmsg_nexthdr(out, &msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP) {
          pkt->ts = reinterpret_cast<struct timeval *>(CMSG_DATA(cmsg));
          // UDPSOURCE_DEBUG("timestamp from cmsg: %zu.%zu!", pkt->ts->tv_sec,
          //                          pkt->ts->tv_usec);
          break;
        }
      }

      // Get data and length into the raw packet.
      pkt->data =
          reinterpret_cast<const u_char *>(io_uring_recvmsg_payload(out, &msg));
      pkt->len = io_uring_recvmsg_payload_length(out, cqe->res, &msg);
    } else {
      // Invalid recvmsg?
      fprintf(stderr, "io_uring_recvmsg_validate() error\n");
      ++i;
      return false;
    }

    // Did the multishot recvmsg op complete? Resubmit it.
    if ((cqe->flags & IORING_CQE_F_MORE) == 0) {
      UDPSOURCE_DEBUG("Resubmitting recvmsg_multishot");
      if (add_recvmsg_multishot(&ring, &msg, /*fdidx=*/0) < 0) {
        fprintf(stderr, "add_recvmsg_multishot() failed\n");
        abort();
      }

      if (io_uring_submit(&ring) != 1) {
        // XXX: Should probably handle graceful?
        fprintf(stderr, "io_uring_submit() failed: %s %d\n", strerror(errno),
                errno);
        abort();
      }
    }

    return true;
  }

  // All CQEs have been exhausted, move the completion queue tail forward.
  io_uring_cq_advance(&ring, n);

  n = i = 0;

  auto count = io_uring_peek_batch_cqe(&ring, cqes.data(), cqes.size());

  if (count > 0) {
    n = count;
    return NextPacket(pkt); // will succeed, for sure!
  } else {
    // Nothing to consume right now :-(
    n = 0;
  }

  return false;
}

void IOUringPacketReceiver::DoneWithPacket() {
  // Recycle the buffer and advance the ring.
  const auto *cqe = cqes[i];

  if (cqe->flags & IORING_CQE_F_BUFFER) {
    uint16_t bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    std::byte *buf = buffer_base + (bid << buf_shift);

    UDPSOURCE_DEBUG("DoneWithPacket() recycle buf=%p bid=%d ", buf, bid);

    io_uring_buf_ring_add(buf_ring, buf, buf_size, bid,
                          io_uring_buf_ring_mask(buffers), 0);
    io_uring_buf_ring_advance(buf_ring, 1);
  }

  ++i;
}

} // namespace zeek::packetsource::udp
