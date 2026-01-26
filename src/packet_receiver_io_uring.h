#pragma once

#include "packet_receiver.h"

#include <liburing.h>
#include <sys/socket.h>
#include <vector>

namespace zeek::packetsource::udp {

class IOUringPacketReceiver : public PacketReceiver {
public:
  /**
   * Construct a new io_uring based packet receiver.
   *
   * @param fd - The file descriptor of the bound UDP socket.
   * @param entries - size of cqes to receive completions.
   * @param buffers - Number of buffers to add to the ring.
   * @param buf_shift - Size of an individual buffer as shift. Use 14 for 16k.
   */
  IOUringPacketReceiver(int fd, size_t entries, size_t buffers,
                        size_t buf_shift);
  ~IOUringPacketReceiver() override;

  bool Open() override;
  bool NextPacket(RawPacket *pkt) override;
  void DoneWithPacket() override;

private:
  int fd;
  size_t entries, buffers, buf_shift, buf_size;

  struct io_uring ring;
  size_t buf_ring_size;

  // mmap()'ed memory area of size of struct io_uring_buf and buffers.
  struct io_uring_buf_ring *buf_ring = nullptr;

  // Pointer where buffer slabs are.
  std::byte *buffer_base;

  std::vector<struct io_uring_cqe *> cqes; // CQE array.
  size_t n = 0; // Number of cqes from last peek call.
  size_t i = 0; // Offset into cqes

  struct msghdr msg;
};

} // namespace zeek::packetsource::udp
