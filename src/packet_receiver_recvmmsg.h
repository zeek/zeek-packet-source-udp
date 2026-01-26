#pragma once

#include "packet_receiver.h"

#include <sys/socket.h>
#include <vector>

namespace zeek::packetsource::udp {

/**
 * A UDP packet receiver using recvmmsg()
 */
class RecvmmsgPacketReceiver : public PacketReceiver {
public:
  /**
   * Construct a new recvmmsg() based packet receiver.
   *
   * @param fd - The file descriptor of the bound UDP socket.
   * @param vecs_len- Number of iovec and msgvec entries to allocate.
   * @param iov_len - Length of an individual iovec - max packet length.
   */
  RecvmmsgPacketReceiver(int fd, size_t vlen, size_t iov_len);

  /**
   * Fills pkt and returns true, or returns false if no packet available.
   */
  bool NextPacket(RawPacket *pkt) override;
  void DoneWithPacket() override;

private:
  int fd;

  // Members used for recvmmsg(), iovecs point into buffer,
  // msgvec points at iovecs, cmsgs at control messages.
  std::vector<std::byte> buffer;
  std::vector<struct iovec> iovecs;
  std::vector<std::byte> cmsgs; // control messages
  std::vector<struct mmsghdr> msgvec;

  size_t n = 0; // Data available in msgvec after a recvmmsg() call.
  size_t i = 0; // offset into msgvec
};

} // namespace zeek::packetsource::udp
