#include "packet_receiver_recvmmsg.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sys/socket.h>

namespace zeek::packetsource::udp {

RecvmmsgPacketReceiver::RecvmmsgPacketReceiver(int fd, size_t vlen,
                                               size_t iov_len)
    : fd(fd) {

  // Allocate some memory for the recvmmsg() calls.
  buffer.resize(vlen * iov_len);
  iovecs.resize(vlen);
  msgvec.resize(vlen);

  const size_t cmsg_len = CMSG_LEN(sizeof(struct timeval));
  cmsgs.resize(vlen * cmsg_len);

  memset(msgvec.data(), 0, vlen * sizeof(msgvec[0]));
  memset(cmsgs.data(), 0, vlen * cmsg_len);

  for (size_t i = 0; i < vlen; ++i) {
    iovecs[i].iov_base = &buffer[i * iov_len];
    iovecs[i].iov_len = iov_len;

    msgvec[i].msg_hdr.msg_iov = &iovecs[i];
    msgvec[i].msg_hdr.msg_iovlen = 1;

    msgvec[i].msg_hdr.msg_control = &cmsgs[i * cmsg_len];
    msgvec[i].msg_hdr.msg_controllen = cmsg_len;
  }
}

bool RecvmmsgPacketReceiver::NextPacket(RawPacket *pkt) {

  if (n > 0 && i < n) {
    // Have a packet ready :-)
    pkt->data = static_cast<u_char *>(msgvec[i].msg_hdr.msg_iov->iov_base);
    pkt->len = msgvec[i].msg_len;

    auto *msg_hdr = &msgvec[i].msg_hdr;

    // Get the timestamp from the aux data. See man 3 cmsg.
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg_hdr); cmsg != nullptr;
         cmsg = CMSG_NXTHDR(msg_hdr, cmsg)) {
      if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP) {
        pkt->ts = reinterpret_cast<struct timeval *>(CMSG_DATA(cmsg));
        break;
      }
    }

    return true;
  }

  // Exhausted all packets, reset packet state.
  i = n = 0;

  // Non-blocking call to recvmmsg() to gather as many packets as are available.
  //
  // Note that the socket is non-blocking and also note that if you ever
  // consider making it blocking, the BUGS section of man recvmmsg() will
  // tell you that the timeout doesn't actually work and then this call
  // blocks Zeek's IO loop until the next packet arrives. Not an issue in
  // high-traffic environments, but not great when testing with a few packets
  // at a time.
  int r = recvmmsg(fd, msgvec.data(), msgvec.size(), /*flags=*/0, nullptr);

  // Success and have some packets.
  if (r > 0) {
    n = r;
    return NextPacket(pkt); // will succeed!
  } else if (r < 0) {
    if (errno != EAGAIN && errno != EINTR) {
      fprintf(stderr, "recvmmsg() failed: r=%d %s (%d), aborting...", r,
              strerror(errno), errno);

      // Not sure: Can or should we recover here?
      std::abort();
    }
  }

  return false;
}

void RecvmmsgPacketReceiver::DoneWithPacket() {
  // Move on to the next packet.
  ++i;
}

} // namespace zeek::packetsource::udp
