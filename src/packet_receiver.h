#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

namespace zeek::packetsource::udp {
/**
 * Represents a raw packet received via recvmmsg() with data
 * holding the VXLAN or GENEVE encapsulation headers, but not
 * the original UDP header.
 */
struct RawPacket {
  const u_char *data;
  size_t len;
  struct timeval *ts;
};

/**
 * Interface for getting packets.
 */
class PacketReceiver {
public:
  virtual ~PacketReceiver() = default;

  /**
   * Open() hook.
   */
  virtual bool Open() { return true; }

  virtual bool NextPacket(RawPacket *pkt) = 0;
  virtual void DoneWithPacket() = 0;
}; // namespace zeek::packetsource::udp

} // namespace zeek::packetsource::udp
