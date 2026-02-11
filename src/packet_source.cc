#include "packet_source.h"

#ifdef HAVE_LIBURING
#include "packet_receiver_io_uring.h"
#endif
#include "packet_receiver_recvmmsg.h"
#include "packet_source_debug.h"
#include "packet_source_options.h"
#include "packet_source_udp.bif.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <zeek/DebugLogger.h>
#include <zeek/Desc.h>
#include <zeek/iosource/PktSrc.h>
#include <zeek/util.h>

namespace zeek::packetsource::udp {

using PktSrc = zeek::iosource::PktSrc;

int UDPSource::vxlan_vni = -1;
int UDPSource::geneve_vni = -1;

UDPSource::UDPSource(const std::string &path, const ListenOptions &listen_opts,
                     const EncapOptions &encap_opts)
    : path(path), listen_opts(listen_opts), encap_opts(encap_opts),
      poll_interval(zeek::BifConst::PacketSource::UDP::poll_interval) {}

void UDPSource::Open() {
  UDPSOURCE_DEBUG("Setting up UDP listener socket");

  fd = socket(listen_opts.af, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) {
    Error(util::fmt("socket creation failed: %s", strerror(errno)));
    return;
  }

  // Configure the receive buffer to be larger than usual.
  auto buf =
      static_cast<int>(zeek::BifConst::PacketSource::UDP::udp_recv_buffer_size);
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf)) < 0) {
    Error(util::fmt("failed setsockopt() for SO_RCVBUF: %s", strerror(errno)));
    close(fd);
    fd = -1;
    return;
  }

  // Set the socket to non-blocking - we assume that Zeek will poll and relax.
  // We could also install the socket as pollable FD, but than we may no batch
  // nicely and wake up for every single packet.
  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
    Error(util::fmt("failed fcntl() for O_NONBLOCK: %s", strerror(errno)));
    close(fd);
    fd = -1;
    return;
  }

  UDPSOURCE_DEBUG("Enabling SO_REUSEADDR on fd=%d", fd);
  int reuseaddr = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) <
      0) {
    Error(util::fmt("failed setsockopt for SO_REUSEADDR: %s", strerror(errno)));
    close(fd);
    fd = -1;
    return;
  }

  // Enable reuseport for load balancing packets across multiple listeners using
  // Linux kernel features. According to the lwn article below, packets are
  // distributed across sockets using a tuple hash, so for VXLAN and GENVE
  // tunnels that have sensible and constant source ports per flow, this should
  // work well for us.
  //
  // https://lwn.net/Articles/542629/
  UDPSOURCE_DEBUG("Enabling SO_REUSEPORT on fd=%d", fd);
  int reuseport = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(reuseport)) <
      0) {
    Error(util::fmt("failed setsockopt for SO_REUSEPORT: %s", strerror(errno)));
    close(fd);
    fd = -1;
    return;
  }

  // Enable SO_TIMESTAMP for per packet receive timestamps.
  //
  // There is also SO_TIMESTAMPING and SO_TIMESTAMPNS. The latter yields struct
  // timespec rather than timeval and the former looks pretty advanced. Stick
  // with SO_TIMESTAMP for now.
  //
  // https://netdevconf.info/0x17/docs/netdev-0x17-paper23-talk-slides/netdevconf%202023_%20SO_TIMESTAMPING.pdf
  UDPSOURCE_DEBUG("Enabling SO_TIMESTAMP on fd=%d", fd);
  int timestampv = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &timestampv,
                 sizeof(timestampv)) < 0) {
    Error(util::fmt("failed setsockopt for SO_TIMESTAMP: %s", strerror(errno)));
    close(fd);
    fd = -1;
    return;
  }

  UDPSOURCE_DEBUG("Binding socket fd=%d", fd);
  socklen_t addr_len = listen_opts.af == AF_INET6 ? sizeof(struct sockaddr_in6)
                                                  : sizeof(struct sockaddr_in);
  if (bind(fd, (const struct sockaddr *)&listen_opts.addr, addr_len) < 0) {
    Error(util::fmt("failed to listen: %s", strerror(errno)));
    close(fd);
    fd = -1;
    return;
  }

  auto impl = zeek::BifConst::PacketSource::UDP::implementation;
  auto recvmmsg_impl = zeek::id::find("PacketSource::UDP::RECVMMSG")->GetVal();
  auto io_uring_impl = zeek::id::find("PacketSource::UDP::IO_URING")->GetVal();

  if (impl == recvmmsg_impl) {
    // Make configurable.
    size_t vlen = zeek::BifConst::PacketSource::UDP::recvmmsg_buffers;
    size_t iov_len = zeek::BifConst::PacketSource::UDP::recvmmsg_buffer_size;
    receiver = std::make_unique<RecvmmsgPacketReceiver>(fd, vlen, iov_len);
  } else if (impl == io_uring_impl) {
#ifdef HAVE_LIBURING
    size_t sq_entries = zeek::BifConst::PacketSource::UDP::io_uring_sq_entries;
    size_t cq_entries = zeek::BifConst::PacketSource::UDP::io_uring_cq_entries;
    size_t buffers = zeek::BifConst::PacketSource::UDP::io_uring_buffers;
    size_t buffer_shift =
        zeek::BifConst::PacketSource::UDP::io_uring_buffer_shift;

    receiver = std::make_unique<IOUringPacketReceiver>(
        fd, sq_entries, cq_entries, buffers, buffer_shift);
#else
    Error(util::fmt("PacketSource::UDP::IO_URING not available"));
    close(fd);
    fd = -1;
    return;
#endif
  } else {
    close(fd);
    fd = -1;
    Error(util::fmt("unknown implementation %s", obj_desc_short(impl).c_str()));
    return;
  }

  if (!receiver->Open()) {
    Error("failed to Open() receiver");
    receiver.reset();
    close(fd);
    fd = -1;
    return;
  }

  PktSrc::Properties props;
  props.path = path;
  props.selectable_fd = -1;

  // Enable selectable_fd for recvmmsg() unless explicitly disabled
  // via redef of recvmmsg_use_selectable_fd in script land.
  if (impl == recvmmsg_impl &&
      zeek::BifConst::PacketSource::UDP::recvmmsg_use_selectable_fd) {
    props.selectable_fd = fd;
    poll_interval = -1.0;
  }

  props.link_type = encap_opts.link_type;
  props.netmask = NETMASK_UNKNOWN;
  props.is_live = true;

  UDPSOURCE_DEBUG("Opened packet source with receiver implementation %s",
                  obj_desc_short(impl).c_str());
  Opened(props);
}

void UDPSource::Close() {
  // Just destruct the receiver instance for cleanup.
  receiver.reset();

  if (fd >= 0) {
    if (close(fd) != 0)
      Error(util::fmt("failed to close socket fd=%d: %s (%d)", fd,
                      strerror(errno), errno));
    fd = -1;
  }

  Closed();
}

/**
 * Packet receive path.
 */
bool UDPSource::ExtractNextPacket(zeek::Packet *pkt) {

  // Delegate to receiver. Could be recvmmsg(), could be io_uring.
  RawPacket rpkt;

  if (!receiver->NextPacket(&rpkt)) {
    had_packet = false;
    return false;
  }

  had_packet = true;
  stats.link += 1; // ?
  stats.received += 1;
  stats.bytes_received += rpkt.len;

  int link_type = encap_opts.link_type;
  const auto *pkt_data = rpkt.data;
  auto pkt_data_len = rpkt.len; // not sure, might have been longer?
  auto pkt_data_caplen = rpkt.len;

#define NO_PACKET_DEBUG
#ifdef PACKET_DEBUG
  constexpr int print_bytes = 32;
  for (int i = 0; i < rpkt.len && i < print_bytes; i++) {
    std::fprintf(stderr, "%02x%s", rpkt.data[i],
                 i < (print_bytes - 1) ? ":" : "");
  }
  std::fprintf(stderr, " \n");
#endif

  switch (encap_opts.encap) {
  case Encapsulation::SKIP: {
    //
    // skip
    //
    if (pkt_data_caplen < encap_opts.skip_bytes)
      goto skip_packet;

    pkt_data += encap_opts.skip_bytes;
    pkt_data_len -= encap_opts.skip_bytes;
    pkt_data_caplen -= encap_opts.skip_bytes;
    break;
  }
  case Encapsulation::GENEVE_VXLAN:
  case Encapsulation::GENEVE: {
    //
    // GENVE
    //
    if (pkt_data_caplen < 8)
      goto skip_packet;

    int geneve_version = pkt_data[0] >> 6;

    if (geneve_version != 0) {
      zeek::reporter->Weird("geneve_invalid_version",
                            util::fmt("%d", geneve_version),
                            "packet-source-udp");

      goto skip_packet_no_weird;
    }

    // Extract VNI for ConnKey implementations.
    geneve_vni = pkt_data[4] << 16 | pkt_data[5] << 8 | pkt_data[6];

    // Jump the GENEVE header and all options.
    uint8_t all_opt_len = (pkt_data[0] & 0x3F) * 4;

    if (pkt_data_caplen < (all_opt_len + 8)) {
      zeek::reporter->Weird("geneve_too_short",
                            util::fmt("pkt_data_caplen=%zu all_opt_len=%d",
                                      pkt_data_caplen, all_opt_len),
                            "packet-source-udp");
      goto skip_packet_no_weird;
    }

    pkt_data += (8 + all_opt_len);
    pkt_data_len -= (8 + all_opt_len);
    pkt_data_caplen -= (8 + all_opt_len);

    // Only GENEVE encapsulated.
    if (encap_opts.encap == Encapsulation::GENEVE)
      break;

    assert(encap_opts.encap == Encapsulation::GENEVE_VXLAN);

    // If this is GENEVE_VXLAN, parse the IP header and ump it.
    if (pkt_data_caplen < 20) {
      zeek::reporter->Weird("short_IP_in_GENEVE",
                            util::fmt("%zu", pkt_data_caplen),
                            "packet-source-udp");
      goto skip_packet_no_weird;
    }

    int ip_version = pkt_data[0] >> 4;
    if (ip_version != 4) {
      zeek::reporter->Weird("unhandled IP version", util::fmt("%d", ip_version),
                            "packet-source-udp");
      goto skip_packet_no_weird;
    }

    // TODO: IPV6 support. Just jump 40 bytes and ignore
    // any extension headers?
    uint8_t ihl = pkt_data[0] & 0x0F;
    size_t header_len = ihl * 4;

    if (header_len < 20 || header_len > pkt_data_caplen) {
      zeek::reporter->Weird(
          "invalid_IP_header_length",
          util::fmt("ihl=%d caplen=%zu", ihl, pkt_data_caplen),
          "packet-source-udp");
      goto skip_packet_no_weird;
    }

    uint8_t proto = pkt_data[9];
    if (proto != IPPROTO_UDP) {
      zeek::reporter->Weird("non_UDP_proto", util::fmt("proto=%d", proto),
                            "packet-source-udp");
      goto skip_packet_no_weird;
    }

    // Jump IP and UDP header.
    pkt_data += (header_len + 8);
    pkt_data_caplen -= (header_len + 8);
    pkt_data_len -= (header_len + 8);

    /* fall through to VXLAN handling */
  }
  case Encapsulation::VXLAN: {
    //
    // VXLAN
    //
    if (pkt_data_caplen < 8)
      goto skip_packet;

    // Test the I flag of VXLAN. If not set, weird and ignore.
    if ((pkt_data[0] & 0x08) == 0) {
      zeek::reporter->Weird("vxlan_unset_I_flag",
                            util::fmt("%02x", pkt_data[0]),
                            "packet-source-udp");

      goto skip_packet_no_weird;
    }

    // Extract VNI for ConnKey implementations.
    vxlan_vni = pkt_data[4] << 16 | pkt_data[5] << 8 | pkt_data[6];

    // Jump the VXLAN header.
    pkt_data += 8;
    pkt_data_len -= 8;
    pkt_data_caplen -= 8;

    break;
  }
  default:
    goto skip_packet;
  }

  // Success path.
  pkt->Init(link_type, rpkt.ts, pkt_data_caplen, pkt_data_len, pkt_data);
  return true;

  // Error path.

skip_packet:
  zeek::reporter->Weird("skipped_packet",
                        util::fmt("pkt_data_len=%zu encap=%d", pkt_data_len,
                                  static_cast<int>(encap_opts.encap)),
                        "packet-source-udp");

skip_packet_no_weird:
  ++invalid_packets;
  receiver->DoneWithPacket();
  return false;
}

void UDPSource::DoneWithPacket() { receiver->DoneWithPacket(); }

double UDPSource::GetNextTimeout() {
  double ret = poll_interval;
  if (had_packet)
    ret = 0.0;

  return ret;
}

// Statistics uses the SO_RXQ_OVFL getsockopt() call for dropped packets we
// can see from the socket. We cannot see more, so users should also
// monitoring drops on the actual interface outside of Zeek.
void UDPSource::Statistics(PktSrc::Stats *arg_stats) {

  *arg_stats = stats;

  if (fd >= 0) {
    uint32_t dropped;
    socklen_t dropped_len = sizeof(dropped);
    if (getsockopt(fd, SOL_SOCKET, SO_RXQ_OVFL, &dropped, &dropped_len) == 0) {
      arg_stats->dropped = stats.dropped = dropped;
    } else {
      zeek::reporter->Error("packet-source-udp: getsockopt(SO_RXQ_OVFL) "
                            "error on fd=%d: %s (%d)",
                            fd, strerror(errno), errno);
    }
  }

  // Add invalid packets to dropped ones.
  arg_stats->dropped += invalid_packets;
}

// Not implemented.
bool UDPSource::SetFilter(int index) { return true; }

// This mostly parses the path to extract all the parameters.
PktSrc *UDPSource::Instantiate(const std::string &path, bool is_live) {

  const auto [error_msg, listen_opts, encap_opts] = parse_interface_path(path);

  if (!error_msg.empty()) {
    zeek::reporter->FatalError("packet-source-udp: invalid path: %s",
                               error_msg.c_str());
    return nullptr;
  }

  return new UDPSource(path, listen_opts, encap_opts);
}

} // namespace zeek::packetsource::udp
