#pragma once

#include "packet_receiver.h"
#include "packet_source_options.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <zeek/iosource/PktSrc.h>

namespace zeek::packetsource::udp {

using PktSrc = zeek::iosource::PktSrc;

class UDPSource : public PktSrc {

public:
  static PktSrc *Instantiate(const std::string &path, bool is_live);

protected:
  /**
   * @copydoc PktSrc::Open
   */
  void Open() override;

  /**
   * @copydoc PktSrc::Close
   */
  void Close() override;

  /**
   * @copydoc PktSrc::Statistics
   */
  void Statistics(PktSrc::Stats *stats) override;

  /**
   * @copydoc PktSrc::ExtractNextPacket
   */
  bool ExtractNextPacket(zeek::Packet *pkt) override;

  /**
   * @copydoc PktSrc::ExtractNextPacket
   */
  double GetNextTimeout() override;

  /**
   * @copydoc PktSrc::DoneWithPacket
   */
  void DoneWithPacket() override;

  /**
   * @copydoc PktSrc::SetFilter
   */
  bool SetFilter(int index) override;

private:
  UDPSource(const std::string &path, const ListenOptions &listen_opts,
            const EncapOptions &encap_opts, const KeyValueOptions &kv_opts);
  virtual ~UDPSource() = default;

  std::string path; // The original interface path.
  ListenOptions listen_opts;
  EncapOptions encap_opts;

  std::unique_ptr<PacketReceiver> receiver;
  PktSrc::Stats stats;

  uint64_t invalid_packets = 0;
  int fd = -1;
  bool had_packet = true;
  double poll_interval = 0.0;
};

} // namespace zeek::packetsource::udp
