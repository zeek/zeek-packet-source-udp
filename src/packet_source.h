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

  /**
   * Return the currently stored VXLAN VNI value or -1 if VXLAN is not used.
   */
  static int VxlanVni() { return vxlan_vni; }
  /**
   * Return the GENEVE VNI value or -1 if GENEVE is not used.
   */
  static int GeneveVni() { return geneve_vni; }

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
            const EncapOptions &encap_opts);
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

  // Globals for stashing the VXLAN and GENEVE VNI
  // values for use in custom ConnKey values.
  static int vxlan_vni;
  static int geneve_vni;
};

} // namespace zeek::packetsource::udp
