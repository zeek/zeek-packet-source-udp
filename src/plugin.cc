#include "plugin.h"
#include "packet_source.h"
#include "packet_source_debug.h"
#include "packet_source_options.h"
#include <zeek/iosource/Component.h>
#include <zeek/iosource/PktSrc.h>

namespace plugin::Zeek_PacketSourceUDP {

zeek::plugin::Configuration Plugin::Configure() {

  AddComponent(new zeek::iosource::PktSrcComponent(
      "UDP", "udp", zeek::iosource::PktSrcComponent::LIVE,
      zeek::packetsource::udp::UDPSource::Instantiate));

  zeek::plugin::Configuration config;
  config.name = "Zeek::PacketSourceUDP";
  config.description = "A packet source listening on a UDP socket.";
  config.version = {VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH};

  return config;
}

void Plugin::InitPostScript() {

  // Run unit tests at InitPostScript() time.
  UDPSOURCE_DEBUG("Running unit tests...");
  zeek::packetsource::udp::test_parse_interface_path();
  UDPSOURCE_DEBUG("Finished unit tests...");
}

// Instantiate plugin.
Plugin plugin;

} // namespace plugin::Zeek_PacketSourceUDP
