#pragma once

#include <zeek/plugin/Plugin.h>

namespace plugin::Zeek_PacketSourceUDP {

class Plugin : public zeek::plugin::Plugin {
protected:
  zeek::plugin::Configuration Configure() override;

  void InitPostScript() override;
};

extern Plugin plugin;

} // namespace plugin::Zeek_PacketSourceUDP
