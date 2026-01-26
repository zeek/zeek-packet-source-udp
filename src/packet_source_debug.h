#pragma once

#include "plugin.h" // For the plugin instance.

#define UDPSOURCE_DEBUG(...)                                                   \
  PLUGIN_DBG_LOG(::plugin::Zeek_PacketSourceUDP::plugin, __VA_ARGS__)

// Avoid plugin.h unused for non-debug builds.
namespace {
struct __use_plugin {
  std::string name = ::plugin::Zeek_PacketSourceUDP::plugin.Name();
};
} // namespace
