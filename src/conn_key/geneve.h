#pragma once

#include "zeek/ConnKey.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/fivetuple/Factory.h"

namespace zeek::packetsource::udp::conn_key {

/**
 * A ConnKey factory that includes the GENEVE VNI from the UDP packet source.
 */
class GeneveVniFactory : public zeek::conn_key::fivetuple::Factory {
public:
  static zeek::conn_key::FactoryPtr Instantiate() {
    return std::make_unique<GeneveVniFactory>();
  }

private:
  zeek::ConnKeyPtr DoNewConnKey() const override;
  zeek::expected<zeek::ConnKeyPtr, std::string>
  DoConnKeyFromVal(const zeek::Val &v) const override;
};

} // namespace zeek::packetsource::udp::conn_key
