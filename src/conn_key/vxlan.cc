#include "conn_key/vxlan.h"

#include <cstring>

#include "packet_source.h"
#include "zeek/ID.h"
#include "zeek/Val.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/fivetuple/Factory.h"

namespace zeek::packetsource::udp::conn_key {

class VxlanVniConnKey : public zeek::IPBasedConnKey {
public:
  VxlanVniConnKey() {
    // Ensure padding holes in the key struct are filled with zeroes.
    memset(static_cast<void *>(&key), 0, sizeof(key));
  }

  detail::PackedConnTuple &PackedTuple() override { return key.tuple; }

  const detail::PackedConnTuple &PackedTuple() const override {
    return key.tuple;
  }

protected:
  zeek::session::detail::Key DoSessionKey() const override {
    return {reinterpret_cast<const void *>(&key), sizeof(key),
            session::detail::Key::CONNECTION_KEY_TYPE};
  }

  void DoPopulateConnIdVal(zeek::RecordVal &conn_id,
                           zeek::RecordVal &ctx) override {
    // Base class populates conn_id fields (orig_h, orig_p, resp_h, resp_p)
    zeek::IPBasedConnKey::DoPopulateConnIdVal(conn_id, ctx);

    if (conn_id.GetType() != id::conn_id)
      return;

    ctx.Assign(GetVxlanVniOffset(), static_cast<zeek_uint_t>(key.vxlan_vni));
  }

  void DoInit(const Packet &pkt) override {
    key.vxlan_vni = UDPSource::VxlanVni();
  }

  static int GetVxlanVniOffset() {
    static int vxlan_vni_offset =
        zeek::id::conn_id_ctx->FieldOffset("vxlan_vni");
    return vxlan_vni_offset;
  }

private:
  friend class VxlanVniFactory;

  struct {
    struct detail::PackedConnTuple tuple;
    uint32_t vxlan_vni;
  } __attribute__((packed, aligned)) key;
};

zeek::ConnKeyPtr VxlanVniFactory::DoNewConnKey() const {
  return std::make_unique<VxlanVniConnKey>();
}

zeek::expected<zeek::ConnKeyPtr, std::string>
VxlanVniFactory::DoConnKeyFromVal(const zeek::Val &v) const {
  if (v.GetType() != id::conn_id)
    return zeek::unexpected<std::string>{"unexpected value type"};

  auto ck = zeek::conn_key::fivetuple::Factory::DoConnKeyFromVal(v);
  if (!ck.has_value())
    return ck;

  int vni_offset = VxlanVniConnKey::GetVxlanVniOffset();
  static int ctx_offset = id::conn_id->FieldOffset("ctx");

  auto *k = static_cast<VxlanVniConnKey *>(ck.value().get());
  auto *ctx = v.AsRecordVal()->GetFieldAs<zeek::RecordVal>(ctx_offset);

  if (vni_offset < 0)
    return zeek::unexpected<std::string>{"missing vlxan_vni field"};

  if (ctx->HasField(vni_offset))
    k->key.vxlan_vni = ctx->GetFieldAs<zeek::CountVal>(vni_offset);

  return ck;
}

} // namespace zeek::packetsource::udp::conn_key
