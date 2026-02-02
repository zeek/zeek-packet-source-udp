#include "conn_key/geneve_vxlan.h"

#include <cstring>

#include "packet_source.h"
#include "zeek/ID.h"
#include "zeek/Val.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/fivetuple/Factory.h"

namespace zeek::packetsource::udp::conn_key {

class GeneveVxlanVniConnKey : public zeek::IPBasedConnKey {
public:
  GeneveVxlanVniConnKey() {
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

    ctx.Assign(GetGeneveVniOffset(), static_cast<zeek_uint_t>(key.geneve_vni));
    ctx.Assign(GetVxlanVniOffset(), static_cast<zeek_uint_t>(key.vxlan_vni));
  }

  void DoInit(const Packet &pkt) override {
    key.geneve_vni = UDPSource::GeneveVni();
    key.vxlan_vni = UDPSource::VxlanVni();
  }

  static int GetGeneveVniOffset() {
    static int geneve_vni_offset =
        zeek::id::conn_id_ctx->FieldOffset("geneve_vni");
    return geneve_vni_offset;
  }

  static int GetVxlanVniOffset() {
    static int geneve_vni_offset =
        zeek::id::conn_id_ctx->FieldOffset("vxlan_vni");
    return geneve_vni_offset;
  }

private:
  friend class GeneveVxlanVniFactory;

  struct {
    struct detail::PackedConnTuple tuple;
    uint32_t geneve_vni;
    uint32_t vxlan_vni;
  } __attribute__((packed, aligned)) key;
};

zeek::ConnKeyPtr GeneveVxlanVniFactory::DoNewConnKey() const {
  return std::make_unique<GeneveVxlanVniConnKey>();
}

zeek::expected<zeek::ConnKeyPtr, std::string>
GeneveVxlanVniFactory::DoConnKeyFromVal(const zeek::Val &v) const {
  if (v.GetType() != id::conn_id)
    return zeek::unexpected<std::string>{"unexpected value type"};

  auto ck = zeek::conn_key::fivetuple::Factory::DoConnKeyFromVal(v);
  if (!ck.has_value())
    return ck;

  int geneve_vni_offset = GeneveVxlanVniConnKey::GetGeneveVniOffset();
  int vxlan_vni_offset = GeneveVxlanVniConnKey::GetVxlanVniOffset();
  static int ctx_offset = id::conn_id->FieldOffset("ctx");

  auto *k = static_cast<GeneveVxlanVniConnKey *>(ck.value().get());
  auto *ctx = v.AsRecordVal()->GetFieldAs<zeek::RecordVal>(ctx_offset);

  if (geneve_vni_offset < 0)
    return zeek::unexpected<std::string>{"missing geneve_vni field"};

  if (vxlan_vni_offset < 0)
    return zeek::unexpected<std::string>{"missing vxlan_vni field"};

  if (ctx->HasField(geneve_vni_offset))
    k->key.geneve_vni = ctx->GetFieldAs<zeek::CountVal>(geneve_vni_offset);

  if (ctx->HasField(vxlan_vni_offset))
    k->key.vxlan_vni = ctx->GetFieldAs<zeek::CountVal>(vxlan_vni_offset);

  return ck;
}

} // namespace zeek::packetsource::udp::conn_key
