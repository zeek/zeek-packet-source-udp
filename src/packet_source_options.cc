#include "packet_source_options.h"
#include "packet_source_debug.h"

#include <algorithm>
#include <limits>

#include <zeek/util.h>

namespace {

using namespace zeek::packetsource::udp;

std::tuple<std::string, ListenOptions, EncapOptions, KeyValueOptions>
make_error(std::string error) {
  return {error, {}, {}, {}};
}
} // namespace

namespace zeek::packetsource::udp {

std::tuple<std::string, ListenOptions, EncapOptions, KeyValueOptions>
parse_interface_path(const std::string &path) {
  std::string addr_str;
  std::string port_str;
  std::string opts_str; // free form query style options.
  ListenOptions listen_opts;
  KeyValueOptions kv_opts; // parse these

  // path is supposed to be: <addr>:<port>?option1=value1,option2=value2...
  // with IPv6 being surrounded with brackets like in Zeek script. An
  // IPv6 address needs to start with `[`.
  auto bopen = path.find('[');
  auto bclose = path.find(']');

  if (bopen == 0 && bclose != path.npos) {
    listen_opts.af = AF_INET6;
    auto pstart = path.find(':', bclose);
    if (pstart == path.npos)
      return make_error(util::fmt("missing port in path '%s'", path.c_str()));

    auto pend = path.find('?', pstart);
    addr_str = path.substr(bopen + 1, bclose - bopen - 1);
    port_str = path.substr(pstart + 1,
                           pend != path.npos ? (pend - pstart - 1) : path.npos);

    if (pend != path.npos)
      opts_str = path.substr(pend + 1, path.npos);

  } else {
    listen_opts.af = AF_INET;
    auto pstart = path.find(':');
    if (pstart == path.npos)
      return make_error(util::fmt("missing port in path '%s'", path.c_str()));

    auto pend = path.find('?');
    auto plen =
        pend == path.npos ? (path.size() - pstart - 1) : (pend - (pstart + 1));
    addr_str = path.substr(0, pstart);
    port_str = path.substr(pstart + 1, plen);

    if (pend != path.npos)
      opts_str = path.substr(pend + 1, path.npos);
  }

  char *endp;
  listen_opts.port = strtol(port_str.c_str(), &endp, 10);
  if (*endp || listen_opts.port < 0 ||
      listen_opts.port > std::numeric_limits<uint16_t>::max())
    return make_error(util::fmt("bad port '%s'", port_str.c_str()));

  if (listen_opts.af == AF_INET) {
    if (inet_pton(listen_opts.af, addr_str.c_str(),
                  &listen_opts.addr.v4.sin_addr) != 1)
      return make_error(util::fmt("bad IPv4 address '%s'", addr_str.c_str()));

    listen_opts.addr.v4.sin_family = AF_INET;
    listen_opts.addr.v4.sin_port = htons(listen_opts.port);

  } else {
    if (inet_pton(listen_opts.af, addr_str.c_str(),
                  &listen_opts.addr.v6.sin6_addr) != 1)
      return make_error(util::fmt("bad IPv6 address '%s'", addr_str.c_str()));

    listen_opts.addr.v6.sin6_family = AF_INET6;
    listen_opts.addr.v6.sin6_port = htons(listen_opts.port);
  }

  // Parse the generic options into kv_opts.
  size_t prev_pos = 0;
  size_t pos = 0;
  while (pos < opts_str.size()) {
    pos = opts_str.find('&', pos + 1);
    std::string kv = opts_str.substr(prev_pos, pos - prev_pos);

    auto pos_eq = kv.find('=');
    if (pos_eq == kv.npos)
      return make_error(util::fmt("missing = in option: '%s'", kv.c_str()));

    std::string k = kv.substr(0, pos_eq);
    std::string v = kv.substr(pos_eq + 1);

    if (kv_opts.contains(k))
      return make_error(util::fmt("duplicate option: '%s'", kv.c_str()));

    kv_opts[k] = v;

    prev_pos = pos + 1;
  }

  // Default to VXLAN + DLT_EN10MB, but allow to override with encap=geneve
  // and link_type=DLT_RAW or something like that.
  EncapOptions encap_opts{
      .encap = Encapsulation::VXLAN,
      .link_type = DLT_EN10MB,
  };

  for (const auto &[k, v] : kv_opts) {

    if (k == "encap") {
      if (v == "raw") {
        encap_opts.encap = Encapsulation::RAW;
      } else if (v.starts_with("skip:")) {

        // Hand parsing of skip:8 or skip:16
        auto cpos = v.find(':');
        auto digits = v.substr(cpos + 1);

        if (digits.empty() ||
            !std::all_of(digits.begin(), digits.end(), isdigit))
          return make_error(util::fmt("invalid skip encap: '%s'", v.c_str()));

        encap_opts.encap = Encapsulation::SKIP;
        encap_opts.skip_bytes = strtoul(digits.c_str(), nullptr, 10);
        UDPSOURCE_DEBUG("skip encap with skip_bytes=%zu",
                        encap_opts.skip_bytes);

      } else if (v == "vxlan") {
        encap_opts.encap = Encapsulation::VXLAN;
      } else if (v == "geneve") {
        encap_opts.encap = Encapsulation::GENEVE;
      } else {
        return make_error(util::fmt("invalid encap option: '%s'", v.c_str()));
      }
    } else if (k == "link_type") {
      if (v == "DLT_EN10MB") {
        encap_opts.link_type = DLT_EN10MB;
      } else if (v == "DLT_RAW") {
        encap_opts.link_type = DLT_RAW; // IP directly.
      } else {
        return make_error(
            util::fmt("invalid link_type option: '%s'", v.c_str()));
      }
    } else {
      return make_error(
          util::fmt("invalid option: '%s=%s'", k.c_str(), v.c_str()));
    }
  }

  return {"", listen_opts, encap_opts, std::move(kv_opts)};
}

} // namespace zeek::packetsource::udp
