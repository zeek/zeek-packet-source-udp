#include "packet_source_options.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <limits>

#include <pcap/dlt.h>
#include <zeek/util.h>

namespace {

using namespace zeek::packetsource::udp;

std::tuple<std::string, ListenOptions, EncapOptions>
make_error(std::string error) {
  return {error, {}, {}};
}

} // namespace

namespace zeek::packetsource::udp {

std::tuple<std::string, ListenOptions, EncapOptions>
parse_interface_path(const std::string &path) {
  std::string port_str;
  std::string opts_str; // Colon (:) separated options after the port
  ListenOptions lopts;
  EncapOptions eopts;

  // path is supposed to be look like
  //
  //     <addr>:<port>[:option1[=value1][:option2[=value2]]
  //
  // with IPv6 being surrounded with brackets like in Zeek script, so an IPV6
  // listen address needs to start with `[`.
  auto bopen = path.find('[');
  auto bclose = path.find(']');

  if (bopen == 0 && bclose != path.npos) {
    // Assume IPv6 address.
    lopts.af = AF_INET6;
    auto pstart = path.find(':', bclose);
    if (pstart == path.npos)
      return make_error(util::fmt("missing port in path '%s'", path.c_str()));

    auto pend = path.find(':', pstart + 1);
    auto addr_str = path.substr(bopen + 1, bclose - bopen - 1);
    port_str = path.substr(pstart + 1,
                           pend != path.npos ? (pend - pstart - 1) : path.npos);

    if (pend != path.npos)
      opts_str = path.substr(pend + 1, path.npos);

    if (inet_pton(AF_INET6, addr_str.c_str(), &lopts.addr.v6.sin6_addr) != 1)
      return make_error(
          util::fmt("bad IPv6 listen address '%s'", addr_str.c_str()));

  } else {
    lopts.af = AF_INET;
    auto pstart = path.find(':');
    if (pstart == path.npos)
      return make_error(util::fmt("missing port in path '%s'", path.c_str()));

    auto pend = path.find(':', pstart + 1);
    auto plen =
        pend == path.npos ? (path.size() - pstart - 1) : (pend - (pstart + 1));
    auto addr_str = path.substr(0, pstart);
    port_str = path.substr(pstart + 1, plen);

    if (pend != path.npos)
      opts_str = path.substr(pend + 1, path.npos);

    if (inet_pton(AF_INET, addr_str.c_str(), &lopts.addr.v4.sin_addr) != 1)
      return make_error(
          util::fmt("bad IPv4 listen address '%s'", addr_str.c_str()));
  }

  char *endp;
  lopts.port = strtol(port_str.c_str(), &endp, 10);
  if (*endp || lopts.port <= 0 ||
      lopts.port > std::numeric_limits<uint16_t>::max())
    return make_error(util::fmt("bad port '%s'", port_str.c_str()));

  // Set the port according to the selected family.
  if (lopts.af == AF_INET6) {
    lopts.addr.v6.sin6_family = AF_INET6;
    lopts.addr.v6.sin6_port = htons(lopts.port);
  } else {
    lopts.addr.v4.sin_family = AF_INET;
    lopts.addr.v4.sin_port = htons(lopts.port);
  }

  // Now parse any following options.
  size_t prev_pos = 0;
  size_t pos = 0;
  while (pos < opts_str.size()) {
    pos = opts_str.find(':', pos + 1);
    std::string opt_str = opts_str.substr(prev_pos, pos - prev_pos);

    if (opt_str == "raw") {
      if (eopts.encap != Encapsulation::UNSET)
        return make_error(util::fmt(
            "encapsulation already set - unexpected '%s'", opt_str.c_str()));

      // Raw is just the same as skip:0.
      eopts.encap = Encapsulation::SKIP;
      eopts.skip_bytes = 0;
    } else if (opt_str.starts_with("skip")) {
      if (eopts.encap != Encapsulation::UNSET || eopts.skip_bytes >= 0)
        return make_error(util::fmt(
            "encapsulation already set - unexpected '%s'", opt_str.c_str()));

      // Parsing of skip:<offset> (skip:8, skip:16, ...)
      auto cpos = opt_str.find('=');
      auto digits = opt_str.substr(cpos + 1);

      if (digits.empty() || !std::all_of(digits.begin(), digits.end(), isdigit))
        return make_error(util::fmt("invalid skip: '%s'", opt_str.c_str()));

      eopts.encap = Encapsulation::SKIP;
      eopts.skip_bytes = strtol(digits.c_str(), nullptr, 10);

    } else if (opt_str == "vxlan") {
      if (eopts.encap != Encapsulation::UNSET)
        return make_error(util::fmt(
            "encapsulation already set - unexpected '%s'", opt_str.c_str()));

      eopts.encap = Encapsulation::VXLAN;
    } else if (opt_str == "geneve") {
      if (eopts.encap != Encapsulation::UNSET)
        return make_error(util::fmt(
            "encapsulation already set - unexpected '%s'", opt_str.c_str()));

      eopts.encap = Encapsulation::GENEVE;
    } else {
      // No encapsulation, check for supported link types.

      if (eopts.link_type >= 0)
        return make_error(util::fmt(
            "data link_type already set - unexpected '%s'", opt_str.c_str()));

      static const struct LinkTypeOption {
        std::string name;
        int value;
      } link_type_options[] = {
          {"dlt=en10mb", DLT_EN10MB},
          {"dlt=raw", DLT_RAW},
          {"dlt=ppp", DLT_PPP},
      };

      bool found = false;
      for (const auto &[name, value] : link_type_options) {
        if (name == opt_str) {
          eopts.link_type = value;
          found = true;
        }
      }

      if (!found) {
        return make_error(util::fmt("invalid option: '%s'", opt_str.c_str()));
      }
    }

    prev_pos = pos + 1;
  }

  // Default to VXLAN with DLT_EN10MB
  if (eopts.encap == Encapsulation::UNSET)
    eopts.encap = Encapsulation::VXLAN;

  if (eopts.link_type < 0)
    eopts.link_type = DLT_EN10MB;

  return {"", lopts, eopts};
}

//
// Poor man's unit testing of the path parsing functionality. This runs
// during every InitPostScript(). It's fast enough.
//
namespace {
int failed_assertions = 0;
}

#define myassert(cond, ...)                                                    \
  if (!(cond)) {                                                               \
    fprintf(stderr, "%s:%d: ", __FILE__, __LINE__);                            \
    fprintf(stderr, __VA_ARGS__);                                              \
    fprintf(stderr, "\n");                                                     \
    ++failed_assertions;                                                       \
  }

void test_parse_interface_path() {
  {
    // Defaults, IPv4.
    auto [error, lopts, eopts] = parse_interface_path("127.0.0.1:4789");
    myassert(error.empty(), "unexpected error");
    myassert(lopts.af == AF_INET, "bad af");
    myassert(lopts.port == 4789, "wrong port");
    myassert(eopts.encap == Encapsulation::VXLAN, "wrong encap");
    myassert(eopts.link_type == DLT_EN10MB, "wrong link_type");
  }

  {
    // Geneve with IPv6.
    auto [error, lopts, eopts] = parse_interface_path("[::1]:6081:geneve");
    myassert(error.empty(), "unexpected error");
    myassert(lopts.af == AF_INET6, "bad af");
    myassert(lopts.port == 6081, "wrong port");
    myassert(eopts.encap == Encapsulation::GENEVE, "wrong encap");
    myassert(eopts.link_type == DLT_EN10MB, "wrong link_type");
  }

  {
    // Defaults with DLT_RAW
    auto [error, lopts, eopts] = parse_interface_path("[::1]:4711:dlt=raw");
    myassert(error.empty(), "unexpected error");
    myassert(lopts.af == AF_INET6, "bad af");
    myassert(lopts.port == 4711, "wrong port");
    myassert(eopts.encap == Encapsulation::VXLAN, "wrong encap");
    myassert(eopts.link_type == DLT_RAW, "wrong link_type");
  }

  {
    // Raw is skip=0 and DLT_RAW.
    auto [error, lopts, eopts] = parse_interface_path("[::1]:4711:raw:dlt=raw");
    myassert(error.empty(), "unexpected error");
    myassert(lopts.af == AF_INET6, "bad af");
    myassert(lopts.port == 4711, "wrong port");
    myassert(eopts.encap == Encapsulation::SKIP, "wrong encap");
    myassert(eopts.skip_bytes == 0, "wrong skip bytes");
    myassert(eopts.link_type == DLT_RAW, "wrong link_type");
  }

  {
    // Custom skip and DLT_PPP
    auto [error, lopts, eopts] =
        parse_interface_path("[::1]:4711:skip=13:dlt=ppp");
    myassert(error.empty(), "unexpected error");
    myassert(lopts.af == AF_INET6, "bad af");
    myassert(lopts.port == 4711, "wrong port");
    myassert(eopts.encap == Encapsulation::SKIP, "wrong encap");
    myassert(eopts.skip_bytes == 13, "wrong skip bytes");
    myassert(eopts.link_type == DLT_PPP, "wrong link_type");
  }

  {
    // Missing port IPv4
    auto [error, lopts, eopts] = parse_interface_path("127.0.0.1");
    myassert(!error.empty(), "no error for missing port");
    myassert(error == "missing port in path '127.0.0.1'", "wrong error %s",
             error.c_str());
  }

  {
    // Missing port IPv4 2
    auto [error, lopts, eopts] = parse_interface_path("127.0.0.1:");
    myassert(!error.empty(), "no error for missing port");
    myassert(error == "bad port ''", "wrong error %s", error.c_str());
  }

  {
    // Missing port IPv6
    auto [error, lopts, eopts] = parse_interface_path("[::1]");
    myassert(!error.empty(), "no error for missing port");
    myassert(error == "missing port in path '[::1]'", "wrong error %s",
             error.c_str());
  }

  {
    // Missing port IPv6 2
    auto [error, lopts, eopts] = parse_interface_path("[::1]:");
    myassert(!error.empty(), "no error for missing port");
    myassert(error == "bad port ''", "wrong error %s", error.c_str());
  }

  {
    // Bad IPv4
    auto [error, unused1, unused2] = parse_interface_path("192.168.300:1:4711");
    myassert(!error.empty(), "no error for invalid IPv6");
    myassert(error == "bad IPv4 listen address '192.168.300'", "wrong error %s",
             error.c_str());
  }

  {
    // Bad IPv6
    auto [error, unused1, unused2] = parse_interface_path("[scramble]:4711");
    myassert(!error.empty(), "no error");
    myassert(error == "bad IPv6 listen address 'scramble'", "wrong error %s",
             error.c_str());
  }

  {
    // Bad port -1
    auto [error, unused1, unused2] = parse_interface_path("[::1]:-1");
    myassert(!error.empty(), "no error for port -1");
    myassert(error == "bad port '-1'", "wrong error %s", error.c_str());
  }

  {
    // Bad port 0
    auto [error, unused1, unused2] = parse_interface_path("[::1]:0");
    myassert(!error.empty(), "no error for port 0");
    myassert(error == "bad port '0'", "wrong error %s", error.c_str());
  }

  {
    // Bad port 2**16
    auto [error, unused1, unused2] =
        parse_interface_path("[::1]:65536"); // one too large
    myassert(!error.empty(), "no error for port 2**16");
    myassert(error == "bad port '65536'", "wrong error %s", error.c_str());
  }

  {
    // Double encap
    auto [error, unused1, unused2] =
        parse_interface_path("[::1]:4879:vxlan:geneve"); // one too large
    myassert(!error.empty(), "no error for vxlan:geneve");
    myassert(error == "encapsulation already set - unexpected 'geneve'",
             "wrong error %s", error.c_str());
  }

  {
    // Double skip
    auto [error, unused1, unused2] =
        parse_interface_path("[::1]:4879:skip=0:skip=4"); // one too large
    myassert(!error.empty(), "no error for skip=0:skip=4");
    myassert(error == "encapsulation already set - unexpected 'skip=4'",
             "wrong error %s", error.c_str());
  }

  {
    // Double link type
    auto [error, unused1, unused2] =
        parse_interface_path("[::1]:4879:dlt=raw:dlt=en10mb"); // one too large
    myassert(!error.empty(), "no error for DLT_RAW:DLT_EN10MB");
    myassert(error == "data link_type already set - unexpected 'dlt=en10mb'",
             "wrong error %s", error.c_str());
  }

  if (failed_assertions > 0) {
    std::fprintf(stderr, "%d failed assertions\n", failed_assertions);
    std::exit(1);
  }
}

} // namespace zeek::packetsource::udp
