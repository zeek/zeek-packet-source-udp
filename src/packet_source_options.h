/**
 * Data structures and a parse_interface_path() function to work with the
 * interface path provided by a user to the -i flag after the udp:: string.
 *
 * This supports the following style. The address and port are always
 * required, subsequent options are separated by colons. The assumption is
 * options do not contain any colons themselves and that we won't have a ton
 * of options going forward. Otherwise fork this repo.
 *
 *   127.0.0.1:4789
 *   [::1]:4789
 *   127.0.0.1:4789:VXLAN:DLT_EN10MB (explicit default values)
 *   [::1]:6081:GENEVE
 *   127.0.0.1:6081:GENEVE:DLT_RAW
 *
 * The offset for the skip option comes after an equals sign.
 *
 *   127.0.0.1:4789:SKIP=8:DLT_RAW
 *
 * Some other options (socket and buffer sizes) are configurable const &redef
 * variables rather than via the path.
 */
#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/dlt.h>
#include <string>
#include <sys/socket.h>
#include <tuple>

namespace zeek::packetsource::udp {

/**
 * Configuration for the listening socket.
 */
struct ListenOptions {
  int af = -1;
  union {
    sockaddr_in v4;
    sockaddr_in6 v6;
  } addr = {0};
  int port = -1;
};

/**
 * The supported encapsulations.
 */
enum class Encapsulation {
  UNSET,
  SKIP,
  VXLAN,
  GENEVE,
  GENEVE_VXLAN, // Outer layer GENEVE, then IP/UDP+VXLAN containing the mirrored
                // packet. There is no ethernet header after GENEVE!
};

/**
 * Expected encapsulation options.
 */
struct EncapOptions {
  Encapsulation encap = Encapsulation::UNSET;
  int link_type = -1;
  int skip_bytes = -1;
};

/**
 * Parse an interface path for the packet source.
 *
 * @param path
 *
 * @return A tuple <error_msg, listen_opts, encap_opts>
 *
 * If error_msg is not empty, parsing failed and the string describes the issue.
 */
std::tuple<std::string, ListenOptions, EncapOptions>
parse_interface_path(const std::string &path);

void test_parse_interface_path();

} // namespace zeek::packetsource::udp
