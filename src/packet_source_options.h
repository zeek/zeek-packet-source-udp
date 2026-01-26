/**
 * Data structures and code for parsing the interface path string.
 *
 * The path can be any of the following styles - additional options (encap,
 * link_type) are passed as query parameters.
 *
 *  127.0.0.1:4789
 *  [::1]:4789
 *  [::1]:6081?encap=geneve
 *  127.0.0.1:6081?encap=geneve?link_type=DLT_RAW
 *
 * Some other options (socket and buffer sizes) are configurable const &redef
 * variables rather than via the path.
 */
#pragma once

#include <arpa/inet.h>
#include <map>
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
  RAW,
  SKIP,
  VXLAN,
  GENEVE,
};

/**
 * Expected encapsulation options.
 */
struct EncapOptions {
  Encapsulation encap;
  int link_type;
  size_t skip_bytes = 0;
};

/**
 * Generic key value options to pass to the receiver.
 *
 * Can be used for receive buffer configuration and stuff.
 */
using KeyValueOptions = std::map<std::string, std::string>;

/**
 * Parse an interface path for the packet source.
 *
 * @param path
 *
 * @return A tuple <error_msg, listen_opts, encap_opts, kv_opts>
 *
 * If error_msg is not empty, parsing failed and the string describes the issue.
 */
std::tuple<std::string, ListenOptions, EncapOptions, KeyValueOptions>
parse_interface_path(const std::string &path);

} // namespace zeek::packetsource::udp
