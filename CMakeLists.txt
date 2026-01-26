cmake_minimum_required(VERSION 3.15)

include(cmake/bootstrap.cmake)

project(Plugin)

# TODO: Properly find liburing.h and luring.

include(ZeekPlugin)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)
string(REGEX REPLACE "[.-]" " " version_numbers ${VERSION})
separate_arguments(version_numbers)
list(GET version_numbers 0 VERSION_MAJOR)
list(GET version_numbers 1 VERSION_MINOR)
list(GET version_numbers 2 VERSION_PATCH)

zeek_add_plugin(
  Zeek
  PacketSourceUDP
  SOURCES
  src/plugin.cc
  src/packet_source.cc
  src/packet_source_options.cc
  src/packet_receiver_recvmmsg.cc
  src/packet_receiver_io_uring.cc
  BIFS
  src/packet_source_udp.bif
  DEPENDENCIES
  uring  # XXX
)

set_source_files_properties(
  src/plugin.cc
  PROPERTIES
    COMPILE_DEFINITIONS
    "VERSION_MAJOR=${VERSION_MAJOR};VERSION_MINOR=${VERSION_MINOR};VERSION_PATCH=${VERSION_PATCH}"
)
