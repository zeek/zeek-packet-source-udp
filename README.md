# Zeek Packet Source UDP

> An opinionated Zeek packet source for the cloud.

This is a [Zeek](https://github.com/zeek/zeek) packet source plugin consuming
live packet input via UDP traffic mirroring tunnels like GENEVE or VXLAN.

In contrast to a classic packet source which usually reads raw packets off an
interface using [libpcap](https://github.com/the-tcpdump-group/libpcap) or
specialized capture libraries, this packet source is meant to be used in
environments where monitoring traffic reaches Zeek exclusively via UDP based
tunnels like VXLAN or GENEVE. This is often the case in cloud environments.
For example, this is true for [AWS Traffic Mirroring](https://docs.aws.amazon.com/vpc/latest/mirroring/what-is-traffic-mirroring.html)
and [GCP Network Security Integration](https://cloud.google.com/blog/products/networking/introducing-network-security-integration).

## Idea

The conceptual idea of this plugin is to make Zeek a high-performance UDP packet
receiver ingesting mirrored traffic. In other words, Zeek terminates the UDP
tunnel itself by listening on the appropriate port, rather than sniffing
packets from an interface.

This avoids headaches around accessing host interfaces in container environments.
Indeed, this packet source allows Zeek to run completely unprivileged. It only
receives packets from non-privileged UDP ports. In other words, this side-steps
any requirements for privileges, CAP_NET_RAW capability, or tricky interface
configuration that can be a burden in cloud environments.

The VXLAN and GENEVE encapsulation layers are currently stripped and only the
contained packet data forwarded to Zeek. For monitoring a single VPC, this should be
sufficient. If these layers aren't stripped, Zeek would track and log the mirroing
tunnel connections itself, too, something that usually isn't that useful.

A future extension planned is to expose the tunnel VNIs and options of the
encapsulation headers using a custom ConnKey plugin as sketched in
[Zeek's plugin documentation for ConnKeys](https://docs.zeek.org/en/master/devel/plugins/connkey-plugin.html).


## Performance and Scaling

This packet source provides two implementations for the UDP receiver. One is
based on the ``recvmmsg()`` syscall and should work on Linux and probably FreeBSD,
the other implementation is based on [liburing](https://github.com/axboe/liburing) and
requires a modern Linux kernel (6.1+, tested on Ubuntu 24.04, with 6.4.0).

The implementation to use can be selected via:

```
redef PacketSource::UDP::implementation = PacketSource::UDP = RECVMMSG;  # default
redef PacketSource::UDP::implementation = PacketSource::UDP = IO_URING;
```

Per-packet timestamps are requested using the socket option ``SO_TIMESTAMP`` and
received as [cmsg](https://man7.org/linux/man-pages/man3/cmsg.3.html) auxiliary data.

For load balancing across multiple processes, the [SO_REUSEPORT](https://lwn.net/Articles/542629/)
feature of the Linux kernel is used. FreeBSD has this as well, but this isn't tested
and might need a bit of porting. That is, multiple Zeek worker processes will
listen on the same UDP port and the Linux kernel will do flow-balancing on the most
outer IP/UDP header across all the UDP sockets. As long as mirrored traffic uses a
consistent and bi-directional / symmetric hash of the inner flow for the outer UDP
source port, as suggested in [RFC 8926, Section 3.3 (GENEVE)](https://datatracker.ietf.org/doc/html/rfc8926#name-udp-header)
or [RFC 7348, Section 5 (VXLAN)](https://datatracker.ietf.org/doc/html/rfc7348#section-5),
this should result in decent and reliable flow-balancing across Zeek's worker
processes.


## Build and Install

This plugin does not contain a configure script, use ``cmake`` directly:

    $ mkdir build && cd build && cmake ../ && make && make install

You may also use ``zkg`` to install this plugin.

    $ zkg install zeek-packet-source-udp

## How to Run

Use ``-i`` as usual. Instead of passing an interface name, however, pass something
like: ``udp::<listen_addr>:<listen_port>?encap=<encap>&link_type=<link_type>``.

The encapsulation defaults to VXLAN, the link type to DLT_EN10MB and so these
can be left out for simple testing:

    $ zeek -i udp::127.0.0.1:4789

## Running with systemd

If a single host deployment is sufficient for your purposes and you have Zeek 8.1
available, ensure the [zeek-systemd-generator](https://github.com/zeek/zeek/tree/master/tools/systemd-generator)
executable is linked into one of systemd's generator directories and put the
following lines into ``<PREFIX>/etc/zeek/zeek.conf``:

    interface = udp::127.0.0.1:4789?encap=vxlan
    workers = 4

Run the following command to startup Zeek with 4 workers listening for VXLAN
encapsulated traffic:

    systemctl daemon-reload && systemctl restart zeek.target

Logs should appear in ``<PREFIX>/spool/zeek/logger-1/`` and rotated into
``<PREFIX>/var/zeek/logs/``.

## Supported Encapsulations

The ``encap`` option can be set to one of:

* vxlan
* geneve
* raw
* skip:<offset>

The VXLAN or GENEVE header is stripped and the inner packet and its timestamp
passed to Zeek via the``zeek::Packet`` data structure. The ``raw`` encapsulation
takes the UDP payload and passes it as packet payload without stripping any headers.
A last encapsulation is ``skip:<offset>`` which allows to skip a fixed number of
bytes into the UDP payload. This can be useful for unsupported encapsulations
with fixed header sizes. For example, ``vxlan`` and ``skip:8`` behave identically,
except for ``vxlan`` potentially extracting the VNI in the future.

## Supported Link Types

The link type defaults to ``DLT_EN10MB,`` but can be set to ``DLT_RAW`` in case
there's no L2 header and instead IPv4 or IPv6 packets follow immediately. If
you need more, patches are welcome.

## Tuning and Monitoring

Dropped UDP packets can easily be observed with default settings. Minimally
ensure the receive buffers are large enough (the plugin uses 16MB by default).

There's also various other places where UDP packets might get dropped. You'll
usually see this in increased capture loss or ``gG`` or ``tT`` in Zeek's
[connection history](https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html#field-Conn::Info$history).

A few pointers for a Linux system:

Check for UDP receive errors:

    $ netstat -suna | grep errors

Check for softnet errors:

    $ cat /proc/net/softnet_stat

Check and increase receive buffers (32MB might be a good start):

    $ sysctl -a -r '^net.core.[rw]mem'
    net.core.rmem_default = 33554432
    net.core.rmem_max = 33554432
    net.core.wmem_default = 33554432
    net.core.wmem_max = 33554432

Check and increase netdev_max_backlog:

    $ sysctl -a -r net.core.netdev_max_backlog
    net.core.netdev_max_backlog = 1000
    $ sysctl -w net.core.netdev_max_backlog=10000

## Requirements on the Packet Mirroring Infrastructure

As mentioned above, this packet source plugin is sensitive to the values used
for the most outer UDP ports. The UDP source port should represent a sticky
and symmetric flow hash (both directions have the same flow hash)
of transported flow. AWS's GWLB, for example, [works this way](https://aws.amazon.com/blogs/networking-and-content-delivery/integrate-your-custom-logic-or-appliance-with-aws-gateway-load-balancer/). The destination port should be the same for all mirrored
packets.

Packet reordering upstream (before reaching the system running Zeek), or
within the OS kernel are possible. Using a raw interface for sniffing cannot
alleviate packet reordering from the upstream.
If you observe packet reordering happening in the Linux network stack, you'll
need to dig, tune your system and potentially debug the kernel.
