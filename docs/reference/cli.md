# Flags

<!-- Generated from the code by `go test ./cmd/ipv6disc -update`: edit it, not this page. -->

| Flag | Default | |
|---|---|---|
| `-exclude_interfaces` | - | No local discovery on these interfaces, comma separated: names, or patterns as docker*,veth* |
| `-hostnames` | `false` | Learn the names of the hosts: listen for mDNS, DHCP and LLDP, ask each host its name, by mDNS, NetBIOS and LLMNR, and the computers and devices that answer WS-Discovery and SSDP theirs, where the families listen, and the plugins read the names of their routers' DHCP leases |
| `-hostnames_dns` | - | DNS servers to ask the name of each address, its PTR record, comma separated, as the router's: 192.168.1.1, or with a port, 192.168.1.1:5353, [fd00::1]:53. Without it: none. Never the system's resolver |
| `-hostnames_lifetime` | - | How long a name stays after it was last said, in place of -lifetime |
| `-hostnames_protocols` | - | The names only by these protocols of the local discovery, comma separated: mdns, dns, netbios, llmnr, wsd, ssdp, dhcp, lldp. Without it: all |
| `-interfaces` | - | The local discovery only on these interfaces, comma separated: names, or patterns as en*. Without it: all |
| `-ipv4` | `false` | Discover IPv4 addresses: the plugins read their routers' ARP tables too |
| `-ipv4_active` | `true` | IPv4: sweep the local subnets, which broadcasts an ARP request for each address |
| `-ipv4_lifetime` | - | IPv4: how long an address stays after it was last seen, in place of -lifetime |
| `-ipv4_listen` | `true` | IPv4: read the kernel's neighbor table, and on Linux hear the ARP the hosts send |
| `-ipv6` | `true` | Discover IPv6 addresses |
| `-ipv6_active` | `true` | IPv6: probe the links, by multicast ping, SSDP and WS-Discovery |
| `-ipv6_lifetime` | - | IPv6: how long an address stays after it was last seen, in place of -lifetime |
| `-ipv6_listen` | `true` | IPv6: listen for NDP and the discovery protocols on the interfaces |
| `-lifetime` | `4h0m0s` | How long an address stays after it was last seen |
| `-live` | `false` | Show the state in the terminal, updating, instead of the log |
| `-log_level` | `info` | The logging level: debug, info, warn, error |
| `-plugin` | - | A plugin, name=type:params, as docs/reference/plugins.md says. Given several times, several plugins |
| `-rediscover` | - | How often the active discovery probes every host. Without it: a third of the shortest lifetime of the families that probe |

A boolean flag is turned off as `-ipv6=false`, not `-ipv6 false`: a word that is no flag, nor a flag's value, is an error.

The names from before still work, with a warning: `-discovery-active`, `-discovery-listen`, `-exclude-interfaces`, `-ipv4-active`, `-ipv4-lifetime`, `-ipv4-listen`, `-ipv6-active`, `-ipv6-lifetime`, `-ipv6-listen`.
