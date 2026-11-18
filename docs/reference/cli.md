# Flags

<!-- Generated from the code by `go test ./cmd/ipv6disc -update`: edit it, not this page. -->

| Flag | Default | |
|---|---|---|
| `-exclude_interfaces` | - | No local discovery on these interfaces, comma separated: names, or patterns as docker*,veth* |
| `-interfaces` | - | The local discovery only on these interfaces, comma separated: names, or patterns as en*. Without it: all |
| `-ipv4` | `false` | Discover IPv4 addresses: the plugins read their routers' ARP tables too |
| `-ipv4_active` | `true` | IPv4: sweep the local subnets, which broadcasts an ARP request for each address |
| `-ipv4_lifetime` | - | IPv4: how long an address stays after it was last seen, in place of -lifetime |
| `-ipv4_listen` | `true` | IPv4: read the kernel's neighbor table |
| `-ipv6` | `true` | Discover IPv6 addresses |
| `-ipv6_active` | `true` | IPv6: probe the links, by multicast ping, SSDP and WS-Discovery |
| `-ipv6_lifetime` | - | IPv6: how long an address stays after it was last seen, in place of -lifetime |
| `-ipv6_listen` | `true` | IPv6: listen for NDP and the discovery protocols on the interfaces |
| `-lifetime` | `4h0m0s` | How long an address stays after it was last seen |
| `-live` | `false` | Show the state in the terminal, updating, instead of the log |
| `-log_level` | `info` | The logging level: debug, info, warn, error |
| `-plugin` | - | A plugin, name=type:params, as docs/reference/plugins.md says. Given several times, several plugins |
| `-rediscover` | - | How often the active discovery probes every host. Without it: a third of the shortest lifetime of the families that probe |

The names from before still work, with a warning: `-discovery-active`, `-discovery-listen`, `-exclude-interfaces`, `-ipv4-active`, `-ipv4-lifetime`, `-ipv4-listen`, `-ipv6-active`, `-ipv6-lifetime`, `-ipv6-listen`.
