# Discovery

Discovery finds addresses and the MAC that has each: a host is its MAC, which doesn't change when its addresses do. Each address is kept for its lifetime after it was last seen.

## Families and ways

Each family, IPv6 and IPv4, is discovered the same ways, each of which can be turned off. IPv6 is on by default, IPv4 off.

| | IPv6 (`-ipv6`) | IPv4 (`-ipv4`) |
|---|---|---|
| **[Plugins](plugins.md)** | The routers' IPv6 neighbor tables | Their ARP tables |
| **Listen** (`-ipv6_listen`, `-ipv4_listen`) | NDP on each link, and the answers of the probes | The kernel's neighbor table: netlink on Linux, `arp -an` on macOS and the BSDs; not on Windows |
| **Active** (`-ipv6_active`, `-ipv4_active`): probing every host | Multicast ping, SSDP and WS-Discovery | A sweep: a UDP packet to the discard port of each address of the local subnets, a /22 at most or the /24 of the address, so the kernel resolves each host. It needs no privilege, but broadcasts an ARP request for each address |
| **Solicit**: asking given hosts, from the library | `Worker.Solicit`: a neighbor solicitation for an address | `Worker.SolicitIPv4`: ARP requests to a MAC alone |
| **Lifetime** (`-ipv6_lifetime`, `-ipv4_lifetime`) | How long an address stays after it was last seen | The same |

Active probing needs listening, which reads the answers: without it, nothing is probed.

### IPv6

On each interface with an IPv6 address, it listens for NDP: every neighbor advertisement and solicitation tells an address and its MAC. The probes, multicast ping, SSDP M-SEARCH and WS-Discovery Probe, make the hosts answer; a host that answers from an address whose MAC isn't known is asked it with a neighbor solicitation. Before an address expires, it is pinged three times, so a host still there keeps it.

### IPv4

Every minute, it reads the kernel's neighbor table, and keeps the entries confirmed recently: a stale one may be a host that left. The sweep, every `-rediscover`, has the kernel resolve every address of the subnets, so the hosts that sent nothing are in the table too.

## Solicitation

Some addresses are never seen without asking: a host's stable IPv6 address, as it sends from temporary ones, or the IPv4 address of a host that sends nothing. The library asks given hosts:

- `Worker.Solicit(addr)` sends a neighbor solicitation for an IPv6 address, on the links whose /64 it is in.
- `Worker.SolicitIPv4(ctx, targets)` asks each target MAC, with ARP requests sent to it alone, for the addresses of the local subnets within its prefixes, up to 4096, on the interfaces the MAC was seen on. Nothing is broadcast, though a switch that no longer knows where the MAC is floods the requests, as any frame to it. It needs Linux and `CAP_NET_RAW`.

An address that answers is registered as any other.

## Interfaces

The local discovery of both families runs on every interface that is up, unless `-interfaces` names those it runs on, and `-exclude_interfaces` those it doesn't: names, or patterns as `docker*,veth*`. On a host running containers, leaving their bridges out keeps the containers out of the state, and the probes off their networks. The plugins aren't concerned.

## Lifetimes and probing

An address stays for its family's lifetime, `-ipv6_lifetime` or `-ipv4_lifetime`, `-lifetime` without, after it was last seen by anything: the local discovery or a plugin. The active discovery probes again every `-rediscover`, by default a third of the shortest lifetime of the families that probe, so a quiet host is probed before it expires.
