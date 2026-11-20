# Discovery

Discovery finds addresses and the MAC that has each: a host is its MAC, which doesn't change when its addresses do. Each address is kept for its lifetime after it was last seen.

## Families and ways

Each family, IPv6 and IPv4, is discovered the same ways, each of which can be turned off. IPv6 is on by default, IPv4 off.

| | IPv6 (`-ipv6`) | IPv4 (`-ipv4`) |
|---|---|---|
| **[Plugins](plugins.md)** | The routers' IPv6 neighbor tables | Their ARP tables |
| **Listen** (`-ipv6_listen`, `-ipv4_listen`) | NDP on each link, and the answers of the probes | The kernel's neighbor table: netlink on Linux, `arp -an` on macOS and the BSDs; on Windows and Solaris, which have neither, this machine's own addresses only |
| **Active** (`-ipv6_active`, `-ipv4_active`): probing every host | Multicast ping, SSDP and WS-Discovery | A sweep: a UDP packet to the discard port of each address of the local subnets, a /22 at most or the /24 of the address, so the kernel resolves each host. It needs no privilege, but broadcasts an ARP request for each address |
| **Solicit**: asking given hosts, from the library | `Worker.Solicit`: a neighbor solicitation for an address | `Worker.SolicitIPv4`: ARP requests to a MAC alone |
| **Lifetime** (`-ipv6_lifetime`, `-ipv4_lifetime`) | How long an address stays after it was last seen | The same |

Active probing needs listening, which reads the answers: without it, nothing is probed.

### IPv6

On each interface with an IPv6 address that isn't link-local, it listens for NDP, on each such address; an interface with only a link-local address is not listened on. There, every neighbor advertisement and solicitation tells an address and its MAC. The probes, multicast ping, SSDP M-SEARCH and WS-Discovery Probe, make the hosts answer, and each address that answers is asked its MAC with a neighbor solicitation. Before an address the local discovery found expires, it is pinged three times, so a host still there keeps it; one only a plugin found isn't. Whichever listener of the interface is running then sends the ping, also for an address a plugin found first. Each interface takes only the packets that came in on it: its sockets, bound to its address, hear on Linux the multicast NDP of the other interfaces too, and the answers of hosts routed in through another, as Docker's bridges do on a machine whose networks they route. Where the system doesn't tell the interface of a packet, as on Windows, an interface's listeners take the others' packets too.

An NDP message whose hop limit isn't 255 is ignored, as RFC 4861 requires: a router lowers it, so it is the only proof that the message comes from the link and not from a host elsewhere, sent to the address listened on. A solicitation from the unspecified address, of duplicate address detection, tells no host.

### IPv4

Every minute, it reads the kernel's neighbor table: on Linux, the entries confirmed recently, as a stale one may be a host that left; elsewhere, those not expired. The table's entries of the broadcast addresses and of the multicast groups, which macOS lists as any neighbor, are no hosts. The sweep, every `-rediscover`, has the kernel resolve every address of the subnets, so the hosts that sent nothing are in the table too. On Linux an entry counts as confirmed for 15 to 45 seconds only, the kernel's `base_reachable_time`, so the table is read right after each sweep as well.

### This machine's own addresses

The addresses of the interfaces discovery runs on are registered too, with the interface's MAC, and marked as this machine's: `(this host)` in `-live`. On Linux, those the kernel made as temporary IPv6 privacy addresses are marked so, `(this host, temporary)`: they change every day or so. They are registered while the family listens, and refreshed well within their lifetime, whatever `-rediscover` is, for as long as the system has them: IPv6 ones every third of the lifetime at most, IPv4 ones every minute. One its interface no longer has, as a prefix that went or a temporary address replaced, leaves the state when the interfaces are next looked at, every minute, not a lifetime later: `host removed` in the log. An address that moves to another interface, as to a bridge, an interface made again, and one whose MAC changed, are followed the same: the discovery stops on the old and starts on the new. Where the system has no neighbor table to read, as on Windows, IPv4 listening still registers this machine's own IPv4 addresses: only the neighbors are missing.

## Solicitation

Some addresses are never seen without asking: a host's stable IPv6 address, as it sends from temporary ones, or the IPv4 address of a host that sends nothing. The library asks given hosts:

- `Worker.Solicit(addr)` sends a neighbor solicitation for an IPv6 address, on the links whose /64 it is in.
- `Worker.SolicitIPv4(ctx, targets)` asks each target MAC, with ARP requests sent to it alone, for the addresses of the local subnets within its prefixes, up to 4096 nearest the local address, or without prefixes those a sweep would ask. With prefixes, it asks on every interface with a subnet they cover, wherever the MAC was seen: a host heard over IPv6 on one interface can have its IPv4 address on another, as two networks of one wire. Without, it asks on the interfaces the local discovery saw the MAC on, or on all of them when it saw it on none. Nothing is broadcast, though a switch that no longer knows where the MAC is floods the requests, as any frame to it. It needs Linux and `CAP_NET_RAW`.

An address that answers is registered as any other.

## Interfaces

The local discovery runs on every interface that is up, not a loopback and has a MAC, with multicast for IPv6, with broadcast for IPv4, unless `-interfaces` names those it runs on, and `-exclude_interfaces` those it doesn't: names, or patterns as `docker*,veth*`. On a host running containers, leaving their bridges out keeps the containers out of the state, and the probes off their networks. The plugins aren't concerned. The interfaces without a MAC, as PPP links and tunnels, are left out, and their own addresses not registered: a host is its MAC, and NDP tells none there.

The interfaces and their addresses are looked at every minute. An address that moved to another interface, or whose interface was made again, is listened on anew there.

## Privileges

| | Needs |
|---|---|
| IPv6 listening and probing, `Worker.Solicit` | Root, or `CAP_NET_RAW`: raw ICMPv6 sockets |
| IPv4 listening, the sweep | Nothing |
| `Worker.SolicitIPv4` | Linux, and root or `CAP_NET_RAW`: raw ARP |
| The plugins | Nothing, but the network to reach their host |

In Docker, the local discovery needs the host's network, `--network host`, which Docker Desktop on macOS and Windows doesn't give: there, only the plugins find hosts. `NET_RAW` is granted by default. On Windows, the IPv6 listener has been seen to miss NDP packets: prefer the plugins there. On Solaris there is no `-live`.

## Lifetimes and probing

An address stays for its family's lifetime, `-ipv6_lifetime` or `-ipv4_lifetime`, `-lifetime` without, after it was last seen by anything: the local discovery or a plugin. The active discovery probes again every `-rediscover`, by default a third of the shortest lifetime of the families that probe, so a quiet host is probed before it expires.

Two settings are accepted but lose hosts that are there, and are warned of at start: a `-rediscover` not shorter than the lifetime of a family that probes, as the hosts that stay quiet expire between probes; and, with IPv4 listening, an IPv4 lifetime of a minute or less, as the neighbor table is read every minute. `DefaultConfig` leaves `Rediscover` zero, so that it follows a `Lifetime` changed afterwards.
