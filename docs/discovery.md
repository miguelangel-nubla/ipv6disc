# Discovery

Discovery finds addresses and the MAC that has each: a host is its MAC, which doesn't change when its addresses do. Each address is kept for its lifetime after it was last seen. When asked to, it learns the [names](#names) of the hosts too.

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

Every minute, it reads the kernel's neighbor table: on Linux, the entries confirmed recently, as a stale one may be a host that left; elsewhere, those not expired. The table's entries of the broadcast addresses and of the multicast groups, which macOS lists as any neighbor, are no hosts. The sweep, before a reading of the table when `-rediscover` has passed since the last, so once a minute at most, has the kernel resolve every address of the subnets, so the hosts that sent nothing are in the table too. On Linux the table is read right after each sweep as well, once the kernel has checked the entries the sweep found stale, by the interface's own settings: `delay_first_probe_time`, then `ucast_solicit` probes `retrans_time_ms` apart, 9 seconds with the defaults. And an entry counts from when the kernel last confirmed it, which the table says: an IPv4 address stays its lifetime from then, so one of a host that left goes a lifetime after it last answered, not after a reading of the table that still had its entry, and a reading never shortens what another gave. Elsewhere an entry counts from when it is read.

### This machine's own addresses

The addresses of the interfaces discovery runs on are registered too, with the interface's MAC, and marked as this machine's: `(this host)` in `-live`. On Linux, those the kernel made as temporary IPv6 privacy addresses are marked so, `(this host, temporary)`: they change every day or so. They are registered while the family listens, and refreshed well within their lifetime, whatever `-rediscover` is, for as long as the system has them: IPv6 ones every third of the lifetime at most, IPv4 ones every minute. One its interface no longer has, as a prefix that went or a temporary address replaced, leaves the state when the interfaces are next looked at, every minute, not a lifetime later: `host removed` in the log. An address that moves to another interface, as to a bridge, an interface made again, and one whose MAC changed, are followed the same: the discovery stops on the old and starts on the new. Where the system has no neighbor table to read, as on Windows, IPv4 listening still registers this machine's own IPv4 addresses: only the neighbors are missing.

## Solicitation

Some addresses are never seen without asking: a host's stable IPv6 address, as it sends from temporary ones, or the IPv4 address of a host that sends nothing. The library asks given hosts:

- `Worker.Solicit(addr)` sends a neighbor solicitation for an IPv6 address, on the links whose /64 it is in.
- `Worker.SolicitIPv4(ctx, targets)` asks each target MAC, with ARP requests sent to it alone, for the addresses of the local subnets within its prefixes, up to 4096 nearest the local address, or without prefixes those a sweep would ask. With prefixes, it asks on every interface with a subnet they cover, wherever the MAC was seen: a host heard over IPv6 on one interface can have its IPv4 address on another, as two networks of one wire. Without, it asks on the interfaces the local discovery saw the MAC on, or on all of them when it saw it on none. Nothing is broadcast, though a switch that no longer knows where the MAC is floods the requests, as any frame to it. It needs Linux and `CAP_NET_RAW`.

An address that answers is registered as any other.

## Names

With `-hostnames`, a host has names too: what it calls itself, and what a router's DHCP server knows it by. It is off by default: without it nothing is sent for a name, no group is joined, and the plugins read no lease.

A name is the host's, its MAC's, not an address's: one learned over IPv4 is the host's for its IPv6 addresses too. A host can have several at once, when its sources disagree or it was renamed, each with what said it: `mdns`, or a plugin's name.

### Where they come from

| | |
|---|---|
| **mDNS, heard** | On each interface the local discovery runs on, for the families that listen there, it joins the groups of mDNS, 224.0.0.251 and ff02::fb, on port 5353. Whatever sends there is a host of the link, and what a host announces tells its name |
| **mDNS, asked** | A host that has no name is asked the name of one of its addresses, by a question sent to it alone |
| **[Plugins](plugins.md#names)** | The host names of the DHCP leases of their routers |

Whoever sends an mDNS message, a query or a response, from an address of the link is a host there: an address the state doesn't have yet is found as any other, by a neighbor solicitation for an IPv6 one, and for an IPv4 one by a packet to its discard port, as the sweep's, and a reading of the neighbor table a second later. With `-ipv6_active` or `-ipv4_active`, a query for `_services._dns-sd._udp.local` goes to the group at every `-rediscover`, with the other probes, so the hosts that have a service answer and are heard. It is sent from a port of its own, not from 5353: a responder then answers to that port, by unicast, so a link of many hosts answers without a multicast packet from each.

A response tells names: the name of an A or an AAAA record has that address, and so does the name the PTR record of an address's reverse name points to. But a response can carry the records of other hosts, as a sleep proxy's does, and of addresses nobody has. So a record is never taken as an address of its sender, nor registered: an address it tells, when it is of the link, is asked of the discovery, and is at whatever MAC answers for it. And a name is its sender's only by a record of the sender's own address: the one the packet came from, or another the state has at the same MAC. The other records name nobody: not their sender, nor the host of their address, which didn't say them. Messages from an address that isn't of the interface's link, a link-local one or one of a subnet the interface has an address in, are left, and so are those of this machine's own responder.

A host with no name is asked: the PTR record of the reverse name of one of its addresses, `20.1.168.192.in-addr.arpa`, sent to its port 5353 alone, from a port of its own again, where the answer comes back. That port is no group's, and what is sent to it could come from anywhere: only a response with the ID of a question sent in the last 5 seconds is taken there, the query for the services' or one of these, and anything else is left. Only a host a local interface saw is asked, at an address of that interface's link, an IPv4 one first; when it doesn't answer there, at another of its addresses the next time, and where it answered, there again. Each host is asked once in a `-rediscover` at most, and 10 hosts a second at most. It is asked again when its name has less than three rediscovery intervals left, or half its lifetime if that is less, as an address is pinged before it expires. A host whose name keeps being said, by itself or by a plugin, is never asked; nor is this machine. The questions go whatever `-ipv6_active` and `-ipv4_active` are, as the pings do: they are to one host, not a probe of all.

Port 5353 is shared with the responder of this machine, if it has one, as avahi or mDNSResponder, and with any number of instances. The socket that hears a group is bound to the group's address, so it takes nothing sent to this machine alone, which stays the responder's: on Windows, where a socket can't be bound so, it takes its share of that too. Nothing is ever sent from port 5353.

### The lifetime

A name stays for `-hostnames_lifetime`, `-lifetime` without, after it was last said, by any of its sources, and then expires by itself: a host renamed has both names until the old one does. A record that says goodbye, with a TTL of zero, takes no name away: it is left to expire. When the last address of a host expires, its names go with it. A name said of a MAC that has no address yet, as a lease of a host the neighbor table doesn't have, is kept for when it has one.

A `-hostnames_lifetime` not longer than `-rediscover` is warned of at start: a host is asked once in each, so its name expires between.

### What a name is

A name is whatever a device claims: nothing proves it, two hosts can claim the same, and anyone on the link can announce any, of itself, or of another host by sending from its address, which nothing here can tell apart: the socket has the address a packet came from, not the MAC. So a name is a hint of which host a MAC is, for someone to read, and no ground to trust the host. What is not of the link can't: a message is taken only from an address of the link, the groups don't cross a router, and what could is taken only as the answer to a question. It is made one DNS label, lower case, of letters, digits and hyphens:

- Of a dotted name, `printer.local.` or `host.domain`, the first label.
- Upper case becomes lower; an underscore or a space within, as in the `ESP_1A2B3C` that devices give their DHCP server, becomes a hyphen; the hyphens at either end are dropped.
- Anything else is no name, and is dropped, never mapped to one: an empty label, one that starts with an underscore, which is a service's, any other character, as the `*` of a lease without a name, a byte that isn't ASCII, more than 63 characters, and an IP address in place of a name.

`-live` shows the names of a host after its MAC, each with what said it. The log has `host named` when a host gets a name, with the `name`, `mac` and `source`, `host name expired` when one goes, and `host name removed` when it goes with its host.

## Interfaces

The local discovery runs on every interface that is up, not a loopback and has a MAC, with multicast for IPv6, with broadcast for IPv4, unless `-interfaces` names those it runs on, and `-exclude_interfaces` those it doesn't: names, or patterns as `docker*,veth*`. On a host running containers, leaving their bridges out keeps the containers out of the state, and the probes off their networks. The plugins aren't concerned. The interfaces without a MAC, as PPP links and tunnels, are left out, and their own addresses not registered: a host is its MAC, and NDP tells none there.

The interfaces and their addresses are looked at every minute. An address that moved to another interface, or whose interface was made again, is listened on anew there.

## Several instances

Any number of instances run at once, on one machine or on several of one link, each with its own flags, and each finds what it would alone. None listens on a port of its own choosing, so there is none to tell apart, and none takes a packet from another.

On one machine, every socket is the instance's own, but the one that hears a group of mDNS, with `-hostnames`: its port, 5353, is every instance's, and the system gives each what is sent to the group. Those of NDP and the ping are raw ICMPv6 sockets, and the system gives each of them its copy of every message; the SSDP and WS-Discovery searches leave from a port the system picks, where their answers come back; an ARP solicitation has its own socket too, and takes the answers of the host it asked. The interfaces, the families and the lifetimes are each instance's: one that leaves an interface out, or doesn't take IPv4, has nothing of them, whatever another does. Only the kernel's IPv4 neighbor table is shared: what the sweep of one resolved, another that listens for IPv4 reads too. And the answers to the multicast ping of one come to the machine's address, where the others hear them as well, as they hear the answers to any ping from the machine: each asks the MAC of those hosts, so a host is solicited once by each instance for each ping of any. It ends there, as the answer to a solicitation asks nothing more. Stopping one leaves the others as they were.

On several machines of one link, each hears some of what the others send: their neighbor solicitations, and their machine's answers. A solicitation tells the address and MAC of its sender only, never of the address it asks for, so another instance's machine is a host as any other, with its real addresses at its MAC, and is never marked as this machine's. Nothing heard from another instance makes one probe: the probes go by `-rediscover` alone, and a solicitation follows only an answer that came to this machine, which those to another's probes don't, so two instances send on the link what each sends alone. A host that leaves expires on each after its own lifetime: the probes of one don't keep it on another.

## Privileges

| | Needs |
|---|---|
| IPv6 listening and probing, `Worker.Solicit` | Root, or `CAP_NET_RAW`: raw ICMPv6 sockets |
| IPv4 listening, the sweep | Nothing |
| `Worker.SolicitIPv4` | Linux, and root or `CAP_NET_RAW`: raw ARP |
| The names: mDNS | Nothing: its sockets are UDP ones |
| The plugins | Nothing, but the network to reach their host |

In Docker, the local discovery needs the host's network, `--network host`, which Docker Desktop on macOS and Windows doesn't give: there, only the plugins find hosts. `NET_RAW` is granted by default. On Windows, the IPv6 listener has been seen to miss NDP packets: prefer the plugins there. On Solaris there is no `-live`.

## Lifetimes and probing

An address stays for its family's lifetime, `-ipv6_lifetime` or `-ipv4_lifetime`, `-lifetime` without, after it was last seen by anything: the local discovery or a plugin. The active discovery probes again every `-rediscover`, by default a third of the shortest lifetime of the families that probe, so a quiet host is probed before it expires.

A name stays for `-hostnames_lifetime`, the same way: see [names](#the-lifetime).

Two settings are accepted but lose hosts that are there, and are warned of at start: a `-rediscover` not shorter than the lifetime of a family that probes, as the hosts that stay quiet expire between probes; and, with IPv4 listening, an IPv4 lifetime of a minute or less, as the neighbor table is read every minute. `DefaultConfig` leaves `Rediscover` zero, so that it follows a `Lifetime` changed afterwards.
