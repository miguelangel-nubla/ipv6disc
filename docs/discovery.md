# Discovery

Discovery finds addresses and the MAC that has each: a host is its MAC, which doesn't change when its addresses do. Each address is kept for its lifetime after it was last seen. When asked to, it learns the [names](#names) of the hosts too.

## Families and protocols

Everything here is set in the [configuration file](reference/configuration.md), `ipv6disc -config_file discovery.yaml`; without one, every key has its default. Each family, IPv6 and IPv4, has its switches, under `ipv6` and `ipv4`: `enabled`, `listen`, `active` and its `lifetime`. IPv6 is on by default, IPv4 off.

| | `ipv6` | `ipv4` |
|---|---|---|
| **[Plugins](plugins.md)** | The routers' IPv6 neighbor tables | Their ARP tables |
| **`listen`**: the local discovery | NDP on each link, and the answers of the probes | The kernel's neighbor table: netlink on Linux, `arp -an` on macOS and the BSDs; on Windows and Solaris, which have neither, this machine's own addresses only. On Linux, the ARP the hosts send, too |
| **`active`**: probing every host | Multicast ping, SSDP and WS-Discovery | A sweep: a UDP packet to the discard port of each address of the local subnets, a /22 at most or the /24 of the address, so the kernel resolves each host. It needs no privilege, but broadcasts an ARP request for each address |
| **Solicit**: asking given hosts, from the library | `Worker.Solicit`: a neighbor solicitation for an address | `Worker.SolicitIPv4`: ARP requests to a MAC alone |
| **`lifetime`** | How long an address stays after it was last seen | The same |

Active probing needs listening, which reads the answers: without it, nothing is probed.

```yaml
ipv4:
  enabled: true
  active: false   # no sweep: nothing is broadcast
```

### Protocols

Under `protocols`, each protocol of the local discovery has its own switch, `enabled`, and its options beside it: always a mapping, never `true` or `false` alone. A protocol runs when it is enabled, and its family is, and listens, or for the sweep is active: the switches of a family are those of all its protocols at once.

| Protocol | Default | Family | Runs with | |
|---|---|---|---|---|
| `ndp` | on | IPv6 | `listen` | The neighbor discovery of each link, which tells an address and its MAC, and asks the MAC of what the others of IPv6 hear |
| `ping` | on | IPv6 | `listen` | An address is pinged before it expires. With `active`, every host is, by multicast |
| `ssdp` | on | IPv6 | `listen` | With `active`, a search for the UPnP devices, whose answers it hears. With its `names`, a device that answers is asked its [name](#fetched-from-the-hosts-that-answer-a-probe) |
| `wsd` | on | IPv6 | `listen` | With `active`, a WS-Discovery probe, which Windows and Samba answer, and it hears. With its `names`, a computer that answers is asked its [name](#fetched-from-the-hosts-that-answer-a-probe) |
| `arp` | on | IPv4 | `listen` | The kernel's neighbor table, read every minute |
| `arp-sweep` | on | IPv4 | `active` | The sweep of the subnets, of those no larger than its `max_prefix`, 22 by default |
| `arp-listen` | on, on Linux | IPv4 | `listen` | The ARP the hosts send, heard. Linux only |
| `mdns` | on | Either | `listen` | Whatever sends to the groups of [mDNS](#mdns) is a host, and what it announces its name. With `active`, a query to the group. Without its `ask`, it only listens |
| `dhcp` | on, on Linux | Either | `listen` | What the [DHCP](#heard) clients say as they ask for an address, heard. Linux only |
| `lldp` | on, on Linux | Either | `listen` | What the [LLDP](#heard) neighbor of an interface says, heard. Linux only |
| `netbios` | on | IPv4 | `listen` | A host is [asked](#asking-a-host) its NetBIOS name. Names only |
| `llmnr` | on | Either | `listen` | A host is [asked](#asking-a-host) its name by LLMNR. Names only |
| `dns` | on | None | - | Its `servers` are asked the name of each address, of the hosts the plugins found too: without, nobody is. Names only |

By default every protocol is on, with its options: `ssdp` and `wsd` fetch names, `mdns` asks. Those that hear frames, `arp-listen`, `dhcp` and `lldp`, are on where they can run, on Linux, and off elsewhere; `dns` asks only the `servers` it is given, so it runs once it has some. A protocol of either family runs on an interface over the families that listen there. A protocol that is off sends nothing, joins no group and opens no socket: the others run without it.

```yaml
ipv4:
  enabled: true
protocols:
  arp-sweep:                    # nothing broadcast
    enabled: false
  ssdp:
    enabled: false
  llmnr:                        # its questions go to every host of the link
    enabled: false
  dns:
    servers:
      - 192.168.1.1
```

What can't run is an error at start, which says what and where, not a protocol left out without a word:

- A protocol there is none of, an option its protocol doesn't have, and a value of another type than its key takes: `mdns: true` is written as `enabled: true` under `mdns`.
- `ping`, `ssdp` or `wsd` enabled without `ndp`: they hear an address, and only NDP tells its MAC, so they would find no host. And `arp-sweep` without both `arp` and `arp-listen`, which tell the hosts that answer it.
- `arp-listen`, `dhcp` or `lldp` enabled where the system can't run them, which is anywhere but Linux. They are on by default on Linux and off elsewhere, so a configuration that doesn't name them runs everywhere.
- A `max_prefix` of `arp-sweep` that is not from 16 to 30. A subnet larger than a /`max_prefix` is swept in the /24 of the interface's address only, or in the /`max_prefix` there when that is smaller.
- `hostnames: true`, or `enabled` under `hostnames`, as there were: the [names](#names) are always kept, of the protocols that learn them.

The options of a protocol that is off are not looked at. The log says at start which protocols run, `protocols of the local discovery: ndp, ping, ssdp, wsd`, and `-live` shows them first, under `Protocols`.

### IPv6

On each interface with an IPv6 address that isn't link-local, it listens for NDP, on each such address; an interface with only a link-local address is not listened on. There, every neighbor advertisement and solicitation tells an address and its MAC. The probes, multicast ping, SSDP M-SEARCH and WS-Discovery Probe, each when its protocol is enabled, make the hosts answer, and each address that answers is asked its MAC with a neighbor solicitation. Before an address the local discovery found expires, it is pinged three times, with `ping`, so a host still there keeps it; one only a plugin found isn't. Whichever listener of the interface is running then sends the ping, also for an address a plugin found first. Each interface takes only the packets that came in on it: its sockets, bound to its address, hear on Linux the multicast NDP of the other interfaces too, and the answers of hosts routed in through another, as Docker's bridges do on a machine whose networks they route. Where the system doesn't tell the interface of a packet, as on Windows, an interface's listeners take the others' packets too.

An NDP message whose hop limit isn't 255 is ignored, as RFC 4861 requires: a router lowers it, so it is the only proof that the message comes from the link and not from a host elsewhere, sent to the address listened on. A solicitation from the unspecified address, of duplicate address detection, tells no host.

### IPv4

Every minute, it reads the kernel's neighbor table: on Linux, the entries confirmed recently, as a stale one may be a host that left; elsewhere, those not expired. The table's entries of the broadcast addresses and of the multicast groups, which macOS lists as any neighbor, are no hosts. The sweep, before a reading of the table when `rediscover` has passed since the last, so once a minute at most, has the kernel resolve every address of the subnets, so the hosts that sent nothing are in the table too. On Linux the table is read right after each sweep as well, once the kernel has checked the entries the sweep found stale, by the interface's own settings: `delay_first_probe_time`, then `ucast_solicit` probes `retrans_time_ms` apart, 9 seconds with the defaults. And an entry counts from when the kernel last confirmed it, which the table says: an IPv4 address stays its lifetime from then, so one of a host that left goes a lifetime after it last answered, not after a reading of the table that still had its entry, and a reading never shortens what another gave. Elsewhere an entry counts from when it is read.

On Linux, with `CAP_NET_RAW`, the ARP of each interface is heard too, by a packet socket that only listens: every request a host broadcasts, as it asks for its router, every reply to this machine, and every address a host announces. The sender of each is registered at once, as a neighbor of the table is: a host that only asked for another's address, which the kernel never talked to and the table doesn't have, is found within the second, not at the reading of the minute after, nor only by a sweep. Only a sender of a subnet of the interface, not the subnet's own address nor its broadcast one, and only when the MAC it says it is at is the one the frame came from: the kernel takes the packet's word, but only of the answers to what it asked, and this hears everything, so a frame from one MAC that says an address is at another, a proxy's, a rewriting bridge's or a lie, tells no host. A probe from the unspecified address, of a host that doesn't have the address yet, tells none either. And 1024 hosts the state didn't have are taken of an interface in a minute at most, as the kernel's table has its bound: frames made up, each from another MAC, fill no more, and the hosts over it wait for the table, as all did. Nothing is sent, and the table is read as before. Without the privilege it is said once in the log, and the table alone finds the hosts, as it does elsewhere. With `arp` off and `arp-listen` on, the hosts are found by the ARP heard alone, the answers to the sweep among it: it is heard from before the first sweep is sent, as no reading of the table follows.

### This machine's own addresses

The addresses of the interfaces discovery runs on are registered too, with the interface's MAC, and marked as this machine's: `(this host)` in `-live`. On Linux, those the kernel made as temporary IPv6 privacy addresses are marked so, `(this host, temporary)`: they change every day or so. They are registered while the family listens, and refreshed well within their lifetime, whatever `rediscover` is, and whatever protocols are enabled, for as long as the system has them: IPv6 ones every third of the lifetime at most, IPv4 ones every minute. One its interface no longer has, as a prefix that went or a temporary address replaced, leaves the state when the interfaces are next looked at, every minute, not a lifetime later: `host removed` in the log. An address that moves to another interface, as to a bridge, an interface made again, and one whose MAC changed, are followed the same: the discovery stops on the old and starts on the new. Where the system has no neighbor table to read, as on Windows, IPv4 listening still registers this machine's own IPv4 addresses: only the neighbors are missing.

## Solicitation

Some addresses are never seen without asking: a host's stable IPv6 address, as it sends from temporary ones, or the IPv4 address of a host that sends nothing. The library asks given hosts:

- `Worker.Solicit(addr)` sends a neighbor solicitation for an IPv6 address, on the links whose /64 it is in.
- `Worker.SolicitIPv4(ctx, targets)` asks each target MAC, with ARP requests sent to it alone, for the addresses of the local subnets within its prefixes, up to 4096 nearest the local address, or without prefixes those a sweep would ask. With prefixes, it asks on every interface with a subnet they cover, wherever the MAC was seen: a host heard over IPv6 on one interface can have its IPv4 address on another, as two networks of one wire. Without, it asks on the interfaces the local discovery saw the MAC on, or on all of them when it saw it on none. Nothing is broadcast, though a switch that no longer knows where the MAC is floods the requests, as any frame to it. It needs Linux and `CAP_NET_RAW`.

An address that answers is registered as any other.

## Names

A host has names too: what it calls itself, what the DNS server of the network calls it, and what a router's DHCP server knows it by.

The names are always kept, of what learns them: each protocol that does, under [`protocols`](#protocols), and the plugins, of their routers' DHCP leases. To learn none, disable those that do, `mdns`, `dhcp`, `lldp`, `netbios`, `llmnr` and `dns`, and the `names` of `wsd` and `ssdp`: a protocol that also finds hosts, as `mdns`, finds them all the same while it runs. `hostnames` has only their `lifetime`.

```yaml
hostnames:
  lifetime: 4h
protocols:
  netbios:
    enabled: false
  wsd:
    names: false
```

A name is the host's, its MAC's, not an address's: one learned over IPv4 is the host's for its IPv6 addresses too. A host can have several at once, when its sources disagree or it was renamed, each with what said it: the protocol, as `mdns` or `dhcp`, or a plugin's name.

### Where they come from

| | Source | |
|---|---|---|
| **mDNS, heard** | `mdns` | On each interface the local discovery runs on, for the families that listen there, it joins the groups of mDNS, 224.0.0.251 and ff02::fb, on port 5353. Whatever sends there is a host of the link, and what a host announces tells its name |
| **mDNS, asked** | `mdns` | A host is asked the name of one of its addresses, by a question sent to it alone |
| **Reverse DNS** | `dns` | The DNS servers given, its `servers`, are asked the name of an address of the host, its PTR record: the dnsmasq of a router knows the clients of its DHCP this way |
| **NetBIOS** | `netbios` | A host is asked its node status, over IPv4, by a question sent to it alone: Windows answers, and Samba, with the machine's name |
| **LLMNR** | `llmnr` | A host is asked the name of one of its addresses, by a question to the group, 224.0.0.252 or ff02::1:3: Windows answers, and systemd-resolved |
| **WS-Discovery** | `wsd` | With its `names`, a computer that answers the probe is asked its metadata, over HTTP, which has its name: Windows, and Samba with wsdd |
| **SSDP** | `ssdp` | With its `names`, a device that answers the search is asked its description, over HTTP, which has its friendly name |
| **DHCP, heard** | `dhcp` | What a client says to all as it asks for an address: its host name, with its MAC. On Linux |
| **LLDP, heard** | `lldp` | What the neighbor of an interface says of itself: its system name. On Linux |
| **[Plugins](plugins.md#leases)** | The plugin's name | The host names of the DHCP leases of their routers |

Each is its protocol, enabled under `protocols`, and runs on the interfaces the local discovery runs on, over the families that listen there. The plugins read their leases whatever protocols are enabled. A name goes to a MAC only when the discovery found a host there: an address the state doesn't have yet is found as any other, by a neighbor solicitation for an IPv6 one, and for an IPv4 one by a packet to its discard port, as the sweep's, and a reading of the neighbor table a second later, and what was said waits for it, 30 seconds at most. So an IPv6 address heard of is found with `ndp`, and an IPv4 one with `arp` or `arp-listen`, whichever tells the answer. Nothing a name protocol says registers an address.

### mDNS

Whoever sends an mDNS message, a query or a response, from an address of the link is a host there, and its address is asked of the discovery. With `active` of a family, a query for `_services._dns-sd._udp.local` goes to the group over it at every `rediscover`, with the other probes, so the hosts that have a service answer and are heard. It is sent from a port of its own, not from 5353: a responder then answers to that port, by unicast, so a link of many hosts answers without a multicast packet from each. With `ask: false` mDNS sends nothing: neither that query nor the questions to the hosts, and it only hears what is said to the groups.

A response tells names: the name of an A or an AAAA record has that address, and so does the name the PTR record of an address's reverse name points to. But a response can carry the records of other hosts, as a sleep proxy's does, and of addresses nobody has. So a record is never taken as an address of its sender, nor registered: an address it tells, when it is of the link, is asked of the discovery, and is at whatever MAC answers for it. And a name is its sender's only by a record of the sender's own address: the one the packet came from, or another the state has at the same MAC. The other records name nobody: not their sender, nor the host of their address, which didn't say them. Messages from an address that isn't of the interface's link, a link-local one or one of a subnet the interface has an address in, are left, and so are those of this machine's own responder.

A host is asked the PTR record of the reverse name of one of its addresses, `20.1.168.192.in-addr.arpa`, sent to its port 5353 alone, from a port of its own again, where the answer comes back. That port is no group's, and what is sent to it could come from anywhere: only a response with the ID of a question sent in the last 5 seconds is taken there, the query for the services' or one of these, and anything else is left.

Port 5353 is shared with the responder of this machine, if it has one, as avahi or mDNSResponder, and with any number of instances. The socket that hears a group is bound to the group's address, so it takes nothing sent to this machine alone, which stays the responder's: on Windows, where a socket can't be bound so, it takes its share of that too. Nothing is ever sent from port 5353.

### Asking a host

A host with no name is asked for it, in a round: by each protocol that can ask it, once, one after another, 2 seconds apart, and only until it has a name, which ends the round. So a host that answers the first is sent one question, and one that answers nothing one by each protocol. A host has one round in a `rediscover` at most, and 10 questions a second are sent at most, of all the protocols to all the hosts. They ask in this order:

1. **mDNS**: a question to the host alone, which most devices answer.
2. **The reverse DNS**: a question to a server, which disturbs no host of the link.
3. **NetBIOS**: to the host alone again, which only Windows and Samba answer.
4. **LLMNR**: last, as its question goes to every host of the link.

But the protocol the host answered the last time asks first, and there. Each protocol asks at one of the addresses of the host it reaches, an IPv4 one first and a link-local one last; when the host doesn't answer there, at another of them in the next round, and where it answered, there again. Only a host a local interface saw is asked by the protocols of that interface, at an address of its link; the DNS servers are asked of every host, those the plugins found too.

A host is asked again when its name has less than three rediscovery intervals left, or half its lifetime if that is less, as an address is pinged before it expires. A host whose name keeps being said, by itself or by a plugin, is never asked; nor is this machine. The questions go whatever `active` is, as the pings do: they are for one host, not a probe of all.

An answer is taken only as the answer to a question asked, by any of them: a response with the ID of a question sent in the last 5 seconds, from where it was sent. The sockets the questions leave from are on ports of their own, which no group has and nothing else of the machine shares: the ports of mDNS, NetBIOS and LLMNR stay those of the responders of this machine, avahi, Samba or systemd-resolved, and no group but mDNS's is joined.

**The reverse DNS.** Each of the `servers` of `dns`, `192.168.1.1`, or with its port `192.168.1.1:5353` or `[fd00::1]:53`, is asked the PTR record of the address over UDP, with recursion desired, as a resolver asks: a server that doesn't have it may ask others, which dnsmasq doesn't for the private ranges with `bogus-priv`. Of an answer without an error, the first label of what the record points to is the name: `printer` of `printer.lan`. It is taken from the address and the port of the server alone, as the answer to the very question sent to it. Every address is asked of but the link-local ones, the same on every link. Only the servers given are asked, never the system's resolver: that may be a program that takes its names from this very discovery.

**NetBIOS.** A node status request (RFC 1002) to port 137 of the host. Its answer, from that address and that port, lists the names the machine registered: the first that is its own, not a group's, registered, and of the workstation service, is its name; its workgroup and its services are not.

**LLMNR.** The PTR record of the address again, but sent to the group, on port 5355, with a hop limit of 1: a responder leaves out a UDP question sent to it alone, which RFC 4795 has go over TCP, where Windows doesn't listen. systemd-resolved was seen to answer the one and not the other. So every host of the link hears the question, and the one that has the address answers, to the port it came from. The answer is taken from port 5355 at an address of the link, with the ID and the question itself; a responder answers from the address its system picks, over IPv6 its link-local one, so an answer from another address than the one asked of names the host only when the state has both at one MAC. Whoever heard the question can forge its answer, which is why LLMNR asks last, and is off unless enabled.

### Fetched from the hosts that answer a probe

WS-Discovery and SSDP are probed for hosts, over IPv6, at every `rediscover`. With `names: true` of `wsd` or `ssdp`, what answers is also asked who it is, by one HTTP request each:

**WS-Discovery.** A ProbeMatch, the answer to a probe sent in the last 10 seconds, tells an endpoint and, sometimes, where its metadata is; when it doesn't, a Resolve sent to that host alone asks, and its ResolveMatch, from that host, tells. A WS-Transfer Get there returns the metadata, and the name is the computer's of its host relationship: `WINBOX` of `WINBOX/Workgroup:WORKGROUP`. A device that is no computer, as a printer, has a friendly name alone, which is its model's, and is left.

**SSDP.** The answer to the search has the LOCATION of the device's description, and the name is the `friendlyName` of its root device. That is a label for people more than a host's name, `Living Room TV`, which becomes `living-room-tv` as any name is cleaned, and two devices of one model may say the same: it is taken as what the device calls itself, with its source to tell it by, and only with the `names` of `ssdp`.

Both are bound the same. Only a host of the link is asked, at the address its answer came from, and nothing else is ever connected to: the address its answer gives must be that one, written as an address, and of it only the port and the path are the host's word. A name in its place, as Samba's wsdd2 gives its host name in a ProbeMatch, is never resolved: the request still goes to the address that answered. Of SSDP, a LOCATION anywhere else is not fetched at all, and an answer is taken in the 10 seconds after a search was sent only: a search has nothing its answer must repeat, and what comes with none sent, as without `active`, fetches nothing. The request has 3 seconds, the document 256 KB at most, no redirection is followed, no proxy used, and 4 are under way at once at most, for each listener. A host is asked once in a `rediscover` at most, and not while it has a name that stays, as it isn't asked by the others then. The probes go to all, so a host of the link that heard one can answer it with another's address as its source: that one is then sent the request, to a port and a path of the forger's choosing, once in a `rediscover`, and what it returns is told to nobody. Without their `names`, which is the default, no request is sent.

### Heard

On Linux, with `CAP_NET_RAW`, two more are heard on each interface, `dhcp` and `lldp`, by packet sockets that only listen: nothing is sent, no group of IP joined and no port taken, so the DHCP server or client of this machine keeps its own. Elsewhere they are an error to enable, and without the privilege it is said once in the log, and the rest runs.

**DHCP.** A client that asks for an address says who it is, to all. Of a DHCPv4 DISCOVER, REQUEST or INFORM: its MAC, and the host name it gives its server, the option 12, or the first label of its whole name, the option 81. The name is the host's at that MAC, the one the server gives the lease to, which is what a plugin reads of the router's leases, and only when the frame came from that MAC: the client sent it itself, and a host that writes another's MAC in a message of its own names nobody. A message a relay forwarded from another link is left. The address a REQUEST asks for, or renews, is the client's word: it is handed to the IPv4 discovery, which finds it once the client has it, and is never registered by it. Of a DHCPv6 message to the servers' group, ff02::1:2, the first label of the client's name, the option 39: it comes from the client's link-local address, and names the MAC the state has that address at, when the frame came from that MAC too.

**LLDP.** A neighbor says its system name, which is the name of the host at the MAC its frames come from, and at its chassis's own when it tells one of the same maker, the same first three bytes, as a switch whose ports have each their MAC: the chassis is the frame's word, and a host can't name any other of the link by it. The addresses it says it is managed at are handed to the discovery. A bridge keeps LLDP to itself: what is heard is what is at the other end of the wire, a switch, or a host that runs lldpd.

### The lifetime

A name stays for the `lifetime` of `hostnames`, the `lifetime` of all without, after it was last said, by any of its sources, and then expires by itself: a host renamed has both names until the old one does. A record that says goodbye, with a TTL of zero, takes no name away: it is left to expire. When the last address of a host expires, its names go with it. A name said of a MAC that has no address yet, as a lease of a host the neighbor table doesn't have, is kept for when it has one.

A names' lifetime not longer than `rediscover` is warned of at start, when a protocol asks the hosts their name: a host is asked once in each, so its name expires between.

### What a name is

A name is whatever a device claims: nothing proves it, two hosts can claim the same, and anyone on the link can announce any, of itself, or of another host by sending from its address, which nothing here can tell apart: a socket has the address a packet came from, not the MAC. Where the MAC a frame came from is known, of DHCP and LLDP, it must be the host's named, and forging that too is all it takes. So a name is a hint of which host a MAC is, for someone to read, and no ground to trust the host. What is not of the link can't: a message is taken only from an address of the link, the groups don't cross a router, and what could is taken only as the answer to a question. The names of the DNS servers given are the servers' word, as much as theirs is worth. It is made one DNS label, lower case, of letters, digits and hyphens:

- Of a dotted name, `printer.local.` or `host.domain`, the first label.
- Upper case becomes lower; an underscore or a space within, as in the `ESP_1A2B3C` that devices give their DHCP server, becomes a hyphen; the hyphens at either end are dropped.
- Anything else is no name, and is dropped, never mapped to one: an empty label, one that starts with an underscore, which is a service's, any other character, as the `*` of a lease without a name, a byte that isn't ASCII, more than 63 characters, and an IP address in place of a name.

`-live` shows the names of a host under its MAC, each with what said it, how long each has left and how long it has said it, as its addresses are, each with its records; and, under each interface, what every protocol running there sent and took: those of the naming layer under `names`, where `hosts` counts the answers and the messages that told a name, and the ARP heard under `ipv4`, as `arp-listen`; the reverse DNS, which is of no interface, comes after them all. The log has `host named` when a host gets a name, with the `name`, `mac` and `source`, `host name expired` when one goes, and `host name removed` when it goes with its host; `log_level: debug` adds `host asked its name`, with the `protocol`, each time one is.

## Interfaces

The local discovery runs on every interface that is up, not a loopback and has a MAC, with multicast for IPv6, with broadcast for IPv4, unless `interfaces` names those it runs on, and `exclude_interfaces` those it doesn't: names, or patterns as `docker*`, `veth*`. On a host running containers, leaving their bridges out keeps the containers out of the state, and the probes off their networks. The plugins aren't concerned.

```yaml
exclude_interfaces:
  - docker*
  - br-*
  - veth*
```

The interfaces without a MAC, as PPP links and tunnels, are left out, and their own addresses not registered: a host is its MAC, and NDP tells none there.

The interfaces and their addresses are looked at every minute. An address that moved to another interface, or whose interface was made again, is listened on anew there.

## Several instances

Any number of instances run at once, on one machine or on several of one link, each with its own configuration, and each finds what it would alone. None listens on a port of its own choosing, so there is none to tell apart, and none takes a packet from another.

On one machine, every socket is the instance's own, but the one that hears a group of mDNS, with `mdns`: its port, 5353, is every instance's, and the system gives each what is sent to the group. The names are asked from ports the system picks, where the answers come back. Those of NDP and the ping are raw ICMPv6 sockets, and the system gives each of them its copy of every message; the SSDP and WS-Discovery searches leave from a port the system picks, where their answers come back; an ARP solicitation has its own socket too, and takes the answers of the host it asked; and the packet sockets that hear ARP, DHCP and LLDP each get their copy of every frame, as the DHCP server of the machine gets its own. The interfaces, the families, the protocols and the lifetimes are each instance's: one that leaves an interface out, or doesn't take IPv4, has nothing of them, whatever another does. Only the kernel's IPv4 neighbor table is shared: what the sweep of one resolved, another that listens for IPv4 reads too. And the answers to the multicast ping of one come to the machine's address, where the others hear them as well, as they hear the answers to any ping from the machine: each asks the MAC of those hosts, so a host is solicited once by each instance for each ping of any. It ends there, as the answer to a solicitation asks nothing more. Stopping one leaves the others as they were.

On several machines of one link, each hears some of what the others send: their neighbor solicitations, and their machine's answers. A solicitation tells the address and MAC of its sender only, never of the address it asks for, so another instance's machine is a host as any other, with its real addresses at its MAC, and is never marked as this machine's. Nothing heard from another instance makes one probe: the probes go by `rediscover` alone, and a solicitation follows only an answer that came to this machine, which those to another's probes don't, so two instances send on the link what each sends alone. A host that leaves expires on each after its own lifetime: the probes of one don't keep it on another.

## Privileges

| | Needs |
|---|---|
| IPv6 listening and probing, `ndp` and `ping`, `Worker.Solicit` | Root, or `CAP_NET_RAW`: raw ICMPv6 sockets |
| IPv4 listening, `arp`, and the sweep, `arp-sweep` | Nothing |
| IPv4 listening: the ARP the hosts send, `arp-listen` | Linux, and root or `CAP_NET_RAW`: a packet socket. Without, the neighbor table alone |
| `Worker.SolicitIPv4` | Linux, and root or `CAP_NET_RAW`: raw ARP |
| `ssdp` and `wsd`, and the names: `mdns`, `dns`, `netbios`, `llmnr`, and those of `wsd` and `ssdp` | Nothing more: their sockets are UDP and TCP ones, on ports the system picks |
| `dhcp` and `lldp` | Linux, and root or `CAP_NET_RAW`: packet sockets. Without the privilege, the others |
| The plugins | Nothing, but the network to reach their host |

In Docker, the local discovery needs the host's network, `--network host`, which Docker Desktop on macOS and Windows doesn't give: there, only the plugins find hosts. `NET_RAW` is granted by default. On Windows, the IPv6 listener has been seen to miss NDP packets: prefer the plugins there. On Solaris there is no `-live`.

## Lifetimes and probing

An address stays for its family's `lifetime`, the `lifetime` of all without, after it was last seen by anything: the local discovery or a plugin. The active discovery probes again every `rediscover`, by default a third of the shortest lifetime of the families that probe, so a quiet host is probed before it expires.

A name stays for the `lifetime` of `hostnames`, the same way: see [names](#the-lifetime).

What a start can't know at once: an address a host keeps beside the one it uses. A host answers the multicast ping from one address, its preferred, and sends nothing from the others: one given while the worker runs is learned by the advertisement the host sends for it, but a worker started afterwards, as after a restart, learns it only when the host speaks from it, as the solicitation it then sends tells it. A stable address beside temporary ones is the usual case. A router's [plugin](plugins.md) knows the addresses in use from its neighbor table, and a solicitation finds an EUI-64 one that a filter names.

```yaml
lifetime: 2h
rediscover: 20m
ipv4:
  enabled: true
  lifetime: 30m
```

Three settings are accepted but lose hosts that are there, and are warned of at start: a `rediscover` not shorter than the lifetime of a family that probes, as the hosts that stay quiet expire between probes; with `arp`, an IPv4 lifetime of a minute or less, as the neighbor table is read every minute; and a family that listens with no protocol that finds its hosts enabled, which registers this machine's own addresses only. `DefaultConfig` leaves `Rediscover` zero, so that it follows a `Lifetime` changed afterwards.
