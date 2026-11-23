# Discovery

Discovery finds the addresses on the network, and the MAC that holds each one. A host is identified by its MAC, which doesn't change when its addresses do. Each address is kept for its lifetime after it was last seen. Discovery also learns the hosts' [names](#names).

## Families and protocols

Everything on this page is set in the [configuration file](reference/configuration.md), which you pass as `ipv6disc --config discovery.yaml`. Without a file, every key has its default.

Each family, IPv6 and IPv4, has its own switches under `ipv6` and `ipv4`: `enabled`, `listen`, `active`, and its `lifetime`. IPv6 is on by default, and IPv4 is off.

| | `ipv6` | `ipv4` |
|---|---|---|
| **[Plugins](plugins.md)** | The routers' IPv6 neighbor tables | The routers' ARP tables |
| **`listen`**: the local discovery | NDP on each link, and the answers to the probes | The kernel's neighbor table. On Linux, also the ARP the hosts send |
| **`active`**: probing every host | Multicast ping, SSDP and WS-Discovery | A sweep of the local subnets |
| **Solicit**: asking given hosts, from the library | `Worker.Solicit`: a neighbor solicitation for an address | `Worker.SolicitIPv4`: ARP requests sent to one MAC only |
| **`lifetime`** | How long an address stays after it was last seen | The same, for IPv4 addresses |

Some details of the IPv4 column:

- **The neighbor table** is read through netlink on Linux, and with `arp -an` on macOS and the BSDs. Windows and Solaris have neither, so there IPv4 listening only finds this machine's own addresses.
- **The sweep** sends a UDP packet to the discard port of each address of the local subnets, so that the kernel resolves each host. It covers a whole subnet up to a /22. In a larger subnet it only covers the /24 of the machine's address. It needs no privilege, but it makes the kernel broadcast an ARP request for each address.

Active probing needs listening, because listening is what reads the answers. Without `listen`, nothing is probed.

```yaml
ipv4:
  enabled: true
  active: false   # no sweep: nothing is broadcast
```

### Protocols

Under `protocols`, each protocol of the local discovery has its own switch, `enabled`, with its options next to it. A protocol is always written as a mapping, never as `true` or `false` alone.

A protocol runs when all of these hold:

- the protocol is enabled;
- its family is enabled;
- its family listens or, for the sweep, is active.

So a family's switches act on all of its protocols at once.

| Protocol | Default | Family | Runs with | |
|---|---|---|---|---|
| `ndp` | on | IPv6 | `listen` | Neighbor discovery on each link. It gives an address and its MAC, and it asks for the MAC of the addresses the other IPv6 protocols hear |
| `ping` | on | IPv6 | `listen` | Pings an address before it expires. With `active`, pings every host by multicast |
| `ssdp` | on | IPv6 | `listen` | With `active`, searches for UPnP devices and hears their answers. With its `names`, asks a device that answers for its [name](#fetched-from-the-hosts-that-answer-a-probe) |
| `wsd` | on | IPv6 | `listen` | With `active`, sends a WS-Discovery probe, which Windows and Samba answer. With its `names`, asks a computer that answers for its [name](#fetched-from-the-hosts-that-answer-a-probe) |
| `arp` | on | IPv4 | `listen` | Reads the kernel's neighbor table every minute |
| `arp-sweep` | on | IPv4 | `active` | Sweeps the subnets no larger than its `max_prefix`, 22 by default |
| `arp-listen` | on, on Linux | IPv4 | `listen` | Hears the ARP the hosts send. Linux only |
| `mdns` | on | Either | `listen` | Whatever sends to the [mDNS](#mdns) groups is a host, and what it announces is its name. With `active`, sends a query to the group. Without its `ask`, it only listens |
| `dhcp` | on, on Linux | Either | `listen` | Hears what [DHCP](#heard) clients say when they ask for an address. Linux only |
| `lldp` | on, on Linux | Either | `listen` | Hears what the [LLDP](#heard) neighbor of an interface says. Linux only |
| `netbios` | on | IPv4 | `listen` | [Asks](#asking-a-host) a host for its NetBIOS name. Names only |
| `llmnr` | on | Either | `listen` | [Asks](#asking-a-host) a host for its name by LLMNR. Names only |
| `dns` | on | None | - | Asks its `servers` for the name of each address, including those of hosts the plugins found. Without `servers`, it asks nobody. Names only |

By default every protocol is on, with its options on too: `ssdp` and `wsd` fetch names, and `mdns` asks.

- The protocols that hear raw frames, `arp-listen`, `dhcp` and `lldp`, are on where they can run, which is Linux, and off elsewhere.
- `dns` only asks the `servers` you give it, so it does nothing until it has some.
- A protocol of either family runs on an interface over the families that listen on that interface.
- A protocol that is off sends nothing, joins no group and opens no socket. The other protocols run without it.

```yaml
ipv4:
  enabled: true
protocols:
  arp-sweep:                    # nothing broadcast
    enabled: false
  ssdp:
    enabled: false
  llmnr:                        # its questions go to every host on the link
    enabled: false
  dns:
    servers:
      - 192.168.1.1
```

A configuration that can't run is an error at start. The error says what is wrong and where. Nothing is silently left out. These are errors:

- **A protocol that doesn't exist, an option the protocol doesn't have, or a value of the wrong type.** For example, `mdns: true` must be written as `enabled: true` under `mdns`.
- **`ping`, `ssdp` or `wsd` enabled without `ndp`.** They only hear an address, and only NDP gives its MAC, so they would find no host.
- **`arp-sweep` without both `arp` and `arp-listen`.** Those two are what report the hosts that answer the sweep.
- **`arp-listen`, `dhcp` or `lldp` enabled where the system can't run them**, which is anywhere but Linux. They are on by default on Linux and off elsewhere, so a configuration that doesn't mention them runs everywhere.
- **A `max_prefix` of `arp-sweep` that is not from 16 to 30.** A subnet larger than a /`max_prefix` is only swept in the /24 of the interface's address, or in the /`max_prefix` there when that is smaller.
- **`hostnames: true`, or `enabled` under `hostnames`**, which older versions had. The [names](#names) are now always kept, from whichever protocols learn them.

The options of a protocol that is off are not checked.

At start, the log says which protocols run: `protocols of the local discovery: ndp, ping, ssdp, wsd`. `--live` shows them first, under `Protocols`.

### IPv6

Discovery listens for NDP on each interface that has an IPv6 address other than a link-local one, on each such address. An interface with only a link-local address is not listened on.

- **Listening.** Every neighbor advertisement and solicitation heard gives an address and its MAC.
- **Probing.** The probes are the multicast ping, the SSDP M-SEARCH and the WS-Discovery Probe, each sent when its protocol is enabled. They make the hosts answer. Each address that answers is then asked for its MAC with a neighbor solicitation.
- **Refreshing.** Before an address found by the local discovery expires, `ping` pings it three times, so a host that is still there keeps its address. An address that only a plugin found is not pinged. The ping is sent by whichever listener is running on the interface at that moment, even if a plugin found the address first.

Each interface only takes the packets that came in on it. This matters because, on Linux, an interface's sockets are bound to its address but still hear the multicast NDP of the other interfaces. They also hear the answers of hosts routed in through another interface, which happens with Docker's bridges on a machine that routes their networks. Where the system doesn't say which interface a packet came in on, as on Windows, an interface's listeners take the other interfaces' packets too.

An NDP message whose hop limit isn't 255 is ignored, as RFC 4861 requires. A router lowers the hop limit, so 255 is the only proof that the message comes from the link, and not from a host elsewhere that sent it to the address listened on.

A solicitation from the unspecified address, which is part of duplicate address detection, identifies no host.

### IPv4

**The neighbor table.** Every minute, discovery reads the kernel's neighbor table.

- On Linux it takes the entries confirmed recently, because a stale entry may belong to a host that left. Elsewhere it takes the entries that haven't expired.
- Entries for broadcast addresses and multicast groups are not hosts. macOS lists them like any neighbor.
- On Linux, an entry counts from the moment the kernel last confirmed it, which the table gives. An IPv4 address stays for its lifetime from that moment. So the address of a host that left goes a lifetime after the host last answered, not a lifetime after a later reading that still had its entry. One reading never shortens what another gave. Elsewhere, an entry counts from the moment it is read.

**The sweep.** The sweep makes the kernel resolve every address of the subnets, so that hosts that sent nothing are in the table too. It runs just before a reading of the table, once `rediscover` has passed since the last sweep, so at most once a minute.

On Linux the table is also read right after each sweep, once the kernel has checked the entries the sweep found stale. How long that takes depends on the interface's own settings: `delay_first_probe_time`, then `ucast_solicit` probes `retrans_time_ms` apart, which is 9 seconds with the defaults.

**The ARP the hosts send.** On Linux, with `CAP_NET_RAW`, discovery also hears the ARP on each interface, through a packet socket that only listens. It hears every request a host broadcasts, for example when it asks for its router, every reply to this machine, and every address a host announces.

- The sender of each frame is registered at once, like a neighbor from the table. A host that only asked for another host's address, which the kernel never talked to and the table doesn't have, is found within a second. It doesn't wait for the next minute's reading, or for a sweep.
- A sender is only taken when its address is in a subnet of the interface, and is neither the subnet's own address nor its broadcast address.
- The MAC the sender claims must be the MAC the frame came from. The kernel trusts what a packet says, but only for answers to what it asked, while this socket hears everything. So a frame from one MAC that says an address is at another MAC identifies no host, whether it comes from a proxy, from a bridge that rewrites frames, or from a host that lies.
- A probe from the unspecified address, sent by a host that doesn't have the address yet, identifies no host either.
- At most 1024 hosts that the state didn't already have are taken per interface per minute, just as the kernel's table has a limit. Made-up frames, each from a different MAC, can't fill more than that. Hosts over the limit wait for the table, as all hosts did before.
- Nothing is sent, and the table is read as before.
- Without the privilege, the log says so once, and the table alone finds the hosts, as it does on other systems.

With `arp` off and `arp-listen` on, hosts are found only by the ARP heard, which includes the answers to the sweep. Since no reading of the table follows a sweep in that case, the listening starts before the first sweep is sent.

### This machine's own addresses

The addresses of the interfaces discovery runs on are registered too, with the interface's MAC, and marked as this machine's. `--live` shows them as `(this host)`.

- **Temporary addresses.** On Linux and macOS, the IPv6 privacy addresses that the kernel created as temporary are marked `(this host, temporary)`. They change every day or so.
- **Deprecated addresses, on macOS.** macOS keeps a temporary address it has replaced for a while, marked as deprecated, and doesn't let it be listened on. Discovery leaves those out: they are not registered, and nothing is listened for on them.
- **Refreshing.** The addresses are registered while the family listens, for as long as the system has them. They are refreshed well within their lifetime, whatever `rediscover` is and whatever protocols are enabled: IPv6 addresses at least every third of the lifetime, and IPv4 addresses every minute.
- **Removal.** An address its interface no longer has, such as one from a prefix that went away or a temporary address that was replaced, leaves the state the next time the interfaces are checked. That is every minute, not a lifetime later. The log says `host removed`.
- **Changes.** Discovery follows an address that moves to another interface (for example to a bridge), an interface that is created again, and an interface whose MAC changed. It stops on the old interface and starts on the new one.
- **Without a neighbor table.** Where the system has no neighbor table to read, as on Windows, IPv4 listening still registers this machine's own IPv4 addresses. Only the neighbors are missing.

## Solicitation

Some addresses are never seen unless you ask for them. One case is a host's stable IPv6 address, because the host sends from its temporary addresses. Another is the IPv4 address of a host that sends nothing. The library can ask for given hosts:

- **`Worker.Solicit(addr)`** sends a neighbor solicitation for an IPv6 address, on the links whose /64 contains the address.
- **`Worker.SolicitIPv4(ctx, targets)`** asks each target MAC for its addresses, with ARP requests sent to that MAC only.
  - With prefixes, it asks for the addresses of the local subnets within the target's prefixes. If there are more than 4096, it asks for the 4096 nearest the local address. It asks on every interface that has a subnet the prefixes cover, wherever the MAC was seen. A host heard over IPv6 on one interface can have its IPv4 address on another, for example when two networks share one wire.
  - Without prefixes, it asks for the addresses a sweep would ask for. It asks on the interfaces where the local discovery saw the MAC, or on all interfaces when it saw the MAC on none.
  - Nothing is broadcast. But a switch that no longer knows where the MAC is floods the requests, as it would any frame to that MAC.
  - It needs Linux and `CAP_NET_RAW`.

An address that answers is registered like any other.

## Names

A host has names too: what it calls itself, what the network's DNS server calls it, and what a router's DHCP server knows it by.

Names are always kept, from whatever learns them: each protocol that learns names, under [`protocols`](#protocols), and the plugins, which read their routers' DHCP leases. `hostnames` only has the names' `lifetime`.

To learn no names, disable the protocols that learn them: `mdns`, `dhcp`, `lldp`, `netbios`, `llmnr` and `dns`, and the `names` option of `wsd` and `ssdp`. A protocol that also finds hosts, such as `mdns`, keeps finding hosts for as long as it runs.

```yaml
hostnames:
  lifetime: 4h
protocols:
  netbios:
    enabled: false
  wsd:
    names: false
```

A name belongs to the host, that is to its MAC, and not to an address. A name learned over IPv4 is also the host's name for its IPv6 addresses.

A host can have several names at once, when its sources disagree or when it was renamed. Each name is kept with what said it: the protocol, such as `mdns` or `dhcp`, or a plugin's name.

### Where they come from

| | Source | How the name is learned |
|---|---|---|
| **mDNS, heard** | `mdns` | Discovery joins the mDNS groups and hears what hosts announce |
| **mDNS, asked** | `mdns` | A host is asked for the name of one of its addresses, by a question sent to it alone |
| **Reverse DNS** | `dns` | The DNS servers you give in `servers` are asked for the PTR record of one of the host's addresses |
| **NetBIOS** | `netbios` | A host is asked for its node status, over IPv4, by a question sent to it alone. Windows and Samba answer with the machine's name |
| **LLMNR** | `llmnr` | A host is asked for the name of one of its addresses, by a question to the group, 224.0.0.252 or ff02::1:3. Windows and systemd-resolved answer |
| **WS-Discovery** | `wsd` | With its `names`, a computer that answers the probe is asked over HTTP for its metadata, which has its name. Windows answers, and Samba with wsdd |
| **SSDP** | `ssdp` | With its `names`, a device that answers the search is asked over HTTP for its description, which has its friendly name |
| **DHCP, heard** | `dhcp` | A client broadcasts its host name, with its MAC, when it asks for an address. On Linux |
| **LLDP, heard** | `lldp` | The neighbor of an interface says its system name. On Linux |
| **[Plugins](plugins.md#leases)** | The plugin's name | The host names in the DHCP leases of the plugins' routers |

For the first row: on each interface the local discovery runs on, and for the families that listen there, discovery joins the mDNS groups, 224.0.0.251 and ff02::fb, on port 5353. Whatever sends to a group is a host on the link, and what a host announces gives its name.

For the reverse DNS row: this is how the dnsmasq on a router knows the clients of its DHCP server.

Each source in the table except the plugins is a protocol, enabled under `protocols`. It runs on the interfaces the local discovery runs on, over the families that listen there. The plugins read their leases whatever protocols are enabled.

**A name needs a discovered host.** A name only goes to a MAC when discovery has found a host there, and nothing a name protocol says registers an address by itself. When a name protocol mentions an address the state doesn't have yet, discovery looks for that address the usual way:

- for an IPv6 address, with a neighbor solicitation;
- for an IPv4 address, with a packet to its discard port, like the sweep's, and a reading of the neighbor table a second later.

Meanwhile the name waits for the address to be found, for at most 30 seconds.

So an IPv6 address that a name protocol mentions is only found with `ndp` on. An IPv4 one is found with `arp` or `arp-listen`, whichever reports the answer.

### mDNS

**Finding hosts.** Whoever sends an mDNS message, a query or a response, from an address on the link is a host there. Discovery then looks for that address, to learn its MAC.

With a family's `active`, discovery also sends a query for `_services._dns-sd._udp.local` to the group, over that family, at every `rediscover`, along with the other probes. Hosts that have a service answer it, and are heard. The query is sent from a port of its own, not from 5353. A responder then answers to that port by unicast, so a link with many hosts answers without a multicast packet from each one.

With `ask: false`, mDNS sends nothing: neither that query nor the questions to individual hosts. It only hears what is said to the groups.

**Names from a response.** A response gives names in two ways: the name of an A or AAAA record has that record's address, and so does the name that the PTR record of an address's reverse name points to.

But a response can carry records about other hosts, as a sleep proxy's response does, and about addresses nobody has. So discovery applies these rules:

- A record is never taken as an address of its sender, and never registered. When a record gives an address on the link, discovery looks for that address, and the address belongs to whatever MAC answers for it.
- A name is only its sender's when a record gives it for one of the sender's own addresses: the address the packet came from, or another address the state has at the same MAC.
- The other records name nobody. They don't name their sender, and they don't name the host of their address, which didn't say them.
- Messages from an address that isn't on the interface's link are ignored. An address on the link is a link-local one, or one in a subnet the interface has an address in.
- Messages from this machine's own responder are ignored.

**Asking a host.** A host is asked for the PTR record of the reverse name of one of its addresses, such as `20.1.168.192.in-addr.arpa`. The question is sent to the host's port 5353 only, again from a port of discovery's own, where the answer comes back.

That port belongs to no group, and anything could be sent to it from anywhere. So the only thing taken there is a response with the ID of a question sent in the last 5 seconds: either the query for the services, or one of these questions. Anything else is ignored.

**Sharing port 5353.** Port 5353 is shared with this machine's own responder, if it has one, such as avahi or mDNSResponder, and with any number of instances. The socket that hears a group is bound to the group's address. So it takes nothing that is sent to this machine alone, and that traffic stays the responder's. On Windows a socket can't be bound that way, so there it takes its share of that traffic too. Nothing is ever sent from port 5353.

### Asking a host

A host with no name is asked for one, in a round:

- Each protocol that can ask the host asks once, one after another, 2 seconds apart.
- The round ends as soon as the host has a name. So a host that answers the first protocol is sent one question, and a host that answers nothing is sent one by each protocol.
- A host has at most one round per `rediscover`.
- At most 10 questions a second are sent in total, across all the protocols and all the hosts.

The protocols ask in this order:

1. **mDNS**: a question to the host alone, which most devices answer.
2. **The reverse DNS**: a question to a server, which disturbs no host on the link.
3. **NetBIOS**: again a question to the host alone, which only Windows and Samba answer.
4. **LLMNR**: last, because its question goes to every host on the link.

There is one exception to the order: the protocol the host answered last time asks first, at the address where the host answered.

**Which address is asked.** Each protocol asks at one of the host's addresses that it can reach. It prefers an IPv4 address, and uses a link-local one last. When the host doesn't answer there, the protocol tries another of the host's addresses in the next round. Where the host answered, the protocol asks there again.

The protocols of an interface only ask a host that the interface itself saw, at an address on its link. The DNS servers are asked about every host, including those the plugins found.

**When a host is asked again.** A host is asked again when its name has less than three rediscovery intervals left, or half its lifetime if that is less. This is like the ping of an address before it expires. A host whose name keeps being said, by the host itself or by a plugin, is never asked. Neither is this machine.

The questions are sent whatever `active` is, like the pings. They are for one host, not a probe of all hosts.

**Which answers are taken.** For every one of these protocols, an answer is only taken as the answer to a question that was asked: a response that carries the ID of a question sent in the last 5 seconds, and comes from the address that question was sent to.

The sockets that send the questions are on ports of their own. No group has those ports, and nothing else on the machine shares them. The ports of mDNS, NetBIOS and LLMNR stay with this machine's own responders, such as avahi, Samba or systemd-resolved. No group is joined except mDNS's.

**The reverse DNS.** Each server in the `servers` of `dns` is asked for the PTR record of the address. A server is written as `192.168.1.1`, or with its port as `192.168.1.1:5353` or `[fd00::1]:53`.

- The question goes over UDP, with recursion desired, the way a resolver asks. A server that doesn't have the record may ask other servers. dnsmasq doesn't do that for the private ranges when it has `bogus-priv`.
- When the answer has no error, the name is the first label of what the record points to: `printer` from `printer.lan`.
- The answer is only taken from the server's address and port, as the answer to the exact question sent to it.
- Every address is asked about except link-local ones, which are the same on every link.
- Only the servers you give are asked, never the system's resolver. The system's resolver may be a program that takes its names from this very discovery.

**NetBIOS.** A node status request (RFC 1002) is sent to port 137 of the host. The answer, from that address and that port, lists the names the machine registered. The host's name is the first one that is the machine's own and not a group's, is registered, and belongs to the workstation service. Its workgroup and its services are not names of the host.

**LLMNR.** The question is again for the PTR record of the address, but it is sent to the group, on port 5355, with a hop limit of 1.

- It goes to the group because a responder ignores a UDP question sent to it alone. RFC 4795 has such a question go over TCP, where Windows doesn't listen. systemd-resolved was seen to answer the group question and not the unicast one.
- So every host on the link hears the question, and the host that has the address answers, to the port the question came from.
- The answer is taken from port 5355 at an address on the link, when it has the ID and the question itself.
- A responder answers from the address its system picks, which over IPv6 is its link-local address. So an answer from a different address than the one asked about only names the host when the state has both addresses at one MAC.
- Whoever heard the question can forge its answer. That is why LLMNR asks last.

### Fetched from the hosts that answer a probe

WS-Discovery and SSDP probe for hosts, over IPv6, at every `rediscover`. With `names: true` under `wsd` or `ssdp`, a host that answers is also asked who it is, with one HTTP request.

**WS-Discovery.** A ProbeMatch, the answer to a probe sent in the last 10 seconds, gives an endpoint and, sometimes, the location of its metadata. When it doesn't give the location, a Resolve sent to that host alone asks for it, and the host's ResolveMatch gives it. A WS-Transfer Get to that location returns the metadata. The name is the computer name in its host relationship: `WINBOX` from `WINBOX/Workgroup:WORKGROUP`. A device that is not a computer, such as a printer, only has a friendly name, which is its model's name, and it is not used.

**SSDP.** The answer to the search has the LOCATION of the device's description. The name is the `friendlyName` of the root device. That is more a label for people than a host name: `Living Room TV` becomes `living-room-tv` when it is cleaned like any name, and two devices of one model may give the same one. It is taken as what the device calls itself, kept with its source so you can tell where it came from, and only with the `names` option of `ssdp`.

Both fetches have the same limits:

- **Only the host that answered is contacted.** Only a host on the link is asked, at the address its answer came from, and nothing else is ever connected to. The address the answer gives must be that same address, written as an address. Only the port and the path are taken on the host's word.
- **A name in place of the address is never resolved.** Samba's wsdd2, for example, gives its host name in a ProbeMatch. The request still goes to the address that answered.
- **For SSDP**, a LOCATION at any other address is not fetched at all. An answer is only taken in the 10 seconds after a search was sent. A search has nothing that its answer must repeat, so an answer that arrives when no search was sent, as happens without `active`, fetches nothing.
- **Request limits.** A request may take 3 seconds at most, and the document may be 256 KB at most. No redirection is followed and no proxy is used. At most 4 requests run at once, for each listener.
- **How often.** A host is asked at most once per `rediscover`. It isn't asked while it has a name that keeps being said, just as the other protocols don't ask it then.
- **What a forger can do.** The probes go to every host, so a host on the link that heard one can answer it with another host's address as its source. That other host is then sent the request, to a port and a path the forger chose, once per `rediscover`. Whatever it returns is told to nobody.

With `names: false`, no request is sent.

### Heard

On Linux, with `CAP_NET_RAW`, two more protocols are heard on each interface: `dhcp` and `lldp`. They use packet sockets that only listen. Nothing is sent, no IP group is joined, and no port is taken, so this machine's own DHCP server or client keeps its port.

On other systems, enabling them is an error. Without the privilege, the log says so once, and everything else runs.

**DHCP.** A client that asks for an address tells everyone who it is.

- **DHCPv4.** A DISCOVER, REQUEST or INFORM gives the client's MAC and its name. The name is the host name the client gives its server in option 12, or the first label of its full name in option 81.
  - The name goes to the host at that MAC. That is the MAC the server gives the lease to, and so the same one a plugin reads in the router's leases.
  - The name is only taken when the frame came from that MAC, which means the client sent it itself. A host that writes another host's MAC in its own message names nobody.
  - A message that a relay forwarded from another link is ignored.
  - The address a REQUEST asks for, or renews, is only the client's claim. It is handed to the IPv4 discovery, which finds it once the client really has it. DHCP itself never registers it.
- **DHCPv6.** A message to the servers' group, ff02::1:2, gives the first label of the client's name, in option 39. The message comes from the client's link-local address. It names the MAC that the state has that address at, when the frame came from that MAC too.

**LLDP.** A neighbor says its system name. That is the name of the host at the MAC its frames come from.

- It is also the name of the host at the chassis's own MAC, when the neighbor gives one from the same maker, meaning the same first three bytes. A switch whose ports each have their own MAC is an example. The chassis MAC is only the frame's claim, and this rule stops a host from naming any other host on the link with it.
- The management addresses the neighbor gives are handed to discovery.
- A bridge doesn't forward LLDP. So what is heard is whatever is at the other end of the wire: a switch, or a host that runs lldpd.

### The lifetime

A name stays for the `lifetime` of `hostnames` after any of its sources last said it, and then expires by itself. Without that key, the general `lifetime` applies.

- A renamed host has both names until the old one expires.
- An mDNS record that says goodbye, with a TTL of zero, doesn't remove a name. The name is left to expire.
- When a host's last address expires, its names go with it.
- A name said for a MAC that has no address yet, such as a lease for a host the neighbor table doesn't have, is kept for when the MAC has one.

A names' lifetime that is not longer than `rediscover` gets a warning at start, when a protocol asks hosts for their name. A host is asked once per `rediscover`, so its name would expire between two questions.

### What a name is

**A name is a claim, not a proof.** A name is whatever a device says it is.

- Nothing proves a name, and two hosts can claim the same one.
- Anyone on the link can announce any name for itself.
- Anyone on the link can also announce a name for another host, by sending from that host's address. Nothing here can tell the difference, because a socket gives the address a packet came from, not the MAC.
- For DHCP and LLDP the MAC a frame came from is known, and it must be the MAC of the host being named. But forging that MAC too is all it takes.

So a name is a hint, for a person to read, about which host a MAC is. It is no reason to trust the host.

What is outside the link can't do any of this. A message is only taken from an address on the link, the groups don't cross a router, and anything that could arrive from elsewhere is only taken as the answer to a question. The names from the DNS servers you give are those servers' word, and are worth as much as the servers are.

**How a name is cleaned.** A name is turned into one DNS label, in lower case, made of letters, digits and hyphens:

- From a dotted name, such as `printer.local.` or `host.domain`, the first label is taken.
- Upper case becomes lower case. An underscore or a space inside the name becomes a hyphen, as in the `ESP_1A2B3C` that devices give their DHCP server. Hyphens at either end are dropped.
- Anything else is not a name. It is dropped, and never converted into one:
  - an empty label;
  - a label that starts with an underscore, which is a service's;
  - any other character, such as the `*` of a lease without a name;
  - a byte that isn't ASCII;
  - more than 63 characters;
  - an IP address in place of a name.

**Where names are shown.** `--live` shows a host's names under its MAC. Each name is shown with what said it, how long each source has left, and how long it has been saying the name. Addresses are shown the same way, each with its records.

Under each interface, `--live` also shows what every protocol running there sent and took:

- The naming protocols are under `names`, where `hosts` counts the answers and the messages that gave a name.
- The ARP heard is under `ipv4`, as `arp-listen`.
- The reverse DNS belongs to no interface, so it comes after all of them.

The log has these events:

- `host named` when a host gets a name, with the `name`, `mac` and `source`;
- `host name expired` when a name goes;
- `host name removed` when a name goes together with its host;
- with `log_level: debug`, `host asked its name`, with the `protocol`, each time a host is asked.

## Interfaces

By default, the local discovery runs on every interface that is up, is not a loopback, and has a MAC. For IPv6 the interface must also support multicast, and for IPv4 it must support broadcast.

- `interfaces` limits discovery to the interfaces you name.
- `exclude_interfaces` leaves out the ones you name.

Both take names, or patterns such as `docker*` and `veth*`.

On a host that runs containers, exclude their bridges. That keeps the containers out of the state, and the probes off their networks:

```yaml
exclude_interfaces:
  - docker*
  - br-*
  - veth*
```

Interfaces without a MAC, such as PPP links and tunnels, are left out, and their own addresses are not registered. A host is identified by its MAC, and NDP gives none there.

The interfaces and their addresses are checked every minute. An address that moved to another interface, or whose interface was created again, is listened on again there.

An address can't be listened on while the system still checks it for a duplicate, for a second or so after it is given: at boot, or when a new prefix is announced. Discovery tries such an address again after a second, then after twice as long each time, so it is listened on seconds after it is ready and not at the next check.

None of this affects the plugins.

## Several instances

You can run any number of instances at once, on one machine or on several machines of one link, each with its own configuration. Each finds what it would find alone. No instance listens on a port of its own choosing, so there is no port to keep different between instances, and no instance takes a packet away from another.

### On one machine

Every socket belongs to its instance, with one exception: the socket that hears an mDNS group, with `mdns`. Its port, 5353, is shared by every instance, and the system gives each instance what is sent to the group.

How the other sockets behave:

- **Name questions** are sent from ports the system picks, where the answers come back.
- **NDP and the ping** use raw ICMPv6 sockets, and the system gives each socket its own copy of every message.
- **The SSDP and WS-Discovery searches** are sent from a port the system picks, where their answers come back.
- **An ARP solicitation** has its own socket too, and takes the answers of the host it asked.
- **The packet sockets that hear ARP, DHCP and LLDP** each get their own copy of every frame, just as the machine's DHCP server gets its own.

The interfaces, the families, the protocols and the lifetimes belong to each instance. An instance that excludes an interface, or doesn't take IPv4, gets nothing from them, whatever another instance does.

Two things are shared:

- **The kernel's IPv4 neighbor table.** When one instance's sweep resolves a host, another instance that listens for IPv4 reads that entry too.
- **The answers to the multicast ping.** They arrive at the machine's address, where the other instances hear them too, as they hear the answers to any ping sent from the machine. Each instance then asks for the MAC of those hosts. So for each ping sent by any instance, a host is solicited once by every instance. It ends there, because the answer to a solicitation triggers nothing more.

Stopping one instance leaves the others as they were.

### On several machines of one link

Each instance hears some of what the others send: their neighbor solicitations, and their machines' answers.

- A solicitation only gives the address and MAC of its sender, never of the address it asks for. So another instance's machine is a host like any other, with its real addresses at its MAC. It is never marked as this machine's.
- Nothing heard from another instance makes an instance probe. The probes are driven by `rediscover` alone. A solicitation only follows an answer that came to this machine, and the answers to another instance's probes don't. So two instances send on the link exactly what each would send alone.
- A host that leaves expires on each instance after that instance's own lifetime. One instance's probes don't keep the host alive on another.

## Privileges

| | Needs |
|---|---|
| IPv6 listening and probing, `ndp` and `ping`, `Worker.Solicit` | Root, or `CAP_NET_RAW`, for raw ICMPv6 sockets |
| IPv4 listening, `arp`, and the sweep, `arp-sweep` | Nothing |
| IPv4 listening: the ARP the hosts send, `arp-listen` | Linux, and root or `CAP_NET_RAW`, for a packet socket. Without the privilege, only the neighbor table is used |
| `Worker.SolicitIPv4` | Linux, and root or `CAP_NET_RAW`, for raw ARP |
| `ssdp` and `wsd`, and the names: `mdns`, `dns`, `netbios`, `llmnr`, and those of `wsd` and `ssdp` | Nothing more. Their sockets are UDP and TCP sockets, on ports the system picks |
| `dhcp` and `lldp` | Linux, and root or `CAP_NET_RAW`, for packet sockets. Without the privilege, the other protocols still run |
| The plugins | Nothing, except network access to their host |

Notes for specific systems:

- **Docker:** the local discovery needs the host's network, `--network host`. Docker Desktop on macOS and Windows doesn't provide it, so there only the plugins find hosts. `NET_RAW` is granted by default.
- **Windows:** the IPv6 listener has been seen to miss NDP packets. Prefer the plugins there.
- **Solaris:** there is no `--live`.

## Lifetimes and probing

An address stays for its family's `lifetime` after anything last saw it, whether the local discovery or a plugin. Without a family `lifetime`, the general `lifetime` applies.

The active discovery probes again every `rediscover`. By default that is a third of the shortest lifetime among the families that probe, so a quiet host is probed before it expires.

A name stays for the `lifetime` of `hostnames`, in the same way: see [names](#the-lifetime).

```yaml
lifetime: 2h
rediscover: 20m
ipv4:
  enabled: true
  lifetime: 30m
```

### What a start can't find at once

A start can't immediately find an address that a host keeps next to the one it uses. A stable address next to temporary ones is the usual case.

A host answers the multicast ping from one address, its preferred one, and sends nothing from its others.

- An address the host gets while the worker runs is learned from the advertisement the host sends for it.
- A worker that starts later, for example after a restart, only learns that address when the host sends from it. The solicitation the host sends then gives the address away.

Two things find such an address sooner:

- A router's [plugin](plugins.md) knows the addresses in use from the router's neighbor table.
- A solicitation finds an EUI-64 address that a filter names.

### Settings that lose hosts

Three settings are accepted, but they lose hosts that are there, so each gets a warning at start:

- **A `rediscover` that is not shorter than the lifetime of a family that probes.** Hosts that stay quiet expire between probes.
- **With `arp`, an IPv4 lifetime of a minute or less.** The neighbor table is only read every minute.
- **A family that listens with no enabled protocol that finds its hosts.** It only registers this machine's own addresses.

In the library, `DefaultConfig` leaves `Rediscover` at zero, so that it follows a `Lifetime` you change afterwards.
