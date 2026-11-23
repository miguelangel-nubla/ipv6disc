# Configuration reference

<!-- Generated from the code by `go test ./cmd/ipv6disc -update`: edit it, not this page. -->

The configuration file is YAML, or JSON, given as `ipv6disc --config discovery.yaml`. Without the flag no file is read, and every key has its default: IPv6 is discovered, by the protocols that find hosts. Every key is optional. A duration is `90s`, `1m30s`, `4h`, or a number of seconds. A key there is none of, a key written twice, and a value of another type than its key takes, are errors at start, each with where it is and what there is; so is a second document after a `---`. The schema is [`pkg/config/schema.json`](../../pkg/config/schema.json), and the [discovery](../discovery.md) page says what each key does.

## Top level

How hosts are found: on the local links, by the protocols turned on, and by plugins that read routers' tables. Every key is optional: a key left out has its default.

| Key | Takes | Default | |
|---|---|---|---|
| `lifetime` | duration | `4h` | How long an address stays after it was last seen, unless its family sets its own. |
| `rediscover` | duration | - | How often active discovery probes every host. Default: a third of the shortest lifetime among the families that probe, so that a quiet host is probed before it expires. |
| `interfaces` | list, or comma separated | - | The interfaces local discovery runs on, for both families: names, or patterns such as en*. Default: all. Plugins aren't affected. |
| `exclude_interfaces` | list, or comma separated | - | The interfaces local discovery skips: names, or patterns such as docker* or veth*. |
| `ipv6` | mapping | - | IPv6: switches for all its protocols at once. A protocol runs only when it's enabled under protocols, and its family and the way it works are on here. |
| `ipv4` | mapping | - | IPv4: switches for all its protocols at once. A protocol runs only when it's enabled under protocols, and its family and the way it works are on here. |
| `hostnames` | mapping | - | The hosts' names, which are always kept. They come from each protocol under protocols that learns names, and from plugins, which read their routers' DHCP leases. To learn none, turn those protocols off, and the names option of ssdp and wsd. |
| `protocols` | mapping | - | The local discovery protocols, each with its enabled switch and its options: always a mapping, never true or false on its own. A protocol runs when it's enabled and its family is on and listens, or, for what probes, is active. |
| `plugins` | mapping | - | The plugins, by name. Each reads the neighbor tables of a router or another host, and its DHCP leases: the names in them, and that an address found otherwise is leased. The plugin's name is the source of what it finds. |
| `log_level` | `debug`, `info`, `warn`, `error` | `info` | How much the log says. Only for the ipv6disc command. |

## IPv6

`ipv6`

IPv6: switches for all its protocols at once. A protocol runs only when it's enabled under protocols, and its family and the way it works are on here.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the family's addresses are kept, and the plugins read them. When off, the rest of the family is off too. |
| `listen` | boolean | `true` | Local discovery of IPv6: its protocols listen, and ask each host about what they heard of it. When off, only plugins find IPv6 addresses. |
| `active` | boolean | `true` | Probes every host on the links at each rediscover: the multicast ping, the SSDP search, the WS-Discovery probe and the mDNS query. Needs listen, which reads the answers. |
| `lifetime` | duration | - | How long the family's addresses stay after they were last seen, whatever found them, plugins included. Default: lifetime. |

## IPv4

`ipv4`

IPv4: switches for all its protocols at once. A protocol runs only when it's enabled under protocols, and its family and the way it works are on here.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `false` | Whether the family's addresses are kept, and the plugins read them. When off, the rest of the family is off too. |
| `listen` | boolean | `true` | Local discovery of IPv4: the neighbor table is read, and the hosts' ARP is heard. When off, only plugins find IPv4 addresses. |
| `active` | boolean | `true` | Probes every host on the subnets at each rediscover: the sweep, which broadcasts an ARP request for each address, and the mDNS query. Needs listen, which reads the answers. |
| `lifetime` | duration | - | How long the family's addresses stay after they were last seen, whatever found them, plugins included. Default: lifetime. |

## Hostnames

`hostnames`

The hosts' names, which are always kept. They come from each protocol under protocols that learns names, and from plugins, which read their routers' DHCP leases. To learn none, turn those protocols off, and the names option of ssdp and wsd.

| Key | Takes | Default | |
|---|---|---|---|
| `lifetime` | duration | - | How long a name stays after it was last given, whatever gave it, plugins included. Default: lifetime. |

## Protocols

`protocols`

The local discovery protocols, each with its enabled switch and its options: always a mapping, never true or false on its own. A protocol runs when it's enabled and its family is on and listens, or, for what probes, is active.

```yaml
protocols:
  mdns:
    enabled: true
    ask: false
  arp-sweep:
    enabled: false
```

### ndp

`protocols.ndp`

IPv6, listening. Neighbor discovery on each link: every advertisement and solicitation heard gives an address and its MAC. It also asks, with a neighbor solicitation, the MAC of whatever the other IPv6 protocols hear. Without it, ping, ssdp and wsd find nothing, and enabling them is an error. It needs root or CAP_NET_RAW.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### ping

`protocols.ping`

IPv6. Listening, an address is pinged before it expires, so that a host still there keeps it. Active, every host is pinged at once, through the all-nodes group. It needs root or CAP_NET_RAW.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### ssdp

`protocols.ssdp`

IPv6. SSDP, for UPnP devices. Active, a search goes to its group; listening hears the answers, on the port the search left from. No group is joined.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `names` | boolean | `true` | Whether a device that answers the search is asked for its description, over HTTP, to get its friendly name. |

### wsd

`protocols.wsd`

IPv6. WS-Discovery, for Windows and Samba. Active, a probe goes to its group; listening hears the answers, on the port the probe left from. No group is joined.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `names` | boolean | `true` | Whether a computer that answers the probe is asked for its metadata, over HTTP, to get its name. |

### mdns

`protocols.mdns`

Either family, listening. mDNS: it joins its groups, on port 5353. Whatever sends there is a host on the link, whose address is found as any other, and the name it announces is its name. Active, a query for services goes to the group.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `ask` | boolean | `true` | Whether to send questions: the query to the group at each rediscover, and to each host for its name. When off, mDNS only listens. |

### arp

`protocols.arp`

IPv4, listening. Reads the kernel's neighbor table every minute, and after each sweep.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### arp-sweep

`protocols.arp-sweep`

IPv4, active. Sweeps the local subnets: a UDP packet to the discard port of each address makes the kernel resolve it, which broadcasts an ARP request. arp or arp-listen hears the hosts that answer: enabling it without either is an error.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `max_prefix` | integer, 16 to 30 | `22` | The largest subnet swept whole, by prefix length: 22 is a /22, of 1022 addresses. In a larger one, only the /24 around the interface's address is swept, or the prefix of this length there, when that is smaller. |

### arp-listen

`protocols.arp-listen`

IPv4, listening. Hears the ARP that hosts send, through a packet socket that only listens, so each host is found at once instead of at the next table read. It needs Linux, and root or CAP_NET_RAW: without the privilege, the log says so once, and the rest runs.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | - | Whether the protocol runs. Default: true on Linux, the only system where it can; false elsewhere, where true is an error. |

### dhcp

`protocols.dhcp`

Either family, listening. Hears what DHCP clients broadcast as they ask for an address, through packet sockets that only listen. The address a client asks for is found as any other, and the name it gives its server is its name. It needs Linux, and root or CAP_NET_RAW: without the privilege, the log says so once, and the rest runs.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | - | Whether the protocol runs. Default: true on Linux, the only system where it can; false elsewhere, where true is an error. |

### lldp

`protocols.lldp`

Either family, listening. Hears what an interface's LLDP neighbor says about itself, through a packet socket that only listens. The addresses it's managed at are found as any other, and its system name is its name. It needs Linux, and root or CAP_NET_RAW: without the privilege, the log says so once, and the rest runs.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | - | Whether the protocol runs. Default: true on Linux, the only system where it can; false elsewhere, where true is an error. |

### netbios

`protocols.netbios`

IPv4, listening. Asks each host for its node status, with a question sent to it alone: Windows and Samba answer with the machine's name. Names only.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### llmnr

`protocols.llmnr`

Either family, listening. Asks a host for the name of one of its addresses, through the LLMNR group, which every host on the link hears: Windows and systemd-resolved answer. Names only.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### dns

`protocols.dns`

Of either family. Asks DNS servers for each address's name, its PTR record, including those of hosts the plugins found. Names only.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs, once it has servers, the only ones it asks. |
| `servers` | list, or comma separated | - | The servers to ask; without any, dns asks nobody. Each is an address, with or without a port, as 192.168.1.1, 192.168.1.1:5353 or [fd00::1]:53. Only these are asked, never the system's resolver. |

## Plugins

`plugins.<name>`

The plugins, by name. Each reads the neighbor tables of a router or another host, and its DHCP leases: the names in them, and that an address found otherwise is leased. The plugin's name is the source of what it finds.

Each has its `type`, one of `freebsd`, `linux`, `mikrotik`, and the fields of that type, which the [plugins reference](plugins.md) lists.
