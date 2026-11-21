# Configuration reference

<!-- Generated from the code by `go test ./cmd/ipv6disc -update`: edit it, not this page. -->

The configuration file is YAML, or JSON, given as `ipv6disc -config_file discovery.yaml`. Without the flag no file is read, and every key has its default: IPv6 is discovered, by the protocols that find hosts. Every key is optional. A duration is `90s`, `1m30s`, `4h`, or a number of seconds. A key there is none of, a key written twice, and a value of another type than its key takes, are errors at start, each with where it is and what there is; so is a second document after a `---`. The schema is [`pkg/config/schema.json`](../../pkg/config/schema.json), and the [discovery](../discovery.md) page says what each key does.

## Top level

How hosts are discovered: on the local links, by the protocols enabled, and by plugins reading the tables of routers. Every key is optional: what is left out is its default.

| Key | Takes | Default | |
|---|---|---|---|
| `lifetime` | duration | `4h` | How long an address stays after it was last seen, unless its family says. |
| `rediscover` | duration | - | How often the active discovery probes every host. Default: a third of the shortest lifetime of the families that probe, so that a quiet host is probed before it expires. |
| `interfaces` | list, or comma separated | - | The interfaces the local discovery of both families runs on: names, or patterns as en*. Default: all. The plugins aren't concerned. |
| `exclude_interfaces` | list, or comma separated | - | The interfaces the local discovery doesn't run on: names, or patterns as docker*, veth*. |
| `ipv6` | mapping | - | IPv6: the switches of all its protocols at once. A protocol runs only when it is enabled, under protocols, and its family, and the way it works, are on here. |
| `ipv4` | mapping | - | IPv4: the switches of all its protocols at once. A protocol runs only when it is enabled, under protocols, and its family, and the way it works, are on here. |
| `hostnames` | mapping | - | The names of the hosts: always kept, of what learns them, each protocol under protocols that does, and the plugins, of their routers' DHCP leases. To learn none, disable those protocols, and the names of ssdp and wsd. |
| `protocols` | mapping | - | The protocols of the local discovery, each with its switch, enabled, and its options: always a mapping, never true or false alone. One runs when it is enabled, its family is, and the family listens, or for what probes is active. |
| `plugins` | mapping | - | The plugins, by name: each reads the neighbor tables of a router or another host, and its DHCP leases: their names, and that an address found otherwise is leased. The name is the source of what it finds. |
| `log_level` | `debug`, `info`, `warn`, `error` | `info` | The level of the log. Of the ipv6disc command alone. |

## IPv6

`ipv6`

IPv6: the switches of all its protocols at once. A protocol runs only when it is enabled, under protocols, and its family, and the way it works, are on here.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the family's addresses are kept, and the plugins read them. Without it, the rest of the family is off. |
| `listen` | boolean | `true` | The local discovery of IPv6: its protocols hear, and ask one host of what they heard of it. Without it, only the plugins find IPv6 addresses. |
| `active` | boolean | `true` | Probing every host of the links, at every rediscover: the multicast ping, the search of SSDP, the probe of WS-Discovery, and the query of mDNS. Only with listen, which reads the answers. |
| `lifetime` | duration | - | How long the family's addresses stay after they were last seen, whatever found them, the plugins too. Default: lifetime. |

## IPv4

`ipv4`

IPv4: the switches of all its protocols at once. A protocol runs only when it is enabled, under protocols, and its family, and the way it works, are on here.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `false` | Whether the family's addresses are kept, and the plugins read them. Without it, the rest of the family is off. |
| `listen` | boolean | `true` | The local discovery of IPv4: the neighbor table is read, and the ARP of the hosts heard. Without it, only the plugins find IPv4 addresses. |
| `active` | boolean | `true` | Probing every host of the subnets, at every rediscover: the sweep, which broadcasts an ARP request for each address, and the query of mDNS. Only with listen, which reads the answers. |
| `lifetime` | duration | - | How long the family's addresses stay after they were last seen, whatever found them, the plugins too. Default: lifetime. |

## Hostnames

`hostnames`

The names of the hosts: always kept, of what learns them, each protocol under protocols that does, and the plugins, of their routers' DHCP leases. To learn none, disable those protocols, and the names of ssdp and wsd.

| Key | Takes | Default | |
|---|---|---|---|
| `lifetime` | duration | - | How long a name stays after it was last said, whatever said it, the plugins too. Default: lifetime. |

## Protocols

`protocols`

The protocols of the local discovery, each with its switch, enabled, and its options: always a mapping, never true or false alone. One runs when it is enabled, its family is, and the family listens, or for what probes is active.

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

IPv6, listening. The neighbor discovery of each link: every advertisement and solicitation heard tells an address and its MAC, and the MAC of whatever the others of IPv6 hear is asked by it, with a neighbor solicitation. Without it ping, ssdp and wsd find nothing, and are an error to enable. It needs root or CAP_NET_RAW.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### ping

`protocols.ping`

IPv6. Listening, an address is pinged before it expires, so that a host still there keeps it. Active, every host is, by a ping to the group of all nodes. It needs root or CAP_NET_RAW.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### ssdp

`protocols.ssdp`

IPv6. SSDP, of the UPnP devices: active, a search goes to its group, and listening hears the answers, at the port it left from. No group is joined.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `names` | boolean | `true` | Whether a device that answers the search is asked its description, over HTTP, for its friendly name. |

### wsd

`protocols.wsd`

IPv6. WS-Discovery, of Windows and Samba: active, a probe goes to its group, and listening hears the answers, at the port it left from. No group is joined.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `names` | boolean | `true` | Whether a computer that answers the probe is asked its metadata, over HTTP, for its name. |

### mdns

`protocols.mdns`

Either family, listening. mDNS: its groups are joined, on port 5353, and whatever sends there is a host of the link, whose address is found as any other, and what it announces is its name. Active, a query for the services goes to the group.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `ask` | boolean | `true` | Whether questions are sent: the query to the group, at every rediscover, and to each host for its name. Without it mDNS only listens. |

### arp

`protocols.arp`

IPv4, listening. The kernel's neighbor table, read every minute, and after each sweep.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### arp-sweep

`protocols.arp-sweep`

IPv4, active. A sweep of the local subnets: a UDP packet to the discard port of each address, so that the kernel resolves it, which broadcasts an ARP request for each. arp or arp-listen tells the hosts that answer: without both it is an error to enable.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `max_prefix` | integer, 16 to 30 | `22` | The largest subnet swept whole, by the length of its prefix: 22 is a /22, of 1022 addresses. A larger one is swept in the /24 of the interface's address only, or in the prefix of this length there when that is smaller. |

### arp-listen

`protocols.arp-listen`

IPv4, listening. The ARP the hosts send, heard by a packet socket that only listens: each is found at once, not at the next reading of the table. It needs Linux, and root or CAP_NET_RAW: without the privilege it is said once in the log, and the rest runs.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | - | Whether the protocol runs. Default: true on Linux, where alone it can; elsewhere false, and true is an error. |

### dhcp

`protocols.dhcp`

Either family, listening. What the DHCP clients say to all as they ask for an address, heard by packet sockets that only listen: the address a client asks for is found as any other, and the name it gives its server is its name. It needs Linux, and root or CAP_NET_RAW: without the privilege it is said once in the log, and the rest runs.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | - | Whether the protocol runs. Default: true on Linux, where alone it can; elsewhere false, and true is an error. |

### lldp

`protocols.lldp`

Either family, listening. What the LLDP neighbor of an interface says of itself, heard by a packet socket that only listens: the addresses it is managed at are found as any other, and its system name is its name. It needs Linux, and root or CAP_NET_RAW: without the privilege it is said once in the log, and the rest runs.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | - | Whether the protocol runs. Default: true on Linux, where alone it can; elsewhere false, and true is an error. |

### netbios

`protocols.netbios`

IPv4, listening. A host is asked its node status, by a question sent to it alone: Windows answers, and Samba, with the machine's name. Names only.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### llmnr

`protocols.llmnr`

Either family, listening. A host is asked the name of one of its addresses, by a question to the group of LLMNR, which every host of the link hears: Windows answers, and systemd-resolved. Names only.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### dns

`protocols.dns`

Of no family: DNS servers are asked the name of each address, its PTR record, of the hosts the plugins found too. Names only.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs: once it has servers, which it asks alone. |
| `servers` | list, or comma separated | - | The servers asked: without, dns asks nobody. each an address, alone or with its port, as 192.168.1.1, 192.168.1.1:5353 or [fd00::1]:53. Only these are asked, never the system's resolver. |

## Plugins

`plugins.<name>`

The plugins, by name: each reads the neighbor tables of a router or another host, and its DHCP leases: their names, and that an address found otherwise is leased. The name is the source of what it finds.

Each has its `type`, one of `freebsd`, `linux`, `mikrotik`, and the fields of that type, which the [plugins reference](plugins.md) lists.
