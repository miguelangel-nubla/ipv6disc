# Plugins

A plugin reads the neighbor table of another host, a router usually, every `interval`, and registers its entries, and with `hostnames` the [names](#names) of its DHCP leases: it finds the hosts of networks the local discovery doesn't reach, as other VLANs, or all of them where the local discovery can't run.

```yaml
plugins:
  router:
    type: linux
    interval: 60s
    address: 192.168.1.1
    username: root
    identity_file: /key
    host_key: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Each key of `plugins`, in the [configuration file](reference/configuration.md#plugins), is a plugin by its name, which is the source of what it finds: any number of them, for several hosts. Each has its `type`, `linux`, `freebsd` or `mikrotik`, and the fields of that type, which are in the [plugins reference](reference/plugins.md). A field the type doesn't have, and one of the wrong type, are errors at start. A password is taken as written, its spaces too: in quotes when YAML would read it as something else, as one of digits alone.

## What they register

The tables of the families on: IPv6 neighbors, and with `ipv4` enabled the ARP tables too. Only the entries confirmed recently: a router can keep an entry long after its host left, and the addresses of hosts that left must expire. Each address is registered with the plugin's name as its source.

Only hosts: the multicast groups a Mikrotik router lists among its neighbors are left out. A link-local address comes from the other host with that host's interface as its zone, `fe80::1%em0`: the zone is dropped, never taken for an interface of this machine.

A poll takes 30 seconds at most, connecting included: a host that doesn't answer is an error of that poll, and the next one runs at its time. Stopping the program stops the poll under way, which is not reported as an error.

## Names

With `hostnames` enabled, a plugin also reads the host names of its router's DHCP leases, whatever [protocols](discovery.md#protocols) are, in the same poll, and registers each as a [name](discovery.md#names) of the lease's MAC, with the plugin's name as its source. A name is the host's whatever the family of the lease: one of a DHCPv4 lease names the host for its IPv6 addresses too. A lease registers no address, only the name.

| | |
|---|---|
| `mikrotik` | `/ip/dhcp-server/lease`: the `host-name` of the leases that are `bound`. The bindings of the DHCPv6 server have no name to read |
| `linux` | The leases of dnsmasq, `/tmp/dhcp.leases` as OpenWrt has it, or `/var/lib/misc/dnsmasq.leases`; and the hosts file odhcpd writes of its DHCPv6 leases, `/tmp/hosts/odhcpd` |
| `freebsd` | The leases of ISC dhcpd, `/var/dhcpd/var/db/dhcpd.leases`, those in the state `active`; of Kea, `/var/lib/kea/dhcp4.leases` and `dhcp6.leases` as pfSense has them, or `/var/db/kea/kea-leases4.csv` and `kea-leases6.csv` as OPNsense does, those assigned; and of dnsmasq, `/var/db/dnsmasq.leases` |

A DHCPv6 lease knows its client by a DUID, not by a MAC: its name goes to the MAC the neighbor table, read at the same time, has the leased address at, if it is in use. A file that isn't there, as those of the servers the host doesn't run, says nothing, and the user of the plugin needs to be let read those that are. The names are as the clients gave them, cleaned as [any name](discovery.md#what-a-name-is): one that is none, as the `*` of a lease without a name, is left out.

A name stays for its lifetime after the last poll that read it: the lease of a host that left stops naming it when the router drops it.

## SSH host keys

Give a `linux` or `freebsd` plugin its `host_key`, so that nobody in between can pass for the host. To get it, from a trusted network:

```
ssh-keyscan 192.168.1.1 | ssh-keygen -lf -
```

A host usually has several keys, one of each kind, and this lists them all: the fingerprint of any of them works. The plugin asks the host for its key of each kind until it shows the one given, and remembers which it was. A host that has none with that fingerprint is refused, with the fingerprints it showed in the error, before the password or the command is sent to it.

Without `host_key` any key is accepted, and the log warns once, after the first poll that succeeds, with the fingerprint the host showed.

## A Mikrotik user

The plugin only reads, so give it a user of its own, with the `read` and `api` policies, limited to the address it connects from:

```
/user group add name=ipv6disc policy=read,api
/user add name=ipv6disc group=ipv6disc address=192.168.88.10/32 password=...
```

The `api` service, or `api-ssl` with `use_tls: true`, must be on, under `/ip/service`. Without `use_tls: true` the password crosses the network in the clear. `use_tls` is `true` or `false`, anything else is an error, and so is a `tls_fingerprint` without `use_tls: true`: it would not be checked.

With `use_tls: true` alone, the router's certificate is verified with the system's CAs, for the name or address in `address`. The certificate RouterOS makes for itself is self-signed, and the Docker image has no CAs at all: there, give its `tls_fingerprint`, which is then all that is checked:

```
openssl s_client -connect 192.168.88.1:8729 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

In the image, a certificate of a public CA is verified with the host's CAs mounted in instead: `-v /etc/ssl/certs:/etc/ssl/certs:ro`.

## Writing one

A plugin implements `ipv6disc.Plugin`, and registers its type in `init` with `plugins.Register`, its params as fields, each with its description and, when it is no string, its type: the configuration file takes them, the [reference](reference/plugins.md) is made of them, and `plugins.FieldParams` builds the params of programs that have them as fields. The [schema](../pkg/config/schema.json) of the configuration lists the fields of each type too: a test fails when it is behind the plugins. The plugins of [`pkg/plugins`](../pkg/plugins) are the examples. `plugins.Describe` only gives a type its description: it is `plugins.Register` that makes it one.

`plugins.Poller` runs the polls and keeps their stats: its `Run` needs a positive interval, and returns an error otherwise, as `Start` of the plugins here does for a config built by hand without one.
