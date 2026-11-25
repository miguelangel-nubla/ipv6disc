# Plugins

A plugin reads the neighbor table of another host, usually a router, every `interval`, and registers the entries. It also reads that host's DHCP [leases](#leases). A `unifi` plugin reads, instead, the clients a UniFi gateway knows are connected: see [UniFi](#unifi).

Use a plugin to find the hosts of networks the local discovery doesn't reach, such as other VLANs. Or use plugins to find all hosts, where the local discovery can't run.

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

Each key of `plugins`, in the [configuration file](reference/configuration.md#plugins), is one plugin. The key is the plugin's name, and that name is the source of everything the plugin finds. You can have any number of plugins, for several hosts.

- Each plugin has a `type`: `linux`, `freebsd`, `mikrotik` or `unifi`. It also has the fields of that type, which are listed in the [plugins reference](reference/plugins.md).
- A field the type doesn't have, or a value of the wrong type, is an error at start.
- A password is taken exactly as written, including its spaces. Put it in quotes when YAML would read it as something else, such as a password made of digits only.

## What they register

- **The tables of the enabled families.** A plugin reads the IPv6 neighbors and, with `ipv4` enabled, the ARP table too.
- **Only entries confirmed recently.** A router can keep an entry long after its host left, and the addresses of hosts that left must expire.
- **Only hosts.** The multicast groups that a MikroTik router lists among its neighbors are left out.
- **The plugin's name as the source.** Each address is registered with it.

A link-local address arrives with the other host's interface as its zone, such as `fe80::1%em0`. The zone is dropped. It is never mistaken for an interface of this machine.

A poll takes 30 seconds at most, including the time to connect. A host that doesn't answer is an error for that poll only, and the next poll runs at its usual time. Stopping the program stops the poll in progress, and that is not reported as an error.

## Leases

In the same poll, a plugin also reads its router's DHCP leases. It does so whatever [protocols](discovery.md#protocols) are enabled. It uses two things from each lease:

- **The lease's name** becomes a [name](discovery.md#names) of the lease's MAC, with the plugin's name as its source. A name belongs to the host whatever the family of the lease. The name from a DHCPv4 lease also names the host for its IPv6 addresses.
- **The lease's address** gets a record, reported by the plugin from `leases`, but only when discovery already has that address at that MAC. A program can filter on this record, for example to take only the addresses its DHCP server handed out.

A lease never registers an address. A server keeps the lease of a host that left until the lease ends, so a lease alone doesn't show that a host is there. For the same reason, a lease keeps an address no longer than whatever found the address.

Where each type reads the leases:

| Type | Leases read |
|---|---|
| `mikrotik` | `/ip/dhcp-server/lease`: the `host-name` of the leases that are `bound`. The bindings of the DHCPv6 server have no name to read |
| `linux` | dnsmasq's leases, and the hosts file that odhcpd writes for its DHCPv6 leases |
| `freebsd` | The leases of ISC dhcpd, of Kea, and of dnsmasq |

The files, by type:

- **`linux`**
  - dnsmasq: `/tmp/dhcp.leases`, where OpenWrt keeps it, or `/var/lib/misc/dnsmasq.leases`.
  - odhcpd: `/tmp/hosts/odhcpd`.
- **`freebsd`**
  - ISC dhcpd: `/var/dhcpd/var/db/dhcpd.leases`, the leases in the state `active`.
  - Kea: `/var/lib/kea/dhcp4.leases` and `dhcp6.leases`, where pfSense keeps them, or `/var/db/kea/kea-leases4.csv` and `kea-leases6.csv`, where OPNsense keeps them. Only the assigned leases are used.
  - dnsmasq: `/var/db/dnsmasq.leases`.

More details:

- **DHCPv6.** A DHCPv6 lease identifies its client by a DUID, not by a MAC. Its name goes to the MAC at which the neighbor table, read in the same poll, has the leased address, if the address is in use.
- **Missing files.** A file that isn't there, such as the file of a server the host doesn't run, is not an error. The plugin's user must be allowed to read the files that are there.
- **Cleaning.** The names are as the clients gave them, cleaned like [any name](discovery.md#what-a-name-is). Something that is not a name, such as the `*` of a lease without a name, is left out.
- **Lifetime.** A name stays for its lifetime after the last poll that read it. So the lease of a host that left stops naming the host once the router drops the lease.

## SSH host keys

Give a `linux` or `freebsd` plugin its `host_key`, so that nobody in between can pose as the host. To get the key, run this from a trusted network:

```
ssh-keyscan 192.168.1.1 | ssh-keygen -lf -
```

A host usually has several keys, one of each kind, and this command lists them all. The fingerprint of any of them works.

- The plugin asks the host for its key of each kind until the host shows the one you gave, and remembers which kind it was.
- A host that has no key with that fingerprint is refused, before the password or the command is sent to it. The error lists the fingerprints the host showed.

Without `host_key`, any key is accepted. The log warns once, after the first poll that succeeds, with the fingerprint the host showed.

## A Mikrotik user

The plugin only reads. Give it a user of its own, with the `read` and `api` policies, limited to the address the plugin connects from:

```
/user group add name=ipv6disc policy=read,api
/user add name=ipv6disc group=ipv6disc address=192.168.88.10/32 password=...
```

The `api` service must be on, under `/ip/service`, or `api-ssl` if you set `use_tls: true`.

- Without `use_tls: true`, the password crosses the network unencrypted.
- `use_tls` is `true` or `false`. Anything else is an error.
- A `tls_fingerprint` without `use_tls: true` is an error too, because it would not be checked.

With `use_tls: true` alone, the router's certificate is verified against the system's CAs, for the name or address in `address`. That fails in two common cases: the certificate RouterOS makes for itself is self-signed, and the Docker image has no CAs at all. In those cases, give the certificate's `tls_fingerprint`. The fingerprint is then the only thing checked. To get it:

```
openssl s_client -connect 192.168.88.1:8729 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

To verify a certificate from a public CA in the Docker image instead, mount the host's CAs into the container: `-v /etc/ssl/certs:/etc/ssl/certs:ro`.

## UniFi

A `unifi` plugin reads the clients that a UniFi gateway's UniFi Network has connected now, UniFi's own devices included, through the UniFi Network API. It works with a UniFi OS console, such as a UDM, UDR, UCG or UXG, with UniFi OS Server, and with a self-hosted UniFi Network Application.

```yaml
plugins:
  gateway:
    type: unifi
    interval: 60s
    address: https://192.168.1.1
    api_key: your-api-key
    tls_fingerprint: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

What it registers, of each client:

- **Its IPv4 address**, with `ipv4` enabled, and **its IPv6 addresses**, where UniFi has them: as from the gateway's neighbors, since the clients listed are those connected now. UniFi doesn't always know a client's IPv6 addresses, privacy ones in particular: the local discovery, or a plugin of the router's neighbor table, finds those.
- **Two [names](discovery.md#names)**, when names are on: the host name the client gave the gateway's DHCP server, and the name you gave it in UniFi, as a lease's name. Each is cleaned like any name: spaces become hyphens, and a name with a character no name has, such as an apostrophe, is left out.

To log in:

- **A UniFi OS console, or UniFi OS Server:** an `api_key`, which a console makes under Settings, Control Plane, Integrations. Or a `username` and `password`.
- **A self-hosted Network Application:** a `username` and `password`. It has no API keys.

The user only reads: give it a role that can't change anything. A user with two-factor authentication can't log in. The `site` is `default` unless you made others.

A console's certificate is its own, so give its `tls_fingerprint`, which the certificate is then checked by, alone:

```
openssl s_client -connect 192.168.1.1:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

## Writing one

A plugin implements `ipv6disc.Plugin`, and registers its type in `init` with `plugins.Register`. The plugins in [`pkg/plugins`](../pkg/plugins) are the examples to follow.

- **Fields.** Register the plugin's params as fields, each with its description and, when it isn't a string, its type. The configuration file accepts them, the [reference](reference/plugins.md) is generated from them, and `plugins.FieldParams` builds the params for programs that have them as fields.
- **Schema.** The [schema](../pkg/config/schema.json) of the configuration also lists each type's fields. A test fails when the schema is behind the plugins.
- **`plugins.Describe`** only gives a type its description. `plugins.Register` is what creates the type.
- **`plugins.Poller`** runs the polls and keeps their stats. Its `Run` needs a positive interval, and returns an error otherwise. The `Start` of the plugins here returns the same error for a config built by hand without an interval.
