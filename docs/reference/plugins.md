# Plugins

<!-- Generated from the code by `go test ./cmd/ipv6disc -update`: edit it, not this page. -->

Each plugin is a key of `plugins` in the [configuration file](configuration.md#plugins), its name, with its `type` and the fields of that type. See [plugins](../plugins.md).

```yaml
plugins:
  router:
    type: linux
    interval: 60s
    address: 192.168.1.1
    username: root
    identity_file: /key
```

A field is a string, in quotes when YAML would read it as something else, as a password of digits, but those that say otherwise. From Go, `plugins.Create` takes them as its params: in this order, separated by commas, or by name in any order, `interval=60s,address=192.168.1.1,...`, where a comma in a value is written `\,`, and a backslash before a comma or another backslash `\\`.

## freebsd

A FreeBSD host, as pfSense or OPNsense, over SSH: `ndp -an` for IPv6, `arp -an` for IPv4, and with `hostnames` the names of the DHCP leases of ISC dhcpd, Kea and dnsmasq.

| Field | Takes | |
|---|---|---|
| `interval` | duration | **Required.** How often the table is read: 60s, 5m. |
| `address` | string | **Required.** The host, with its port unless 22: 192.168.1.1, [2001:db8::1]:2222. |
| `username` | string | **Required.** The SSH user. |
| `password` | string | Its password. Or an identity_file, or both. |
| `identity_file` | string | The SSH private key file. |
| `host_key` | string | The fingerprint of the host's SSH key, any of them when it has several, SHA256:..., as ssh-keygen -l shows it. Recommended: without it, any key is accepted, and the log warns with the fingerprint seen. |

## linux

A Linux host, as OpenWrt, over SSH: `ip neigh`, and with `hostnames` the names of the DHCP leases of dnsmasq and odhcpd.

| Field | Takes | |
|---|---|---|
| `interval` | duration | **Required.** How often the table is read: 60s, 5m. |
| `address` | string | **Required.** The host, with its port unless 22: 192.168.1.1, [2001:db8::1]:2222. |
| `username` | string | **Required.** The SSH user. |
| `password` | string | Its password. Or an identity_file, or both. |
| `identity_file` | string | The SSH private key file. |
| `host_key` | string | The fingerprint of the host's SSH key, any of them when it has several, SHA256:..., as ssh-keygen -l shows it. Recommended: without it, any key is accepted, and the log warns with the fingerprint seen. |

## mikrotik

A Mikrotik router, over its API: `/ipv6/neighbor` for IPv6, `/ip/arp` for IPv4, and with `hostnames` the names of `/ip/dhcp-server/lease`.

| Field | Takes | |
|---|---|---|
| `interval` | duration | **Required.** How often the tables are read: 60s, 5m. |
| `address` | string | **Required.** The router, with its port unless the default: 8728, or 8729 with TLS. |
| `username` | string | **Required.** An API user: the read and api policies are enough. |
| `password` | string | Its password. |
| `use_tls` | boolean | true or false: the API over TLS, the api-ssl service. Without it, the password crosses the network in the clear. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the router's certificate, 64 hex digits, colons allowed, when the system's CAs can't verify it, as the self-signed one RouterOS makes. It needs use_tls. |
