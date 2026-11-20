# Plugins

<!-- Generated from the code by `go test ./cmd/ipv6disc -update`: edit it, not this page. -->

`-plugin name=type:params`, the params in this order, separated by commas, or by name in any order: `interval=60s,address=192.168.1.1,...`. The optional ones at the end can be left out. A comma in a value is written `\,`, and a backslash before a comma or another backslash `\\`. See [plugins](../plugins.md).

## freebsd

A FreeBSD host, as pfSense or OPNsense, over SSH: `ndp -an` for IPv6, `arp -an` for IPv4.

| Param | |
|---|---|
| `interval` | **Required.** How often the table is read: 60s, 5m. |
| `address` | **Required.** The host, with its port unless 22: 192.168.1.1, [2001:db8::1]:2222. |
| `username` | **Required.** The SSH user. |
| `password` | Its password. Or an identity_file, or both. |
| `identity_file` | The SSH private key file. |
| `host_key` | The fingerprint of the host's SSH key, any of them when it has several, SHA256:..., as ssh-keygen -l shows it. Recommended: without it, any key is accepted, and the log warns with the fingerprint seen. |

## linux

A Linux host, as OpenWrt, over SSH: `ip neigh`.

| Param | |
|---|---|
| `interval` | **Required.** How often the table is read: 60s, 5m. |
| `address` | **Required.** The host, with its port unless 22: 192.168.1.1, [2001:db8::1]:2222. |
| `username` | **Required.** The SSH user. |
| `password` | Its password. Or an identity_file, or both. |
| `identity_file` | The SSH private key file. |
| `host_key` | The fingerprint of the host's SSH key, any of them when it has several, SHA256:..., as ssh-keygen -l shows it. Recommended: without it, any key is accepted, and the log warns with the fingerprint seen. |

## mikrotik

A Mikrotik router, over its API: `/ipv6/neighbor` for IPv6, `/ip/arp` for IPv4.

| Param | |
|---|---|
| `interval` | **Required.** How often the tables are read: 60s, 5m. |
| `address` | **Required.** The router, with its port unless the default: 8728, or 8729 with TLS. |
| `username` | **Required.** An API user: the read and api policies are enough. |
| `password` | Its password. |
| `use_tls` | true or false: the API over TLS, the api-ssl service. Without it, the password crosses the network in the clear. |
| `tls_fingerprint` | The SHA-256 fingerprint of the router's certificate, 64 hex digits, colons allowed, when the system's CAs can't verify it, as the self-signed one RouterOS makes. It needs use_tls. |
