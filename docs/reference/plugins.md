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

A FreeBSD host, as pfSense or OPNsense, over SSH: `ndp -an` for IPv6, `arp -an` for IPv4, and the DHCP leases of ISC dhcpd, Kea and dnsmasq.

| Field | Takes | |
|---|---|---|
| `interval` | duration | **Required.** How often the table is read, as 60s or 5m. |
| `address` | string | **Required.** The host, with its port unless it's 22, as 192.168.1.1 or [2001:db8::1]:2222. |
| `username` | string | **Required.** The SSH user. |
| `password` | string | Its password. An identity_file works instead, or as well. |
| `identity_file` | string | The SSH private key file. |
| `host_key` | string | The fingerprint of the host's SSH key, as ssh-keygen -l shows it: SHA256:.... Any of its keys works. Recommended: without it, any key is accepted, and the log warns with the fingerprint it saw. |

## linux

A Linux host, as OpenWrt, over SSH: `ip neigh`, and the DHCP leases of dnsmasq and odhcpd.

| Field | Takes | |
|---|---|---|
| `interval` | duration | **Required.** How often the table is read, as 60s or 5m. |
| `address` | string | **Required.** The host, with its port unless it's 22, as 192.168.1.1 or [2001:db8::1]:2222. |
| `username` | string | **Required.** The SSH user. |
| `password` | string | Its password. An identity_file works instead, or as well. |
| `identity_file` | string | The SSH private key file. |
| `host_key` | string | The fingerprint of the host's SSH key, as ssh-keygen -l shows it: SHA256:.... Any of its keys works. Recommended: without it, any key is accepted, and the log warns with the fingerprint it saw. |

## mikrotik

A Mikrotik router, over its API: `/ipv6/neighbor` for IPv6, `/ip/arp` for IPv4, and the DHCP leases of `/ip/dhcp-server/lease`.

| Field | Takes | |
|---|---|---|
| `interval` | duration | **Required.** How often the tables are read, as 60s or 5m. |
| `address` | string | **Required.** The router, with its port unless it's the default: 8728, or 8729 with TLS. |
| `username` | string | **Required.** An API user: the read and api policies are enough. |
| `password` | string | Its password. |
| `use_tls` | boolean | Whether to use the API over TLS, the api-ssl service. Without it, the password crosses the network unencrypted. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the router's certificate, as 64 hex digits, colons allowed. For when the system's CAs can't verify it, as with the self-signed one RouterOS makes. It needs use_tls. |

## unifi

A UniFi gateway, through the UniFi Network API: the clients connected now, of a UniFi OS console or UniFi OS Server, or of a self-hosted Network Application. Their IPv4 address, their IPv6 addresses where UniFi has them, the host name they gave, and the name you gave them in UniFi.

| Field | Takes | |
|---|---|---|
| `interval` | duration | **Required.** How often the clients are read, as 60s or 5m. |
| `address` | string | **Required.** The console, as https://192.168.1.1, or the self-hosted Network Application, as https://192.168.1.2:8443. |
| `api_key` | string | An API key of UniFi OS: in the console, Settings, Control Plane, Integrations. A self-hosted Network Application has none: give username and password instead. |
| `username` | string | A local user, instead of api_key, without two-factor authentication. Reading is enough. |
| `password` | string | Its password. |
| `site` | string | The site, by its name in the API: default unless you made others. Default: default. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the console's certificate, as 64 hex digits, colons allowed. For when the system's CAs can't verify it, as with the one a console makes for itself. |
