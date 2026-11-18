# IPv6 Host Discovery

[![ci](https://github.com/miguelangel-nubla/ipv6disc/actions/workflows/ci.yaml/badge.svg)](https://github.com/miguelangel-nubla/ipv6disc/actions/workflows/ci.yaml)
[![release](https://img.shields.io/github/v/release/miguelangel-nubla/ipv6disc)](https://github.com/miguelangel-nubla/ipv6disc/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/miguelangel-nubla/ipv6disc.svg)](https://pkg.go.dev/github.com/miguelangel-nubla/ipv6disc)

This program scans the local network and discovers IPv6 hosts addresses.

Used by [ipv6ddns](https://github.com/miguelangel-nubla/ipv6ddns)

## Installation

Download the [latest release](https://github.com/miguelangel-nubla/ipv6disc/releases/latest) for your architecture.

### Or use the docker image

Minimal run (active discovery only):
```
docker run -it --rm --network host ghcr.io/miguelangel-nubla/ipv6disc -live
```

Run with plugins (recommended):
```
docker run -it --rm --network host ghcr.io/miguelangel-nubla/ipv6disc \
  -live \
  -plugin "router-main=mikrotik:60s,192.168.88.1,admin,password"
```

The image is built for linux/386, amd64, arm/v6, arm/v7 and arm64. Active discovery needs the host's network (`--network host`) and raw sockets: the `NET_RAW` capability, which Docker grants by default but other runtimes, or a Kubernetes `securityContext`, can drop. Without them, listening fails with `operation not permitted`, and only the plugins work.

> [!IMPORTANT]
> **Docker IPv6 support is experimental/fragile.** Active local discovery (NDP/Multicast) often fails inside containers depending on the host network configuration. It is **highly recommended** to use [Plugins](#plugins) to fetch neighbor data directly from your router instead.

### Or build from source

Use `go install github.com/miguelangel-nubla/ipv6disc/cmd/ipv6disc@latest` to build and install the binary.

## How it Works

The tool uses two complementary methods to discover IPv6 hosts:

### 1. Active Local Discovery
It listens on all available IPv6 interfaces and actively scans for hosts using multiple protocols:
- **ICMPv6**: Sends multicast Echo Requests (ping) to all nodes.
- **SSDP**: Sends Simple Service Discovery Protocol M-SEARCH packets (used by UPnP).
- **WS-Discovery**: Sends Web Services for Devices Probe messages (used by Windows network discovery).

When a host responds to any of these probes, the tool triggers a specific **NDP (Neighbor Discovery Protocol)** solicitation to resolve the host's MAC address and register it.

### 2. Plugin Integration
For hosts that might not be directly reachable via multicast (e.g. on different VLANs or filtered by firewalls) or to get a comprehensive view from the network gateway, `ipv6disc` supports plugins.
Plugins connect to routers/firewalls (Linux, FreeBSD/OPNsense, Mikrotik) to fetch their known neighbor tables. This allows populating the list with hosts that the router sees.

### 3. IPv4 neighbors, with `-ipv4`
Off by default. With it:
- The plugins also read their host's IPv4 neighbor table, ARP: `ip neigh`, `arp -an`, `/ip/arp/print`.
- The local discovery reads the kernel's: through netlink on Linux, with no command needed; `arp -an` on macOS and the BSDs; not on Windows.
- With active discovery, it first sends a UDP packet to the discard port of each address of the local subnets (a /22 at most, or the /24 of the address), so the kernel resolves the hosts that stay quiet. That needs no privilege.

As for IPv6, only the entries confirmed recently count, so that hosts that left expire.

## Usage

By default, it will output the discovered hosts as JSON messages to `stdout`. You can easily parse the output with [`jq`](https://stedolan.github.io/jq/).

> [!NOTE]
> This utility needs to be executed as a superuser to be able to listen for IPv6 ICMP packets.

```
sudo ipv6disc | jq 'select(.msg == "host identified") | .ip'
```

Alternatively, using `-live` the data will be displayed on the screen in a human-readable form.

If you need to pause and select/copy data use `screen`, launch `ipv6disc -live [...]` and press `Ctrl+a` and then `ESC` to enter copy mode. Now you can use the mouse to copy text. When finished `ESC` again will continue updating.

## Flags

- `-log_level`: Set the logging level (default: "info"). Available options: "debug", "info", "warn", "error", "fatal", "panic".
- `-lifetime`: Set the lifetime for a discovered host entry after it has been last seen (default: 4 hours).
- `-live`: Show the current state live on the terminal (default: false).
- `-ipv4`: Discover IPv4 neighbors too, see above (default: false).
- `-plugin`: Plugin configuration: `name=type:params` (can be specified multiple times, multiple instances of the same plugin connected to different hosts are allowed)

## Plugins

The params are separated by commas. A comma in a value, as in a password, is written `\,`, and a backslash before a comma or another backslash `\\`.

The plugins register the neighbors their host saw recently: they skip the stale entries, which a router can keep long after their host left, so that the addresses of hosts that left expire.

### Linux / OpenWrt
connect to a Linux host via SSH and parse `ip -6 neigh` output.
format: `name=linux:interval,address,username,password[,identity_file[,host_key]]`
- `interval`: Polling interval (e.g. `60s`, `5m`)
- `address`: Hostname or IP address (and optional port) (e.g., `192.168.1.1`, `[2001:db8::1]:2222`)
- `username`: SSH username
- `password`: SSH password (optional if identity_file provided)
- `identity_file`: Path to SSH private key file (optional, leave it empty to give a host key only)
- `host_key`: Fingerprint of the host's SSH key, `SHA256:...` (recommended). Without it any key is accepted, so anyone in between can impersonate the host, and a warning tells the fingerprint seen. To get it from a trusted network: `ssh-keyscan -t ed25519 192.168.1.1 | ssh-keygen -lf -`

### pfSense / OPNsense / FreeBSD
Connect to a FreeBSD host via SSH and parse `ndp -an` output.
format: `name=freebsd:interval,address,username,password[,identity_file[,host_key]]`
- `interval`: Polling interval (e.g. `60s`, `5m`)
- `address`: Hostname or IP address (and optional port)
- `username`: SSH username
- `password`: SSH password (optional if identity_file provided)
- `identity_file`: Path to SSH private key file (optional, leave it empty to give a host key only)
- `host_key`: Fingerprint of the host's SSH key, `SHA256:...` (recommended). Without it any key is accepted, so anyone in between can impersonate the host, and a warning tells the fingerprint seen. To get it from a trusted network: `ssh-keyscan -t ed25519 192.168.1.1 | ssh-keygen -lf -`

### Mikrotik
Connect to a Mikrotik router via API and parse IPv6 neighbor list.
format: `name=mikrotik:interval,address,username,password[,use_tls[,tls_fingerprint]]`
- `interval`: Polling interval (e.g. `60s`, `5m`)
- `address`: Hostname or IP address (and optional port). Defaults to port 8728 (plain) or 8729 (TLS).
- `username`: API username
- `password`: API password
- `use_tls`: `true`/`false` (default: false)
- `tls_fingerprint`: Expected SHA256 fingerprint of the server certificate (optional)
