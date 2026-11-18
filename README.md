# ipv6disc: host discovery

[![ci](https://github.com/miguelangel-nubla/ipv6disc/actions/workflows/ci.yaml/badge.svg)](https://github.com/miguelangel-nubla/ipv6disc/actions/workflows/ci.yaml)
[![release](https://img.shields.io/github/v/release/miguelangel-nubla/ipv6disc)](https://github.com/miguelangel-nubla/ipv6disc/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/miguelangel-nubla/ipv6disc.svg)](https://pkg.go.dev/github.com/miguelangel-nubla/ipv6disc)

`ipv6disc` finds the hosts of the local network and their addresses, each with its MAC: IPv6, and IPv4 too. It listens to the network, probes it, and reads the neighbor tables of routers. The name is from when it was IPv6 only.

It is a command, and a Go library: [ipv6ddns](https://github.com/miguelangel-nubla/ipv6ddns) uses it to keep DNS records of the devices of a network.

## Installation

- **A release**: the binary for your system, from the [latest release](https://github.com/miguelangel-nubla/ipv6disc/releases/latest).
- **Docker**: `ghcr.io/miguelangel-nubla/ipv6disc`, for linux/386, amd64, arm/v6, arm/v7 and arm64.
- **From source**: `go install github.com/miguelangel-nubla/ipv6disc/cmd/ipv6disc@latest`.

## Usage

```
sudo ipv6disc -live
```

shows the hosts as they are found, in the terminal. Without `-live`, it logs them as JSON, for [`jq`](https://jqlang.github.io/jq/):

```
sudo ipv6disc | jq 'select(.msg == "host identified") | .ip'
```

With the neighbor table of a router too, and IPv4:

```
docker run -it --rm --network host ghcr.io/miguelangel-nubla/ipv6disc \
  -live -ipv4 \
  -plugin "router=mikrotik:interval=60s,address=192.168.88.1,username=ipv6disc,password=secret"
```

IPv6 local discovery needs root or `CAP_NET_RAW`, and in Docker the host's network: see [privileges](docs/discovery.md#privileges). The image has the binary alone: files a plugin reads, as an `identity_file`, are mounted in.

The log has an event per change: `host identified` when an address is found, `host expired` when it goes, with its `ip`, `mac` and `source`; `-log_level debug` adds each refresh. `-live` shows the state instead of the log.

In `-live`, to select and copy, run it in `screen`, and press `Ctrl+a` then `Esc` for copy mode; `Esc` again goes on updating.

## Documentation

| | |
|---|---|
| [Discovery](docs/discovery.md) | How hosts are found: each family's ways, interfaces, lifetimes, solicitation |
| [Plugins](docs/plugins.md) | Reading routers' neighbor tables |
| [The library](docs/library.md) | Using it from Go |
| [Flags reference](docs/reference/cli.md) | Every flag, generated from the code |
| [Plugins reference](docs/reference/plugins.md) | Every plugin's params, generated from the code |

Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).
