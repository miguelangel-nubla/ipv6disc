# ipv6disc: host discovery

[![ci](https://github.com/miguelangel-nubla/ipv6disc/actions/workflows/ci.yaml/badge.svg)](https://github.com/miguelangel-nubla/ipv6disc/actions/workflows/ci.yaml)
[![release](https://img.shields.io/github/v/release/miguelangel-nubla/ipv6disc)](https://github.com/miguelangel-nubla/ipv6disc/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/miguelangel-nubla/ipv6disc.svg)](https://pkg.go.dev/github.com/miguelangel-nubla/ipv6disc)

`ipv6disc` finds the hosts of the local network and their addresses, each with its MAC: IPv6, and IPv4 too. It listens to the network, probes it, and reads the neighbor tables of routers. The name is from when it was IPv6 only.

It learns the names of the hosts too, by each protocol that is turned on: those they announce over mDNS and give as they ask for an address by DHCP, those they answer when asked, by mDNS, NetBIOS, LLMNR, WS-Discovery or SSDP, those a DNS server has for their addresses, and those of the routers' DHCP leases.

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

Everything else is in a configuration file, YAML: the families, each protocol with its switch and its options, the names, the interfaces, the lifetimes, the plugins. Without one, the defaults discover IPv6, by every protocol, and the names the hosts tell. With IPv4 too, and the neighbor table of a router, `discovery.yaml`:

```yaml
ipv4:
  enabled: true
plugins:
  router:
    type: mikrotik
    interval: 60s
    address: 192.168.88.1
    username: ipv6disc
    password: "secret"
```

```
docker run -it --rm --network host -v "$PWD/discovery.yaml:/discovery.yaml:ro" \
  ghcr.io/miguelangel-nubla/ipv6disc -live -config_file /discovery.yaml
```

The [example](cmd/ipv6disc/example.config.yaml) shows every key, and the [configuration reference](docs/reference/configuration.md) lists them. The command has three flags: `-config_file`, `-live` and `-version`.

IPv6 local discovery needs root or `CAP_NET_RAW`, and in Docker the host's network: see [privileges](docs/discovery.md#privileges). The image has the binary alone: the configuration file, and the files a plugin reads, as an `identity_file`, are mounted in, and it has no CA certificates, so a mikrotik plugin with `use_tls: true` needs its [`tls_fingerprint`](docs/plugins.md#a-mikrotik-user) there.

The log has an event per change: `host identified` when an address is found, `host expired` when it goes, `host removed` when it is an address of this machine's that its interface no longer has, with its `ip`, `mac` and `source`; `log_level: debug` adds each refresh. `host named` and `host name expired` tell the [names](docs/discovery.md#names) of a host as they come and go, with the `name`, `mac` and `source`. `-live` shows the state instead of the log, errors too, as those of a plugin that can't reach its router: run without it to see why hosts are missing. It needs a terminal, in Docker `-it`, and ends with `q`, or when the process is told to stop.

In `-live`, to select and copy, run it in `screen`, and press `Ctrl+a` then `Esc` for copy mode; `Esc` again goes on updating.

## Documentation

| | |
|---|---|
| [Discovery](docs/discovery.md) | How hosts are found: the families, each protocol, interfaces, lifetimes, solicitation, names |
| [Plugins](docs/plugins.md) | Reading routers' neighbor tables, and the names of their DHCP leases |
| [The library](docs/library.md) | Using it from Go |
| [Configuration reference](docs/reference/configuration.md) | Every key of the configuration file, generated from its schema |
| [Flags reference](docs/reference/cli.md) | The three flags, generated from the code |
| [Plugins reference](docs/reference/plugins.md) | Every plugin's fields, generated from the code |

Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).
