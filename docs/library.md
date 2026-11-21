# The library

```
go get github.com/miguelangel-nubla/ipv6disc
```

The API's documentation is on [pkg.go.dev](https://pkg.go.dev/github.com/miguelangel-nubla/ipv6disc). The parts, and how they go together:

```go
config := ipv6disc.DefaultConfig() // IPv6 by the protocols that find hosts, no IPv4
config.IPv4.Enabled = true         // by its own: the neighbor table, the sweep
config.Protocols.ARPSweep.Enabled = false
config.ExcludeInterfaces = []string{"docker*", "veth*"}

worker := ipv6disc.NewWorker(logger, config)

plugin, err := plugins.Create("mikrotik", "router", "interval=60s,address=192.168.88.1,username=ipv6disc,password=secret", config.Lifetime)
if err != nil {
	return err
}
worker.RegisterPlugin(plugin)

// Before Start, not to miss the first changes.
changes, cancel := worker.State.Subscribe()
defer cancel()

if err := worker.Start(ctx); err != nil { // until ctx is done
	return err
}
defer worker.State.Close() // after Wait: the addresses stop expiring
defer worker.Wait()

for {
	select {
	case <-ctx.Done():
		return nil
	case <-changes:
		for mac, addrs := range worker.State.GetAll() {
			fmt.Println(mac, addrs.FilterValid().Strings())
		}
	}
}
```

A worker starts once, and its plugins are registered before `Start`. A program can run several, each with its own `Config` and its own `State`, as several commands can run on one machine: see [several instances](discovery.md#several-instances). Import the plugins with `_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/all"`, or one by one.

## Config

`Config` is what the [configuration file](reference/configuration.md) of the command sets: a `Family` for each of `IPv6` and `IPv4`, with `Enabled`, `Listen`, `Active` and `Lifetime`, the `Lifetime` and `Rediscover` of all, the `Interfaces` and `ExcludeInterfaces`, `Hostnames`, with `Enabled`, off by default, and its `Lifetime`, and `Protocols`. The [discovery](discovery.md) page says what each does. A zero `Rediscover` is a third of the shortest lifetime of the families that probe. A family's zero `Lifetime` leaves each registration its own: `Config.Lifetime` for the local discovery, and for a plugin the lifetime it was made with.

`Protocols` has a field for each [protocol](discovery.md#protocols) of the local discovery, each a struct with `Enabled` and the options of that one: `NDP`, `Ping`, `SSDP` and `WSD`, both with `Names`, `MDNS`, with `Ask`, `ARP`, `ARPSweep`, with `MaxPrefix`, `ARPListen`, `DHCP`, `LLDP`, `NetBIOS`, `LLMNR`, and `DNS`, with its `Servers`. `ProtocolNames` are their names, as the file and the log have them. A protocol runs when it is enabled and its family listens, or for the sweep probes. Start from `DefaultConfig`, or give a `Config` made by hand `DefaultProtocols()`: the zero value of `Protocols` enables none, and such a worker, warned of at start, finds this machine's own addresses only.

`Config.Validate` tells what `Worker.Start` would refuse, without starting anything: every error at once, as a protocol enabled that the system can't run, or one that only learns names without `Hostnames`.

## The configuration file

[`pkg/config`](../pkg/config) is the configuration as a file has it, for a program that reads the discovery from its own settings, as the command does, and as [ipv6ddns](https://github.com/miguelangel-nubla/ipv6ddns) does among others of its own:

- `config.Load` and `config.Parse` read the file of the command, a `File`: YAML, or JSON, read strictly over `config.Default`, and validated.
- `Discovery` is the keys of the discovery alone, a `File` without `log_level`. It reads itself from JSON, as `encoding/json` hands it, as strictly: a key it doesn't have and a value of the wrong type are errors that tell where they are and what there is. Read it into `config.DefaultDiscovery()`, or into that with the program's own defaults put in: what a document leaves out stays as it was.
- `Discovery.Config` is the `ipv6disc.Config` of it, `Discovery.NewPlugins` its plugins, made, and `Discovery.Validate` what of both can't run.
- `config.Schema` is the JSON schema of the file, [`schema.json`](../pkg/config/schema.json), and `config.DiscoverySchema` that of a `Discovery`, for the schema of the program that has one.

```yaml
ipv4:
  enabled: true
protocols:
  arp-sweep:
    enabled: false
plugins:
  router:
    type: mikrotik
    interval: 60s
    address: 192.168.88.1
    username: ipv6disc
    password: "secret"
```

## State

The worker's `State` holds the addresses, by MAC:

- `GetAll`, `FilterMACs`: the addresses, as `AddrCollection`s, which filter by family, subnet and validity. An `Addr` has its MAC, its sources, the interfaces and plugins that saw it, its `Interfaces`, the local ones of them, and its expiration. `Self` tells an address of this machine's own, which `State.RegisterSelf` registers, and `Temporary`, on Linux, one of them the kernel made as a privacy address, which changes every day or so.
- `Subscribe`: a channel that receives a value after each change, an address added, expired, or seen by a new source. Changes coming faster than they are received are told once. Its `cancel` doesn't close the channel: wait on the context too.
- `Register`: adds an address, as the plugins do. It returns nil, and true, for an address the state leaves out: one of a family it doesn't take, one that is invalid, unspecified or multicast, or one with no MAC. `Seen` takes an `Addr` as it is, without those checks nor the families' lifetimes: one it adds is valid for its lifetime from then on.
- `Close`: stops the expiration of every address, each of which has a goroutine and its timers until it expires, and of the names, which have one timer among them all. For after `Worker.Wait`, which leaves the state as it is, still expiring: a program that makes workers again and again would otherwise keep those of each for a lifetime. Nothing is removed, and `Valid` still tells by time.

## Names

With `Config.Hostnames.Enabled`, the state holds the [names](discovery.md#names) of the hosts too, by MAC, which the protocols enabled for them tell, and the plugins:

- `NamesOf`, `AllNames`: the names of a MAC, or of each, whose lifetime is running, as `HostName`s: the `Name`, its `Sources`, each a protocol of the local discovery, as `mdns`, `dns`, `netbios`, `llmnr`, `wsd`, `ssdp`, `dhcp` or `lldp`, or a plugin's name, when it was last `Seen` and its `Expiration`. They are copies. A name is the host's, not an address's: use it with whichever addresses `GetAll` has at that MAC.
- `Subscribe` tells the changes of the names as those of the addresses: a name added, expired, gone with its host, or said by a new source.
- `RegisterName`: adds a name of a MAC, as a source said it, for a lifetime, or refreshes it, as `Register` does an address. It is the one way in, of the local discovery and of the plugins: a plugin calls it when `State.Names` tells that the state takes names. The name is cleaned by `CleanName`, to one DNS label, and left out when nothing is left of it.
- `SetNames`: what the worker does with `Config.Hostnames`, for a state made by hand: without it, a state takes no names.

A name is whatever a device claims: a hint of which host a MAC is, not a proof. The sources are not worth the same: `mdns`, `dhcp`, `netbios`, `llmnr` and `wsd` are the host's own name for itself, `dns` and a plugin's what a server of the network calls it, `lldp` what a switch or a host calls itself, and `ssdp` a label for people, that two devices of a model may share. A program that needs one name of a host picks by them.

## Solicitation

`Worker.Solicit` and `Worker.SolicitIPv4` ask given hosts for addresses that aren't otherwise seen: see [solicitation](discovery.md#solicitation). `Worker.Prefixes` returns the IPv6 /64s it listens on, to work out an EUI-64 address.
