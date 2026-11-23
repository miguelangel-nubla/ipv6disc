# The library

```
go get github.com/miguelangel-nubla/ipv6disc
```

The API documentation is on [pkg.go.dev](https://pkg.go.dev/github.com/miguelangel-nubla/ipv6disc). This example shows the parts and how they fit together:

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

- A worker starts once. Register its plugins before `Start`.
- A program can run several workers, each with its own `Config` and its own `State`, just as several commands can run on one machine: see [several instances](discovery.md#several-instances).
- Import the plugins with `_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/all"`, or one by one.

## Config

`Config` holds what the command's [configuration file](reference/configuration.md) sets. The [discovery](discovery.md) page says what each setting does. Its fields:

- `IPv6` and `IPv4`: a `Family` each, with `Enabled`, `Listen`, `Active` and `Lifetime`;
- `Lifetime` and `Rediscover`, which apply to everything;
- `Interfaces` and `ExcludeInterfaces`;
- `Hostnames`, with its `Lifetime`;
- `Protocols`.

Two zero values have a meaning:

- A zero `Rediscover` means a third of the shortest lifetime among the families that probe.
- A family's zero `Lifetime` leaves each registration its own lifetime: `Config.Lifetime` for the local discovery, and for a plugin the lifetime the plugin was created with.

### Protocols

`Protocols` has a field for each [protocol](discovery.md#protocols) of the local discovery. Each field is a struct with `Enabled` and that protocol's options:

- `NDP`, `Ping`, `ARP`, `ARPListen`, `DHCP`, `LLDP`, `NetBIOS` and `LLMNR`, with `Enabled` only;
- `SSDP` and `WSD`, each with `Names`;
- `MDNS`, with `Ask`;
- `ARPSweep`, with `MaxPrefix`;
- `DNS`, with `Servers`.

`ProtocolNames` returns their names, as the file and the log write them. A protocol runs when it is enabled and its family listens or, for the sweep, probes.

Start from `DefaultConfig`. If you build a `Config` by hand, give it `DefaultProtocols()`. The zero value of `Protocols` enables no protocol. A worker with none gets a warning at start, and only finds this machine's own addresses.

### Validation

`Config.Validate` reports what `Worker.Start` would refuse, without starting anything. It returns every error at once. Examples are an enabled protocol that the system can't run, and a protocol that needs another protocol that is off.

## The configuration file

[`pkg/config`](../pkg/config) is the configuration in the form a file has it. Use it in a program that reads the discovery settings from its own configuration. The command does that, and so does [ipv6ddns](https://github.com/miguelangel-nubla/ipv6ddns), which has the discovery among other settings of its own.

- **`config.Load` and `config.Parse`** read the command's file, a `File`. The file is YAML or JSON. It is read strictly on top of `config.Default`, and validated.
- **`Discovery`** is the discovery's keys alone: a `File` without `log_level`.
  - It reads itself from JSON, through `encoding/json`, just as strictly. A key it doesn't have, or a value of the wrong type, is an error that says where the problem is and what is allowed there.
  - Read it into `config.DefaultDiscovery()`, or into that value with your program's own defaults set in it. Whatever a document leaves out stays as it was.
- **`Discovery.Config`** returns the matching `ipv6disc.Config`.
- **`Discovery.NewPlugins`** creates its plugins.
- **`Discovery.Validate`** reports what can't run in either of them.
- **`config.Schema`** is the JSON schema of the file, [`schema.json`](../pkg/config/schema.json). `config.DiscoverySchema` is the schema of a `Discovery`, to include in the schema of a program that has one.

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

The worker's `State` holds the addresses, by MAC.

**`GetAll`, `FilterMACs`** return the addresses as `AddrCollection`s, which filter by family, subnet and validity. An `Addr` has:

- its MAC;
- its sources, which are the interfaces and plugins that saw it;
- its `Interfaces`, the local interfaces among those sources;
- its expiration;
- `Self`, which is true for one of this machine's own addresses. `State.RegisterSelf` registers those;
- `Temporary`, on Linux and macOS, which is true for one of this machine's addresses that the kernel created as a privacy address. Such an address changes every day or so.

**`Subscribe`** returns a channel that receives a value after each change: an address added, expired, or seen by a new source. Changes that arrive faster than they are received are reported once. Its `cancel` doesn't close the channel, so wait on the context too.

**`Register`** adds an address, as the plugins do. It returns nil and true for an address the state leaves out:

- one of a family the state doesn't take;
- one that is invalid, unspecified or multicast;
- one with no MAC.

**`Seen`** takes an `Addr` as it is, without those checks and without the families' lifetimes. An address it adds is valid for the address's own lifetime from then on.

**`Close`** stops the expiration of every address and of the names. Each address has a goroutine and its timers until it expires, and the names share one timer.

- Call it after `Worker.Wait`. `Wait` leaves the state as it is, still expiring.
- Without `Close`, a program that creates workers again and again would keep each worker's goroutines and timers for a lifetime.
- `Close` removes nothing, and `Valid` still answers by time.

## Records

An address has a record for each way it was seen. Each record has its own `FirstSeen`, `LastSeen` and `Lifetime`, and the address stays while any record does. `Addr.Records` returns the records that are still current, in the order they arrived.

There are two kinds of record:

- **A protocol's record** is made by the local discovery. It has its `Protocol`, such as `ndp` or `mdns`; its `Way`, which is `Announced`, `Answered` or `Heard`; and `On`, the interface it was seen on.
- **A report** has `By`, who made it, which is a plugin's name or `ReportedByKernel`; its `Type`, the plugin's type; and `From`, the table it comes from: `FromNeighbors`, `FromLeases` or `FromInterfaces`. `Reported` tells a report from a protocol's record.

Three methods of the state make reports:

- **`Report`** registers an address with a report, as a plugin does.
- **`Register`** makes a report that only has `By`.
- **`Attach`** adds a report to an address the state already has. It registers no address.
  - The report says how the address was seen for as long as the address stays, but it keeps the address no longer than its other records do.
  - The plugins attach their leases this way, because a DHCP server keeps the lease of a host that left until the lease ends.
  - `Record.Attached` tells such a record.

## Names

A worker's state also holds the hosts' [names](discovery.md#names), by MAC. They come from the protocols enabled for names, and from the plugins. A state you create yourself only takes names once `SetNames` enables them.

**`NamesOf`, `AllNames`** return the names of one MAC, or of every MAC, whose lifetime is still running. Each is a `HostName`, with:

- the `Name`;
- its `Sources`. Each source is a protocol of the local discovery (`mdns`, `dns`, `netbios`, `llmnr`, `wsd`, `ssdp`, `dhcp` or `lldp`) or a plugin's name;
- when it was last `Seen`;
- its `Expiration`.

The values are copies. A name belongs to the host, not to an address, so use it with whichever addresses `GetAll` has at that MAC.

**`Subscribe`** reports changes of names like changes of addresses: a name added, expired, gone with its host, or said by a new source.

**`RegisterName`** adds a name for a MAC, as said by a source, for a lifetime. If the name is already there, it refreshes it, as `Register` does for an address.

- It is the only way in, for the local discovery and for the plugins. A plugin calls it when `State.Names` says that the state takes names.
- The name is cleaned by `CleanName` into one DNS label. If nothing is left of it, the name is left out.

**`SetNames`** does what the worker does with `Config.Hostnames`, for a state you create yourself. Without it, a state takes no names.

### How much a name is worth

A name is whatever a device claims. It is a hint about which host a MAC is, not a proof. The sources are not worth the same:

| Source | What the name is |
|---|---|
| `mdns`, `dhcp`, `netbios`, `llmnr`, `wsd` | The host's own name for itself |
| `dns`, a plugin | What a server on the network calls the host |
| `lldp` | What a switch or a host calls itself |
| `ssdp` | A label for people, which two devices of one model may share |

A program that needs a single name for a host should choose by source.

## Solicitation

`Worker.Solicit` and `Worker.SolicitIPv4` ask given hosts for addresses that aren't seen otherwise: see [solicitation](discovery.md#solicitation). `Worker.Prefixes` returns the IPv6 /64s the worker listens on, which you need to work out an EUI-64 address.
