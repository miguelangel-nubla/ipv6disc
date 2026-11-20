# The library

```
go get github.com/miguelangel-nubla/ipv6disc
```

The API's documentation is on [pkg.go.dev](https://pkg.go.dev/github.com/miguelangel-nubla/ipv6disc). The parts, and how they go together:

```go
config := ipv6disc.DefaultConfig() // IPv6 by every way, no IPv4
config.IPv4 = ipv6disc.Family{Enabled: true, Listen: true}
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

A worker starts once, and its plugins are registered before `Start`. Import the plugins with `_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/all"`, or one by one.

## Config

`Config` is what the [command's flags](reference/cli.md) set: a `Family` for each of `IPv6` and `IPv4`, with `Enabled`, `Listen`, `Active` and `Lifetime`, the `Lifetime` and `Rediscover` of all, and the `Interfaces` and `ExcludeInterfaces`. The [discovery](discovery.md) page says what each does. A zero `Rediscover` is a third of the shortest lifetime of the families that probe. A family's zero `Lifetime` leaves each registration its own: `Config.Lifetime` for the local discovery, and for a plugin the lifetime it was made with.

## State

The worker's `State` holds the addresses, by MAC:

- `GetAll`, `FilterMACs`: the addresses, as `AddrCollection`s, which filter by family, subnet and validity. An `Addr` has its MAC, its sources, the interfaces and plugins that saw it, its `Interfaces`, the local ones of them, and its expiration. `Self` tells an address of this machine's own, which `State.RegisterSelf` registers, and `Temporary`, on Linux, one of them the kernel made as a privacy address, which changes every day or so.
- `Subscribe`: a channel that receives a value after each change, an address added, expired, or seen by a new source. Changes coming faster than they are received are told once. Its `cancel` doesn't close the channel: wait on the context too.
- `Register`: adds an address, as the plugins do. It returns nil, and true, for an address the state leaves out: one of a family it doesn't take, one that is invalid, unspecified or multicast, or one with no MAC. `Seen` takes an `Addr` as it is, without those checks nor the families' lifetimes: one it adds is valid for its lifetime from then on.
- `Close`: stops the expiration of every address, each of which has a goroutine and its timers until it expires. For after `Worker.Wait`, which leaves the state as it is, still expiring: a program that makes workers again and again would otherwise keep those of each for a lifetime. Nothing is removed, and `Valid` still tells by time.

## Solicitation

`Worker.Solicit` and `Worker.SolicitIPv4` ask given hosts for addresses that aren't otherwise seen: see [solicitation](discovery.md#solicitation). `Worker.Prefixes` returns the IPv6 /64s it listens on, to work out an EUI-64 address.
