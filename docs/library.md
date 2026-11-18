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

if err := worker.Start(ctx); err != nil { // until ctx is done
	return err
}
defer worker.Wait()

changes, cancel := worker.State.Subscribe()
defer cancel()
for range changes {
	for mac, addrs := range worker.State.GetAll() {
		fmt.Println(mac, addrs.FilterValid().Strings())
	}
}
```

Import the plugins with `_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/all"`, or one by one.

## Config

`Config` is what the [command's flags](reference/cli.md) set: a `Family` for each of `IPv6` and `IPv4`, with `Enabled`, `Listen`, `Active` and `Lifetime`, the `Lifetime` and `Rediscover` of all, and the `Interfaces` and `ExcludeInterfaces`. The [discovery](discovery.md) page says what each does. A zero `Rediscover`, or a family's zero `Lifetime`, takes the default.

## State

The worker's `State` holds the addresses, by MAC:

- `GetAll`, `FilterMACs`: the addresses, as `AddrCollection`s, which filter by family, subnet and validity. An `Addr` has its MAC, its sources, the interfaces and plugins that saw it, and its expiration.
- `Subscribe`: a channel that receives a value after each change, an address added, expired, or seen by a new source. Changes coming faster than they are received are told once.
- `Register`: adds an address, as the plugins do.

## Solicitation

`Worker.Solicit` and `Worker.SolicitIPv4` ask given hosts for addresses that aren't otherwise seen: see [solicitation](discovery.md#solicitation). `Worker.Prefixes` returns the IPv6 /64s it listens on, to work out an EUI-64 address.
