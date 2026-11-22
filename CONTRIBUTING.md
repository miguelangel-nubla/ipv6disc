# Contributing

Issues and pull requests are welcome. Security issues: see [SECURITY.md](SECURITY.md), not a public issue.

## Developing

```bash
go vet ./...
go test -race ./...
```

CI runs those, a vet for the other systems (`GOOS=darwin`, `freebsd`, `netbsd`, `openbsd`, `solaris`, `windows`: those the release builds for), whose files a build on one system doesn't see, a 32-bit build, `staticcheck`, `golangci-lint` as `.golangci.yaml` sets it, on each of those systems, `go mod tidy -diff`, `govulncheck`, and the live test below.

The live test discovers over a real link, between two network namespaces, which needs Linux, root and iproute2, and for the names the services that tell them, which it runs in the namespaces of the hosts: `avahi-daemon`, without D-Bus, Samba's `nmbd`, `systemd-resolved`, `dnsmasq`, `udhcpc`, `dhclient`, `wsdd2` and `lldpd`. A test whose service is missing is skipped:

```bash
go test -c -tags integration -o integration.test . && go build -o ipv6disc ./cmd/ipv6disc && sudo ./integration.test -test.run '^TestLive'
```

The command is built beside the test, which runs two of it at once, each with a configuration file of its own.

From another system, with Docker, `tools/live-test.sh` runs it, and the other tests under the race detector, in a privileged container that is thrown away. Among the live tests, what only a real socket tells: that a neighbor advertisement with a hop limit below 255 is left out, and that the same one from the link isn't; and several instances at once: two workers of one process, two processes and two commands on one machine, and two machines of one link, where the probes of each are counted on the wire, alone and with the other; and a host that leaves the link, whose IPv4 address goes a lifetime after the kernel last confirmed it, while those that stay are there through every reading of the table; and the names, told by a real responder: a host asked its name over each family, one found and named by what it announces, renamed, and losing its old name a lifetime later, nothing sent to the port of mDNS by default, a worker beside the responder of its own machine, both on that port, and a host that sends its name unasked to the port the worker asks from, which names nobody; and the names by each of the other protocols, each alone: asked of nmbd over NetBIOS, of systemd-resolved over LLMNR, which answers a question to the group and none sent to it alone, and of dnsmasq as a DNS server; fetched from wsdd2, and from a UPnP device of the test's own, the one that is not a real service; heard of udhcpc and dhclient as they ask dnsmasq for an address, beside it too, and not of a host that writes another's MAC or address in a message of its own, and of lldpd; a host found by the ARP it sends within a second; without `CAP_NET_RAW`, none of the three heard, each said once, and the hosts found by the table as before; and nothing of any of it on the wire, nor a socket for it, by default; and the switches of the protocols, each alone with only what it can't run without: what it sends counted on the wire, its sockets and its groups there when it is enabled, and none of them of any protocol that is not, nor of a worker with none at all, the sweep of the subnets no larger than its `max_prefix`, and mDNS that only listens when told not to ask; the switches of a family over them, with every protocol enabled, where a family that is off, or doesn't probe, has none of its own on the wire nor open; the command without a configuration, and with a file that says nothing, which send what the command sent before it had one; mDNS without the names kept, which finds a host that only announces itself and asks it nothing; and the command with its configuration in a file, a flag from before the file refused, and a file that can't be, with nothing sent.

## The documentation

The [flags reference](docs/reference/cli.md), the [configuration reference](docs/reference/configuration.md) and the [plugins reference](docs/reference/plugins.md) are generated from the code: the flags' usages, the schema of the configuration file, [`pkg/config/schema.json`](pkg/config/schema.json), and the fields each plugin registers. After changing them:

```bash
go test ./cmd/ipv6disc -update
```

A test fails when the pages are behind, or a field has no description. Others hold the schema to the code: every key of it is a field of the types of [`pkg/config`](pkg/config), and every field a key, of the same type and with the same default; its plugins are those registered, with their fields; and every configuration the pages show, and the [example](cmd/ipv6disc/example.config.yaml) of the release, is one the command takes; and the archives of a release have that example and every page, by the files of [`.goreleaser.yaml`](.goreleaser.yaml).

A new protocol is a field of `ipv6disc.Protocols`, with its `Enabled` and its options, its name in `ProtocolNames`, a key of `protocols` in `pkg/config` and in the schema, a row of the table of [protocols](docs/discovery.md#protocols), which a test holds to the code, and a row of the live test of the switches, with what it sends and opens.

## Releases

A tag makes a release: goreleaser builds it and publishes it on GitHub, with its images. Work goes to `dev`, where CI runs on every push, and reaches `main` when it is released.

- **A prerelease** is a tag of `dev` with a prerelease part: `v0.23.0-rc.1`, `-rc.2`, `-beta.1`. GitHub marks it a prerelease, not the latest release, and its images have its own tags only: `latest`, `vX` and `vX.Y` stay on the last release, so nobody gets it who didn't ask for it. ipv6ddns can take one in its `go.mod` to be tested with it before the release.
- **A release** is `dev` merged into `main`, and tagged there: `v0.23.0`.
