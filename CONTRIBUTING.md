# Contributing

Issues and pull requests are welcome. For a security issue, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Developing

Before opening a pull request, run:

```bash
go vet ./...
go test -race ./...
```

CI runs both. It also runs:

- a vet for the other systems the release builds for (`GOOS=darwin`, `freebsd`, `netbsd`, `openbsd`, `solaris`, `windows`), because a build on one system doesn't see the other systems' files;
- a 32-bit build;
- `staticcheck`, and `golangci-lint` with the settings in `.golangci.yaml`, on each of those systems;
- `go mod tidy -diff`;
- `govulncheck`;
- the live test described below.

### The live test

The live test discovers over a real link, between two network namespaces. It needs Linux, root and iproute2.

For the names, it also needs the services that announce or answer them, which it runs in the hosts' namespaces: `avahi-daemon` (without D-Bus), Samba's `nmbd`, `systemd-resolved`, `dnsmasq`, `udhcpc`, `dhclient`, `wsdd2` and `lldpd`. A test whose service is missing is skipped.

```bash
go test -c -tags integration -o integration.test . && go build -o ipv6disc ./cmd/ipv6disc && sudo ./integration.test -test.run '^TestLive'
```

The command is built next to the test, because the test runs two copies of it at once, each with its own configuration file.

On another system, `tools/live-test.sh` runs the live test with Docker, in a privileged container that is thrown away afterwards. It also runs the other tests under the race detector.

### What the live tests cover

The live tests check what only a real socket can show:

- **The NDP hop limit.** A neighbor advertisement with a hop limit below 255 is ignored, and the same advertisement from the link is not.
- **Several instances at once.** Two workers in one process, two processes on one machine, two commands on one machine, and two machines on one link. On the two machines, each instance's probes are counted on the wire, alone and with the other instance running.
- **A host that leaves the link.** Its IPv4 address goes a lifetime after the kernel last confirmed it. The hosts that stay remain through every reading of the table.
- **Names from a real mDNS responder.**
  - A host is asked for its name over each family.
  - A host is found and named by what it announces. When it is renamed, it loses its old name a lifetime later.
  - With mDNS off, nothing is sent to the mDNS port.
  - A worker runs next to its own machine's responder, with both on the mDNS port.
  - A host that sends its name, unasked, to the port the worker asks from names nobody.
- **Names from each of the other protocols, each one alone.**
  - Asked: of nmbd over NetBIOS, of systemd-resolved over LLMNR, and of dnsmasq as a DNS server. systemd-resolved answers a question sent to the group, and not one sent to it alone.
  - Fetched: from wsdd2, and from a UPnP device that the test provides itself. That device is the only one that is not a real service.
  - Heard: from udhcpc and dhclient as they ask dnsmasq for an address, also when the worker runs on the same machine as dnsmasq, and from lldpd. A host that writes another host's MAC or address in its own message names nobody.
- **The ARP a host sends.** The host is found within a second.
- **Without `CAP_NET_RAW`.** None of the three protocols that need packet sockets is heard, the log says so once for each, and the hosts are found through the table as before.
- **With the name protocols off.** Nothing of any of them is on the wire, and no socket is opened for them.
- **Each protocol's switch**, with the protocol alone plus only what it can't run without.
  - When the protocol is enabled, what it sends is counted on the wire, and its sockets and groups are there.
  - No socket or group belongs to a protocol that is not enabled, or to a worker with no protocol at all.
  - The sweep only covers the subnets no larger than its `max_prefix`.
  - mDNS only listens when it is told not to ask.
- **Each family's switches**, which override the protocols' switches. With every protocol enabled, a family that is off, or that doesn't probe, has none of its protocols on the wire and none of their sockets open.
- **The command's defaults.** The command without a configuration, and with a file that sets nothing, sends what the command sent before it had a configuration file.
- **mDNS finding hosts.** It finds a host that only announces itself, and asks that host nothing.
- **The command's configuration file.** The command takes its configuration from a file. A flag that existed before the file is refused. With a file that is invalid, nothing is sent.

## The documentation

Three pages are generated from the code:

| Page | Generated from |
|---|---|
| [Flags reference](docs/reference/cli.md) | The flags' usage texts |
| [Configuration reference](docs/reference/configuration.md) | The schema of the configuration file, [`pkg/config/schema.json`](pkg/config/schema.json) |
| [Plugins reference](docs/reference/plugins.md) | The fields each plugin registers |

After changing any of those sources, regenerate the pages:

```bash
go test ./cmd/ipv6disc -update
```

It also writes the manual page, [`docs/ipv6disc.1`](docs/ipv6disc.1), from the flags.

The same command redraws the README's picture of the live view, `docs/images/page-light.svg` and `page-dark.svg`, from `docs/images/page.txt`. Change the text, never the pictures. A test holds the picture's colors to those the program gives each kind of line.

A test fails when the pages are out of date, or when a field has no description. Other tests keep the rest consistent:

- **The schema matches the code.** Every key of the schema is a field of the types in [`pkg/config`](pkg/config), and every field is a key, with the same type and the same default. The schema's plugins are the registered plugins, with their fields.
- **The examples load.** Every configuration shown in the pages, and the release's [example](cmd/ipv6disc/example.config.yaml), is one the command accepts.
- **The release has the pages.** A release's archives contain that example and every page, according to the files listed in [`.goreleaser.yaml`](.goreleaser.yaml).

Some sentences of [`docs/discovery.md`](docs/discovery.md) are also held to the code by tests, word for word, because they state limits the code defines. When you reword one, update the test that quotes it: `naming_test.go`, `protocols_test.go` or `docs_links_test.go`.

### Adding a protocol

A new protocol needs all of these:

1. A field in `ipv6disc.Protocols`, with its `Enabled` and its options.
2. Its name in `ProtocolNames`.
3. A key under `protocols` in `pkg/config`, and in the schema.
4. A row in the table of [protocols](docs/discovery.md#protocols). A test keeps that table matching the code.
5. A row in the live test of the switches, with what the protocol sends and opens.

## Releases

A tag makes a release: goreleaser builds it and publishes it on GitHub, with its images. Work goes to `dev`, where CI runs on every push. It reaches `main` when it is released.

- **A prerelease** is a tag on `dev` with a prerelease part: `v0.23.0-rc.1`, `-rc.2`, `-beta.1`.
  - GitHub marks it as a prerelease, not as the latest release.
  - Its images only get its own tags. `latest`, `vX` and `vX.Y` stay on the last release, so nobody gets a prerelease without asking for it.
  - ipv6ddns can depend on a prerelease in its `go.mod`, to be tested with it before the release.
- **A release** is `dev` merged into `main`, and tagged there: `v0.23.0`.
  - It makes the Homebrew formula, in [`miguelangel-nubla/homebrew-tap`](https://github.com/miguelangel-nubla/homebrew-tap), of its version, when the release workflow has the secret `HOMEBREW_TAP_TOKEN`. Without the secret, run `./update.sh ipv6disc <tag>` by hand in a clone of the tap, and push it.

A tag whose commit message contains `[skip ci]` starts no release. GitHub skips every workflow of that push, including the tag's. Either tag a commit without it, or run the release on the tag by hand: *Actions*, *goreleaser*, *Run workflow*, with the tag under *Use workflow from*.
