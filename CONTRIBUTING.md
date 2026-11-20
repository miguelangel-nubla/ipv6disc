# Contributing

Issues and pull requests are welcome. Security issues: see [SECURITY.md](SECURITY.md), not a public issue.

## Developing

```bash
go vet ./...
go test -race ./...
```

CI runs those, a vet for the other systems (`GOOS=darwin`, `freebsd`, `netbsd`, `openbsd`, `solaris`, `windows`: those the release builds for), whose files a build on one system doesn't see, a 32-bit build, `staticcheck`, `govulncheck`, and the live test below.

The live test discovers over a real link, between two network namespaces, which needs Linux, root and iproute2:

```bash
go test -c -tags integration -o integration.test . && go build -o ipv6disc ./cmd/ipv6disc && sudo ./integration.test -test.run '^TestLive'
```

The command is built beside the test, which runs two of it at once.

From another system, with Docker, `tools/live-test.sh` runs it, and the other tests under the race detector, in a privileged container that is thrown away. Among the live tests, what only a real socket tells: that a neighbor advertisement with a hop limit below 255 is left out, and that the same one from the link isn't; and several instances at once: two workers of one process, two processes and two commands on one machine, and two machines of one link, where the probes of each are counted on the wire, alone and with the other.

## The documentation

The [flags reference](docs/reference/cli.md) and the [plugins reference](docs/reference/plugins.md) are generated from the code: the flags' usages, and the params each plugin registers. After changing them:

```bash
go test ./cmd/ipv6disc -update
```

A test fails when the pages are behind, or a param has no description.
