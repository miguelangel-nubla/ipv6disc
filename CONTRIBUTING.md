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
go test -c -tags integration -o integration.test . && sudo ./integration.test -test.run '^TestLive'
```

From another system, with Docker, `tools/live-test.sh` runs it, and the other tests under the race detector, in a privileged container that is thrown away. Among the live tests, what only a real socket tells: that a neighbor advertisement with a hop limit below 255 is left out, and that the same one from the link isn't.

## The documentation

The [flags reference](docs/reference/cli.md) and the [plugins reference](docs/reference/plugins.md) are generated from the code: the flags' usages, and the params each plugin registers. After changing them:

```bash
go test ./cmd/ipv6disc -update
```

A test fails when the pages are behind, or a param has no description.
