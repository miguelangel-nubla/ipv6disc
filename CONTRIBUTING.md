# Contributing

Issues and pull requests are welcome. Security issues: see [SECURITY.md](SECURITY.md), not a public issue.

## Developing

```bash
go vet ./...
go test -race ./...
```

CI runs those, a 32-bit build, `staticcheck`, `govulncheck`, and the live test below.

The live test discovers over a real link, between two network namespaces, which needs Linux, root and iproute2:

```bash
go test -c -tags integration -o integration.test . && sudo ./integration.test -test.run '^TestLive'
```

## The documentation

The [flags reference](docs/reference/cli.md) and the [plugins reference](docs/reference/plugins.md) are generated from the code: the flags' usages, and the params each plugin registers. After changing them:

```bash
go test ./cmd/ipv6disc -update
```

A test fails when the pages are behind, or a param has no description.
