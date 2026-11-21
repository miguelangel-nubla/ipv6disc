#!/bin/sh
# The live tests, and the others under the race detector, on Linux as root, from any system with
# Docker: in a container that is thrown away, privileged for its network namespaces. Arguments go
# to the live tests: tools/live-test.sh -test.run '^TestLiveNDPHopLimit$'
set -eu
cd "$(dirname "$0")/.."
exec docker run --rm --privileged \
	-v "$PWD":/src:ro -v ipv6disc-go-cache:/go/pkg/mod -v ipv6disc-go-build:/root/.cache/go-build \
	-w /src -e GOFLAGS=-buildvcs=false "golang:${GO_VERSION:-1.26}" sh -euc '
		apt-get update -qq >/dev/null
		# The services that tell names, which the tests run in the namespaces of their hosts.
		apt-get install -yqq --no-install-recommends iproute2 iputils-ping procps avahi-daemon \
			samba systemd-resolved dnsmasq-base udhcpc isc-dhcp-client wsdd2 lldpd >/dev/null
		go test -race -count=1 ./...
		go test -c -race -tags integration -o /tmp/integration.test .
		go build -race -o /tmp/ipv6disc ./cmd/ipv6disc
		cd /tmp && exec ./integration.test -test.v -test.timeout 30m "${@:--test.run=^TestLive}"
	' sh "$@"
