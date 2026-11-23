#!/bin/sh
# Arch's package, built as a release builds it and installed in Arch, from any system with
# Docker, in a container that is thrown away: the command runs and says its version, its manual
# page is there, and a removal leaves nothing.
#
# The build takes minutes, for every system of a release. PACKAGES_BUILT=1 tests those dist/ has.
set -eu
cd "$(dirname "$0")/.."

if [ -z "${PACKAGES_BUILT:-}" ]; then
	docker run --rm -v "$PWD":/src -w /src -e GOFLAGS=-buildvcs=false \
		-v ipv6disc-go-cache:/go/pkg/mod -v ipv6disc-go-build:/root/.cache/go-build \
		"goreleaser/goreleaser:${GORELEASER_VERSION:-latest}" release --snapshot --clean --skip=docker,archive
fi

set -- dist/ipv6disc_*_linux_amd64.pkg.tar.zst
[ $# -eq 1 ] && [ -f "$1" ] || {
	echo "package-test: not one package of amd64 in dist/: $*" >&2
	exit 1
}
pkg=$(basename "$1")

# Arch is of amd64 alone: emulated, where Docker runs another, and pacman's own sandbox doesn't
# start so. The image leaves the manual pages of every package out, which the test looks for.
echo "package-test: $pkg in archlinux:latest"
docker run --rm --platform linux/amd64 -v "$PWD/dist":/dist:ro -e PKG="$pkg" archlinux:latest sh -euc '
	fail() {
		echo "package-test: $*" >&2
		exit 1
	}
	pacman="pacman --disable-sandbox --noconfirm"
	sed -i "/^NoExtract/d" /etc/pacman.conf
	$pacman -U "/dist/$PKG" >/dev/null 2>&1 || fail "the install"
	ipv6disc --version | grep -q "^ipv6disc [0-9]" || fail "the command does not say its version: $(ipv6disc --version 2>&1)"
	ipv6disc --help 2>&1 | grep -q -- "--config file" || fail "the usage"
	zcat /usr/share/man/man1/ipv6disc.1.gz | grep -q "^\.TH IPV6DISC 1 " || fail "no manual page"
	[ -s /usr/share/doc/ipv6disc/example.config.yaml ] && [ -s /usr/share/licenses/ipv6disc/LICENSE ] || fail "no example, or no license"
	$pacman -R ipv6disc >/dev/null 2>&1 || fail "the removal"
	[ ! -e /usr/bin/ipv6disc ] && [ ! -e /usr/share/man/man1/ipv6disc.1.gz ] || fail "the removal left files"
'
echo "package-test: ok"
