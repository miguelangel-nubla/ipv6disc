//go:build linux

package ipv6disc

import (
	"bufio"
	"net/netip"
	"strings"
	"testing"
)

func TestParseIfInet6(t *testing.T) {
	proc := `00000000000000000000000000000001 01 80 10 80       lo
20010db8000000000000000000000001 02 40 00 00     eth0
20010db800000000a1b2c3d4e5f60708 02 40 00 01     eth0
20010db800000000a1b2c3d4e5f60709 02 40 00 21     eth0
fe80000000000000021122fffe334455 02 40 20 80     eth0
garbage
`
	got := parseIfInet6(bufio.NewScanner(strings.NewReader(proc)))
	for addr, want := range map[string]bool{
		"2001:db8::1":                  false,
		"2001:db8::a1b2:c3d4:e5f6:708": true, // temporary
		"2001:db8::a1b2:c3d4:e5f6:709": true, // temporary and deprecated
		"fe80::211:22ff:fe33:4455":     false,
		"::1":                          false,
	} {
		if got[netip.MustParseAddr(addr)] != want {
			t.Errorf("%s: temporary %v, want %v", addr, got[netip.MustParseAddr(addr)], want)
		}
	}
}
