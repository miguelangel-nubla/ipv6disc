package arp

import (
	"net/netip"
	"testing"
)

func TestProbeTargets(t *testing.T) {
	p := netip.MustParsePrefix
	count := func(local, within string) (int, []netip.Addr) {
		var w netip.Prefix
		if within != "" {
			w = p(within)
		}
		got := ProbeTargets(p(local), w)
		return len(got), got
	}
	// Without a prefix, as a sweep.
	if n, _ := count("10.2.3.75/24", ""); n != 253 {
		t.Errorf("a /24: %d", n)
	}
	// A prefix inside a larger subnet: all its addresses, even out of the /24 of local.
	if n, got := count("10.0.5.1/16", "10.0.9.0/24"); n != 256 || got[0] != netip.MustParseAddr("10.0.9.0") {
		t.Errorf("a /24 in a /16: %d, from %v", n, got[:1])
	}
	// A prefix around the subnet: the subnet's, but the network, the broadcast and local.
	if n, _ := count("10.2.3.75/24", "10.0.0.0/8"); n != 253 {
		t.Errorf("a /8 around a /24: %d", n)
	}
	if n, _ := count("10.2.3.75/24", "192.168.1.0/24"); n != 0 {
		t.Errorf("off the subnet: %d", n)
	}
	if n, _ := count("10.0.0.1/8", "10.0.0.0/8"); n != MaxProbeAddrs {
		t.Errorf("a /8: %d, want at most %d", n, MaxProbeAddrs)
	}
	if n, got := count("10.2.3.75/24", "10.2.3.10/32"); n != 1 || got[0] != netip.MustParseAddr("10.2.3.10") {
		t.Errorf("one address: %v", got)
	}
}
