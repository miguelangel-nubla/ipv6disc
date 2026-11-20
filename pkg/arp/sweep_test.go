package arp

import (
	"net/netip"
	"slices"
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
	if n, _ := count("10.0.0.1/8", "10.0.0.0/8"); n > MaxProbeAddrs {
		t.Errorf("a /8: %d, want at most %d", n, MaxProbeAddrs)
	}
	// Capped, the addresses nearest local: its own /24 among them.
	_, got := count("10.0.200.1/16", "10.0.0.0/8")
	if len(got) == 0 || got[0].Compare(netip.MustParseAddr("10.0.192.0")) < 0 || !slices.Contains(got, netip.MustParseAddr("10.0.200.77")) {
		t.Errorf("capped around local: from %v, %d addresses", got[:1], len(got))
	}
	// Capped, with local out of the prefix: the window stays in the prefix, at the end nearest local.
	if n, got := count("10.200.0.1/8", "10.0.0.0/16"); n != MaxProbeAddrs || got[0] != netip.MustParseAddr("10.0.240.0") || got[n-1] != netip.MustParseAddr("10.0.255.255") {
		t.Errorf("capped, local above the prefix: %d from %v to %v", n, first(got), last(got))
	}
	// The network's address is the subnet's, not the prefix's: left out here.
	if n, got := count("10.0.0.1/8", "10.200.0.0/16"); n != MaxProbeAddrs || got[0] != netip.MustParseAddr("10.200.0.0") || got[n-1] != netip.MustParseAddr("10.200.15.255") {
		t.Errorf("capped, local below the prefix: %d from %v to %v", n, first(got), last(got))
	}
	// Everything: the subnet's, the window around local, at the ends of the address space too.
	if n, got := count("10.0.0.1/8", "0.0.0.0/0"); n != MaxProbeAddrs-2 || got[0] != netip.MustParseAddr("10.0.0.2") || !slices.Contains(got, netip.MustParseAddr("10.0.0.2")) || slices.Contains(got, netip.MustParseAddr("10.0.0.1")) {
		t.Errorf("a /0 around a /8: %d from %v to %v", n, first(got), last(got))
	}
	if n, got := count("0.0.0.5/0", "0.0.0.0/0"); n != MaxProbeAddrs-2 || got[0] != netip.MustParseAddr("0.0.0.1") {
		t.Errorf("the start of a /0: %d from %v to %v", n, first(got), last(got))
	}
	if n, got := count("255.255.255.250/0", "0.0.0.0/0"); n != MaxProbeAddrs-2 || got[n-1] != netip.MustParseAddr("255.255.255.254") {
		t.Errorf("the end of a /0: %d from %v to %v", n, first(got), last(got))
	}
	// A /31 has no network nor broadcast address, a /32 no other host.
	if n, got := count("10.0.0.0/31", "10.0.0.0/24"); n != 1 || got[0] != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("a /31: %v", got)
	}
	if n, got := count("10.0.0.1/32", "10.0.0.0/24"); n != 0 {
		t.Errorf("a /32: %v", got)
	}
	// Not IPv4, an IPv4-mapped address neither: nothing, without a panic.
	for _, c := range [][2]string{
		{"2001:db8::1/64", "2001:db8::/64"},
		{"2001:db8::1/64", ""},
		{"::ffff:10.2.3.75/120", "::ffff:10.2.3.0/120"},
		{"::ffff:10.2.3.75/120", ""},
		{"10.2.3.75/24", "::ffff:10.2.3.0/120"},
		{"10.2.3.75/24", "2001:db8::/64"},
	} {
		if n, got := count(c[0], c[1]); n != 0 {
			t.Errorf("%s within %q: %v", c[0], c[1], got)
		}
	}
	if n, got := count("10.2.3.75/24", "10.2.3.10/32"); n != 1 || got[0] != netip.MustParseAddr("10.2.3.10") {
		t.Errorf("one address: %v", got)
	}
}
