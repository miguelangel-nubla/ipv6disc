package onlink

import (
	"net"
	"net/netip"
	"testing"
)

func TestWhere(t *testing.T) {
	link := Among(netip.MustParsePrefix("192.168.1.5/24"), netip.MustParsePrefix("2001:db8::5/64"), netip.MustParsePrefix("fe80::5/64"))
	for addr, want := range map[string][2]bool{
		"192.168.1.20":        {true, false},
		"::ffff:192.168.1.20": {true, false},
		"192.168.1.5":         {true, true},
		"192.168.2.20":        {false, false},
		"2001:db8::20":        {true, false},
		"2001:db8::5":         {true, true},
		"2001:db8:1::20":      {false, false},
		"fe80::20":            {true, false},
		"fe80::20%eth9":       {true, false},
		"fe80::5":             {true, true},
		"169.254.3.4":         {true, false},
		"224.0.0.251":         {false, false},
		"ff02::fb":            {false, false},
		"127.0.0.1":           {false, false},
		"::1":                 {false, false},
		"0.0.0.0":             {false, false},
	} {
		onLink, own := link.Where(netip.MustParseAddr(addr))
		if onLink != want[0] || own != want[1] || link.Has(netip.MustParseAddr(addr)) != (want[0] && !want[1]) {
			t.Errorf("%s: on the link %v, own %v; want %v", addr, onLink, own, want)
		}
	}
	if onLink, _ := link.Where(netip.Addr{}); onLink {
		t.Error("no address is on the link")
	}
}

// The addresses of an interface are read, with the length of their subnets.
func TestPrefixes(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skip(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		prefixes := Prefixes(&iface)
		if len(prefixes) == 0 {
			t.Skipf("%s has no address", iface.Name)
		}
		for _, p := range prefixes {
			if !p.IsValid() || !p.Addr().IsLoopback() && !p.Addr().IsLinkLocalUnicast() {
				t.Errorf("an address of %s: %s", iface.Name, p)
			}
		}
		if onLink, _ := Of(&iface).Where(netip.MustParseAddr("192.0.2.1")); onLink {
			t.Error("an address elsewhere is on the loopback's link")
		}
		return
	}
}
