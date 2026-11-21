//go:build linux && integration

package ipv6disc

import (
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"
)

// recordsOfAddr are the records the instance has of mac's ip.
func (r report) recordsOfAddr(mac string, ip netip.Addr) []string {
	for _, a := range r.Hosts[mac] {
		if a.IP == ip {
			return a.Records
		}
	}
	return nil
}

// How each address of a host was seen, as it was: by real kernels, and a real avahi-daemon that
// announces the host's addresses. A worker on a, with IPv4 and mDNS; the host p.
//
//   - p answers the multicast ping, and the solicitation that follows: ping:answered, ndp:answered.
//   - avahi announces p's addresses, of its name: mdns:announced, IPv6 and IPv4.
//   - the sweep has a's kernel resolve p, whose table then reports it, and the listener hears
//     its reply: reported by the kernel from neighbors, arp:answered.
//   - p takes an address, and says so: ndp:announced.
//   - p speaks from an address, unasked: its solicitation and its ARP request are heard,
//     ndp:heard, arp:heard.
func TestLiveRecords(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveRecords")
		return
	}
	p := lan["p"]
	ip(t, "netns", "exec", p.namespace, "sysctl", "-qw", "net.ipv6.conf.lan.ndisc_notify=1")
	startAvahi(t, p.namespace, "p-host", false)
	a := startInstance(t, lan["a"].namespace, Config{Lifetime: time.Minute, Rediscover: 3 * time.Second,
		IPv6: Family{Enabled: true, Listen: true, Active: true}, IPv4: Family{Enabled: true, Listen: true, Active: true},
		Protocols: func() Protocols { ps := DefaultProtocols(); ps.MDNS.Enabled = true; return ps }()})
	defer a.stop()
	const on = " on lan"

	has := func(addr netip.Addr, want ...string) func() bool {
		return func() bool {
			got := a.report().recordsOfAddr(p.mac, addr)
			for _, w := range want {
				if !slices.Contains(got, w+on) {
					return false
				}
			}
			return true
		}
	}
	check := func(what string, timeout time.Duration, addr netip.Addr, want ...string) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for !has(addr, want...)() {
			if time.Now().After(deadline) {
				t.Errorf("%s: %s has %q, want %q", what, addr, a.report().recordsOfAddr(p.mac, addr), want)
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Logf("%s: %s has %q", what, addr, a.report().recordsOfAddr(p.mac, addr))
	}

	check("the ping answered, and the solicitation", 30*time.Second, p.ipv6, "ping:answered", "ndp:answered")
	check("announced by avahi", 30*time.Second, p.ipv6, "mdns:announced")
	check("the IPv4 address, by the sweep", 90*time.Second, p.ipv4, "reported by kernel from neighbors", "arp:answered")
	check("the IPv4 address, announced by avahi", 30*time.Second, p.ipv4, "mdns:announced")

	// An address p takes: it says so.
	taken := netip.MustParseAddr("fd00:6:5::77")
	ip(t, "-n", p.namespace, "addr", "add", taken.String()+"/64", "dev", "lan")
	check("an address taken", 15*time.Second, taken, "ndp:announced")

	// p speaks from its address, to a, which it has no neighbor entry of: it asks a's MAC.
	speak := func(args ...string) {
		ip(t, "-n", p.namespace, "neigh", "flush", "dev", "lan")
		out, err := exec.Command("ip", append([]string{"netns", "exec", p.namespace, "ping", "-c", "1", "-W", "1"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("ping %v: %v\n%s", args, err, out)
		}
	}
	speak("-6", "-I", p.ipv6.String(), lan["a"].ipv6.String())
	check("a solicitation from it", 5*time.Second, p.ipv6, "ndp:heard")
	speak("-4", "-I", p.ipv4.String(), lan["a"].ipv4.String())
	check("an ARP request from it", 5*time.Second, p.ipv4, "arp:heard")

	// q sends a record of b's address, as a proxy, or a liar, would: b runs no responder, so it is
	// no announcement of b's, nor q's, and b's address stays at b's MAC.
	q, b := lan["q"], lan["b"]
	waitFor(t, 30*time.Second, "b's address", func() bool { return a.report().has(b.mac, b.ipv6) })
	for range 3 {
		sayNameOf(t, q.namespace, q.ipv6, "liar.local.", b.ipv6, netip.MustParseAddrPort("[ff02::fb%lan]:5353"))
		time.Sleep(500 * time.Millisecond)
	}
	time.Sleep(time.Second)
	if got := a.report().recordsOfAddr(q.mac, b.ipv6); len(got) != 0 {
		t.Errorf("b's address at q's MAC, by q's record of it: %q", got)
	}

	// None of another host's: what p says is p's.
	for mac, addrs := range a.report().Hosts {
		if mac == p.mac {
			continue
		}
		for _, addr := range addrs {
			for _, r := range addr.Records {
				if r == "mdns:announced"+on {
					t.Errorf("%s of %s, announced over mDNS: only p's avahi announces", addr.IP, mac)
				}
			}
		}
	}
}
