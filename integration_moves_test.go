//go:build linux && integration

package ipv6disc

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// An address moves to the MAC that shows it, at once, not a lifetime after the MAC it left last
// showed it: by real kernels, and a real avahi-daemon. A worker on a, with addresses that stay five
// minutes, and the host p, named by avahi.
//
//   - p is made again with a new MAC, as a container, or a device whose network card was changed:
//     its addresses and its name go to the new MAC, and the old one is gone, with its name.
//   - q takes p's IPv4 address, which p gave up, and uses it: the address goes to q, and p keeps
//     its IPv6 address and its name.
func TestLiveAddressMoves(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveAddressMoves")
		return
	}
	p, q := lan["p"], lan["q"]
	const lifetime = 5 * time.Minute
	config := namesConfig(probing, probing)
	config.Lifetime = lifetime
	config.Hostnames.Lifetime = lifetime
	avahi := startAvahi(t, p.namespace, "printer-p", true)
	a := startInstance(t, lan["a"].namespace, config)
	defer a.stop()

	waitFor(t, 90*time.Second, "p's addresses, and its name", func() bool {
		r := a.report()
		return r.has(p.mac, p.ipv6) && r.has(p.mac, p.ipv4) && r.named(p.mac, "printer-p")
	})

	// p, made again with another MAC: its responder starts again, as the host's would.
	const newMAC = "02:00:00:00:05:12"
	avahi.stop()
	ip(t, "-n", p.namespace, "link", "set", "lan", "address", newMAC)
	startAvahi(t, p.namespace, "printer-p", true)
	moved := time.Now()
	waitFor(t, 60*time.Second, "p's addresses and name at its new MAC, and none at the old one", func() bool {
		r := a.report()
		return r.has(newMAC, p.ipv6) && r.has(newMAC, p.ipv4) && r.named(newMAC, "printer-p") &&
			len(r.Hosts[p.mac]) == 0 && len(r.Names[p.mac]) == 0
	})
	if took := time.Since(moved); took > lifetime/2 {
		t.Errorf("the move took %s, with addresses that stay %s", took.Round(time.Second), lifetime)
	}
	t.Logf("p moved to %s in %s", newMAC, time.Since(moved).Round(time.Second))

	// p gives up its IPv4 address, and q takes it, and uses it: it asks for a's MAC from it.
	ip(t, "-n", p.namespace, "addr", "del", p.ipv4.String()+"/26", "dev", "lan")
	ip(t, "-n", q.namespace, "addr", "add", p.ipv4.String()+"/26", "dev", "lan")
	taken := time.Now()
	waitFor(t, 60*time.Second, "p's old IPv4 address at q, and not at p", func() bool {
		ip(t, "-n", q.namespace, "neigh", "flush", "dev", "lan")
		exec.Command("ip", "netns", "exec", q.namespace, "ping", "-4", "-c", "1", "-W", "1", "-I", p.ipv4.String(), lan["a"].ipv4.String()).Run()
		r := a.report()
		return r.has(q.mac, p.ipv4) && !r.has(newMAC, p.ipv4)
	})
	t.Logf("p's old IPv4 address went to q in %s", time.Since(taken).Round(time.Second))
	r := a.report()
	if !r.has(newMAC, p.ipv6) || !r.named(newMAC, "printer-p") {
		t.Errorf("p lost what it kept: its addresses %+v, its names %+v", r.Hosts[newMAC], r.Names[newMAC])
	}
	if r.named(q.mac, "printer-p") {
		t.Error("q has p's name, by the address it took")
	}
}
