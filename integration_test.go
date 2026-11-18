//go:build linux && integration

package ipv6disc

// The discovery over a real link, between two network namespaces. It needs root and iproute2:
//
//	go test -c -tags integration -o integration.test . && sudo ./integration.test -test.v
//
// The test makes the namespaces and a veth pair between them, then runs itself again inside the
// worker's namespace: the discovery sees that link only, not the machine's network.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

const (
	workerNamespace = "ipv6disc-test-worker"
	peerNamespace   = "ipv6disc-test-peer"
	peerMAC         = "02:00:00:00:00:02"
	insideEnv       = "IPV6DISC_TEST_INSIDE"
)

var (
	workerAddr = netip.MustParseAddr("fd00:6:1::1")
	peerAddr   = netip.MustParseAddr("fd00:6:1::2")
	workerIPv4 = netip.MustParseAddr("10.66.1.1")
	peerIPv4   = netip.MustParseAddr("10.66.1.2")
	// An address of the peer's it never sends from, as a stable address a host keeps beside its
	// temporary ones: deprecated, so never a source. Only a solicitation finds it.
	quietAddr = netip.MustParseAddr("fd00:6:1::99")
)

func ip(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func TestLiveDiscovery(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runInNamespace(t, "TestLiveDiscovery")
		return
	}

	w := NewWorker(zaptest.NewLogger(t).Sugar(), Config{Lifetime: 6 * time.Second, Rediscover: 2 * time.Second,
		IPv6: Family{Enabled: true, Listen: true, Active: true}, IPv4: Family{Enabled: true, Listen: true, Active: true}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// Active discovery: the peer answers the multicast ping, and the solicitation that follows
	// tells its MAC.
	waitFor(t, 30*time.Second, "the peer's address", func() bool { return has(w, peerMAC, peerAddr) })

	// Its IPv4 address: the peer sends nothing of itself, the sweep has the kernel resolve it,
	// and the neighbor table tells it.
	waitFor(t, 30*time.Second, "the peer's IPv4 address", func() bool { return has(w, peerMAC, peerIPv4) })

	// A quiet address: not found until solicited.
	ip(t, "-n", peerNamespace, "addr", "add", quietAddr.String()+"/64", "dev", "veth-peer", "nodad", "preferred_lft", "0")
	time.Sleep(3 * time.Second)
	if has(w, peerMAC, quietAddr) {
		t.Fatalf("%s found without soliciting it", quietAddr)
	}
	waitFor(t, 15*time.Second, "the solicited address", func() bool {
		if sent, err := w.Solicit(quietAddr); err != nil || sent == 0 {
			t.Logf("solicit: sent %d, %v", sent, err)
		}
		return has(w, peerMAC, quietAddr)
	})

	// An address that goes expires, while the others stay.
	ip(t, "-n", peerNamespace, "addr", "del", quietAddr.String()+"/64", "dev", "veth-peer")
	waitFor(t, 30*time.Second, "the removed address to expire", func() bool { return !has(w, peerMAC, quietAddr) })
	if !has(w, peerMAC, peerAddr) {
		t.Errorf("the peer's address expired too, though it answers")
	}

	// Stopping closes the listeners.
	cancel()
	stopped := make(chan struct{})
	go func() { w.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("the worker did not stop")
	}
	if prefixes := w.Prefixes(); len(prefixes) != 0 {
		t.Errorf("still listening on %v after stopping", prefixes)
	}
}

// has tells whether the worker knows ip at mac.
func has(w *Worker, mac string, ip netip.Addr) bool {
	collection, ok := w.GetAll()[mac]
	if !ok {
		return false
	}
	for _, addr := range collection.Get() {
		if addr.WithZone("") == ip {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, timeout time.Duration, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// The IPv4 addresses of a host that sends nothing, found with nothing broadcast: no sweep, the peer
// asked by unicast ARP.
func TestLiveIPv4Solicit(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runInNamespace(t, "TestLiveIPv4Solicit")
		return
	}

	w := NewWorker(zaptest.NewLogger(t).Sugar(), Config{Lifetime: time.Minute, Rediscover: 2 * time.Second,
		IPv6: Family{Enabled: true, Listen: true, Active: true}, IPv4: Family{Enabled: true, Listen: true}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}

	time.Sleep(5 * time.Second)
	if has(w, peerMAC, peerIPv4) {
		t.Fatalf("%s found without a sweep or a solicitation", peerIPv4)
	}

	// Only the subnets a prefix of the target's covers are asked.
	if found, err := w.SolicitIPv4(ctx, []IPv4Target{{MAC: mustMAC(peerMAC), Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}}); err != nil || found != 0 || has(w, peerMAC, peerIPv4) {
		t.Fatalf("a prefix off the link: found %d, %v", found, err)
	}
	// Nor the interfaces the configuration leaves out.
	excluding := NewWorker(zaptest.NewLogger(t).Sugar(), Config{Lifetime: time.Minute, Rediscover: time.Minute,
		IPv4: Family{Enabled: true}, ExcludeInterfaces: []string{"veth-*"}})
	if found, err := excluding.SolicitIPv4(ctx, []IPv4Target{{MAC: mustMAC(peerMAC)}}); err != nil || found != 0 {
		t.Fatalf("an interface left out: found %d, %v", found, err)
	}

	found, err := w.SolicitIPv4(ctx, []IPv4Target{{MAC: mustMAC(peerMAC), Prefixes: []netip.Prefix{netip.MustParsePrefix("10.66.1.0/24")}}})
	if err != nil || found == 0 || !has(w, peerMAC, peerIPv4) {
		t.Fatalf("solicited: found %d, %v; the peer's IPv4 known: %v", found, err, has(w, peerMAC, peerIPv4))
	}

	if found, err := w.SolicitIPv4(ctx, []IPv4Target{{MAC: mustMAC("02:00:00:00:00:99")}}); err != nil || found != 0 {
		t.Errorf("a MAC not on the link: found %d, %v", found, err)
	}
	cancel()
	w.Wait()
}

func mustMAC(s string) net.HardwareAddr {
	mac, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return mac
}

// runInNamespace makes the namespaces and their link, and runs the test inside the worker's.
func runInNamespace(t *testing.T, name string) {
	if os.Geteuid() != 0 {
		t.Skip("needs root, to make network namespaces")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2")
	}

	for _, ns := range []string{workerNamespace, peerNamespace} {
		exec.Command("ip", "netns", "del", ns).Run() // from a run that didn't clean up
		ip(t, "netns", "add", ns)
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
	}
	ip(t, "link", "add", "veth-worker", "netns", workerNamespace, "type", "veth", "peer", "name", "veth-peer", "netns", peerNamespace)
	ip(t, "-n", peerNamespace, "link", "set", "veth-peer", "address", peerMAC)
	for ns, link := range map[string]string{workerNamespace: "veth-worker", peerNamespace: "veth-peer"} {
		for _, setting := range []string{"all", "default", link} {
			ip(t, "netns", "exec", ns, "sysctl", "-qw", fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6=0", setting))
		}
		ip(t, "-n", ns, "link", "set", "lo", "up")
		ip(t, "-n", ns, "link", "set", link, "up")
	}
	ip(t, "-n", workerNamespace, "addr", "add", workerAddr.String()+"/64", "dev", "veth-worker", "nodad")
	ip(t, "-n", peerNamespace, "addr", "add", peerAddr.String()+"/64", "dev", "veth-peer", "nodad")
	ip(t, "-n", workerNamespace, "addr", "add", workerIPv4.String()+"/24", "dev", "veth-worker")
	ip(t, "-n", peerNamespace, "addr", "add", peerIPv4.String()+"/24", "dev", "veth-peer")

	cmd := exec.Command("ip", "netns", "exec", workerNamespace, os.Args[0], "-test.run=^"+name+"$", "-test.v", "-test.timeout=3m")
	cmd.Env = append(os.Environ(), insideEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("inside %s:\n%s", workerNamespace, out)
	if err != nil {
		t.Fatalf("the test inside the namespace failed: %v", err)
	}
}
