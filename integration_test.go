//go:build linux && integration

package ipv6disc

// The discovery over a real link, between two network namespaces. It needs root and iproute2:
//
//	go test -c -tags integration -o integration.test . && go build -o ipv6disc ./cmd/ipv6disc && sudo ./integration.test -test.v
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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"go.uber.org/zap/zaptest"
	"golang.org/x/net/ipv6"
)

const (
	workerNamespace = "ipv6disc-test-worker"
	peerNamespace   = "ipv6disc-test-peer"
	peerMAC         = "02:00:00:00:00:02"
	insideEnv       = "IPV6DISC_TEST_INSIDE"
	advertiseEnv    = "IPV6DISC_TEST_ADVERTISE"
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

	w := NewWorker(zaptest.NewLogger(t).Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: 6 * time.Second, Rediscover: 2 * time.Second,
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

	// This machine's own addresses say so; the peer's don't.
	self := func(ip netip.Addr) (bool, bool) {
		for _, collection := range w.State.GetAll() {
			for _, a := range collection.Get() {
				if a.WithZone("") == ip {
					return true, a.Self()
				}
			}
		}
		return false, false
	}
	waitFor(t, 30*time.Second, "the worker's own addresses", func() bool {
		found6, self6 := self(workerAddr)
		found4, self4 := self(workerIPv4)
		return found6 && self6 && found4 && self4
	})
	if _, peerSelf := self(peerAddr); peerSelf {
		t.Error("the peer's address said this machine's")
	}

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

	w := NewWorker(zaptest.NewLogger(t).Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Minute, Rediscover: 2 * time.Second,
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
	excluding := NewWorker(zaptest.NewLogger(t).Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Minute, Rediscover: time.Minute,
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

// A neighbor advertisement that was forwarded, its hop limit below 255, tells no host: one sent to
// the worker's address from anywhere would otherwise give any address to any MAC. The same
// message from the link does.
func TestLiveNDPHopLimit(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runInNamespace(t, "TestLiveNDPHopLimit")
		return
	}

	w := NewWorker(zaptest.NewLogger(t).Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Minute, Rediscover: 2 * time.Second,
		IPv6: Family{Enabled: true, Listen: true, Active: true}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// The listener hears the link.
	waitFor(t, 30*time.Second, "the peer's address", func() bool { return has(w, peerMAC, peerAddr) })

	const forwardedMAC, onLinkMAC = "02:00:00:00:00:64", "02:00:00:00:00:ff"
	forwarded, onLink := netip.MustParseAddr("fd00:6:1::64"), netip.MustParseAddr("fd00:6:1::ff")
	for _, hopLimit := range []int{64, 254, 1} {
		advertise(t, hopLimit, forwarded, forwardedMAC)
	}
	// The socket read them before this one: once it is known, they were left out, not late.
	advertise(t, 255, onLink, onLinkMAC)
	waitFor(t, 15*time.Second, "the address advertised on the link", func() bool { return has(w, onLinkMAC, onLink) })
	if _, found := w.GetAll()[forwardedMAC]; found {
		t.Errorf("%s found at %s, by an advertisement with a hop limit below 255", forwarded, forwardedMAC)
	}
	cancel()
	w.Wait()
}

// advertise has the peer send the worker's address a neighbor advertisement of target at mac, with
// that hop limit, as a host anywhere could with one that isn't 255: the test binary again, in the
// peer's namespace.
func advertise(t *testing.T, hopLimit int, target netip.Addr, mac string) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", peerNamespace, os.Args[0], "-test.run=^TestAdvertise$")
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d %s %s", advertiseEnv, hopLimit, target, mac))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("advertising %s with hop limit %d: %v\n%s", target, hopLimit, err, out)
	}
}

// TestAdvertise is no test, but what advertise runs in the peer's namespace.
func TestAdvertise(t *testing.T) {
	var hopLimit int
	var target, mac string
	if n, _ := fmt.Sscanf(os.Getenv(advertiseEnv), "%d %s %s", &hopLimit, &target, &mac); n != 3 {
		t.Skip("run by advertise, in the peer's namespace")
	}
	iface, err := net.InterfaceByName("veth-peer")
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := ndp.Listen(iface, ndp.Addr(peerAddr.String()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	message := &ndp.NeighborAdvertisement{Override: true, TargetAddress: netip.MustParseAddr(target),
		Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Target, Addr: mustMAC(mac)}}}
	if err := conn.WriteTo(message, &ipv6.ControlMessage{HopLimit: hopLimit}, workerAddr); err != nil {
		t.Fatal(err)
	}
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
	makeLink(t)
	runInside(t, workerNamespace, name)
}

// makeLink makes the worker's namespace and the peer's, and the link between them.
func makeLink(t *testing.T) {
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
}

// runInside runs the test again inside a namespace.
func runInside(t *testing.T, namespace, name string) {
	cmd := exec.Command("ip", "netns", "exec", namespace, os.Args[0], "-test.run=^"+name+"$", "-test.v", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), insideEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("inside %s:\n%s", namespace, out)
	if err != nil {
		t.Fatalf("the test inside the namespace failed: %v", err)
	}
}

// Two networks of one wire, as two macvlan networks of a container on one bridge, and a bridge of
// the machine's own, as Docker's: the peer, one MAC on the wire, is heard over IPv6 on one, and has
// its IPv4 address on the other.
const (
	wirePeerMAC = "02:00:00:00:00:12"
	bridgeName  = "brx"
)

var (
	wireIPv6Worker = netip.MustParseAddr("fd00:6:2::1") // on wa, with 172.16.66.1/24
	wireIPv6Peer   = netip.MustParseAddr("fd00:6:2::2")
	wireIPv4Worker = netip.MustParseAddr("10.66.2.1") // on wb only
	wireIPv4Peer   = netip.MustParseAddr("10.66.2.2")
	bridgeIPv6     = netip.MustParseAddr("fd00:6:3::1") // the bridge's, with 172.20.66.1/24
)

// The peer's addresses are only on the interfaces of its wire: its multicast NDP, which a socket
// bound to the bridge's address hears too, isn't the bridge's, nor are the hosts routed to it.
// And its IPv4 address, in a prefix of the other network of the wire, is asked there, though its
// MAC was only seen on the first.
func TestLiveTwoNetworksOneWire(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runInTwoNetworks(t, "TestLiveTwoNetworksOneWire")
		return
	}

	w := NewWorker(zaptest.NewLogger(t).Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Minute, Rediscover: 2 * time.Second,
		IPv6: Family{Enabled: true, Listen: true, Active: true}, IPv4: Family{Enabled: true, Listen: true}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 30*time.Second, "the peer's IPv6 address", func() bool { return has(w, wirePeerMAC, wireIPv6Peer) })

	// The peer's multicast NDP: solicitations for the worker's address, which it forgets first, and
	// an unsolicited advertisement of a new address, to all nodes.
	for range 3 {
		ip(t, "-n", peerNamespace, "neigh", "flush", "all")
		exec.Command("ip", "netns", "exec", peerNamespace, "ping", "-6", "-c1", "-W1", wireIPv6Worker.String()).Run()
		time.Sleep(time.Second)
	}
	ip(t, "-n", peerNamespace, "addr", "add", "fd00:6:2::22/64", "dev", "br0")
	waitFor(t, 15*time.Second, "the peer's advertised address", func() bool { return has(w, wirePeerMAC, netip.MustParseAddr("fd00:6:2::22")) })
	time.Sleep(2 * time.Second)
	for _, a := range w.GetAll()[wirePeerMAC].Get() {
		if slices.Contains(a.Interfaces(), bridgeName) || slices.Contains(a.Interfaces(), "wb") {
			t.Errorf("%s seen on %v: only wa has the peer's IPv6", a.WithZone(""), a.Interfaces())
		}
	}

	// Its IPv4 address, in wb's subnet, though its MAC was only heard on wa.
	if has(w, wirePeerMAC, wireIPv4Peer) {
		t.Fatalf("%s found before soliciting it", wireIPv4Peer)
	}
	found, err := w.SolicitIPv4(ctx, []IPv4Target{{MAC: mustMAC(wirePeerMAC), Prefixes: []netip.Prefix{netip.MustParsePrefix("10.66.2.0/24")}}})
	if err != nil || found == 0 || !has(w, wirePeerMAC, wireIPv4Peer) {
		t.Fatalf("solicited in wb's subnet: found %d, %v; known: %v", found, err, has(w, wirePeerMAC, wireIPv4Peer))
	}
	cancel()
	w.Wait()
}

// runInTwoNetworks makes the worker's namespace with two links to the peer's bridge, wa and wb, and
// a bridge of its own with no port, and runs the test inside it.
func runInTwoNetworks(t *testing.T, name string) {
	if os.Geteuid() != 0 {
		t.Skip("needs root, to make network namespaces")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2")
	}
	for _, ns := range []string{workerNamespace, peerNamespace} {
		exec.Command("ip", "netns", "del", ns).Run()
		ip(t, "netns", "add", ns)
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
		for _, setting := range []string{"all", "default"} {
			ip(t, "netns", "exec", ns, "sysctl", "-qw", fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6=0", setting))
		}
		ip(t, "-n", ns, "link", "set", "lo", "up")
	}
	ip(t, "-n", peerNamespace, "link", "add", "br0", "address", wirePeerMAC, "type", "bridge")
	ip(t, "netns", "exec", peerNamespace, "sysctl", "-qw", "net.ipv6.conf.br0.ndisc_notify=1")
	for _, l := range []string{"wa", "wb"} {
		ip(t, "link", "add", l, "netns", workerNamespace, "type", "veth", "peer", "name", "p"+l, "netns", peerNamespace)
		ip(t, "-n", peerNamespace, "link", "set", "p"+l, "master", "br0")
		ip(t, "-n", peerNamespace, "link", "set", "p"+l, "up")
		ip(t, "-n", workerNamespace, "link", "set", l, "up")
	}
	ip(t, "-n", peerNamespace, "link", "set", "br0", "up")
	ip(t, "-n", workerNamespace, "link", "add", bridgeName, "type", "bridge")
	ip(t, "-n", workerNamespace, "link", "set", bridgeName, "up")

	ip(t, "-n", workerNamespace, "addr", "add", wireIPv6Worker.String()+"/64", "dev", "wa", "nodad")
	ip(t, "-n", workerNamespace, "addr", "add", "172.16.66.1/24", "dev", "wa")
	ip(t, "-n", workerNamespace, "addr", "add", wireIPv4Worker.String()+"/24", "dev", "wb")
	ip(t, "-n", workerNamespace, "addr", "add", bridgeIPv6.String()+"/64", "dev", bridgeName, "nodad")
	ip(t, "-n", workerNamespace, "addr", "add", "172.20.66.1/24", "dev", bridgeName)
	ip(t, "-n", peerNamespace, "addr", "add", wireIPv6Peer.String()+"/64", "dev", "br0", "nodad")
	ip(t, "-n", peerNamespace, "addr", "add", wireIPv4Peer.String()+"/24", "dev", "br0")

	runInside(t, workerNamespace, name)
}
