//go:build linux && integration

package ipv6disc

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"go.uber.org/zap/zaptest"
)

// A host with two addresses. One it is given while the worker runs is learned at once, by the
// advertisement the host sends for it. But a worker that starts afterwards, as after a restart,
// learns only the one the host answers the multicast ping from, its preferred: of the other,
// nothing is on the wire, until the host speaks from it. Then the solicitation it sends tells
// it, and the worker has it within a second.
//
// This is what a restart of a program on ipv6disc can't know at once: an address a host keeps
// beside the one it uses, as a stable one beside a newer, is learned when the host uses it, or
// from a router's neighbor table by a plugin, or by a solicitation when it is an EUI-64 address.
func TestLiveSecondAddress(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runInNamespace(t, "TestLiveSecondAddress")
		return
	}
	second := netip.MustParseAddr("fd00:6:1::55")

	// The NDP messages that reach this machine, by a socket of the test's: what the worker is
	// given to learn from.
	iface, err := net.InterfaceByName("veth-worker")
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := ndp.Listen(iface, ndp.Unspecified)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var mutex sync.Mutex
	var solicitedFrom []netip.Addr
	go func() {
		for {
			msg, _, from, err := conn.ReadFrom()
			if err != nil {
				return
			}
			if _, ok := msg.(*ndp.NeighborSolicitation); ok {
				mutex.Lock()
				solicitedFrom = append(solicitedFrom, from.WithZone(""))
				mutex.Unlock()
			}
		}
	}()
	solicited := func(from netip.Addr) bool {
		mutex.Lock()
		defer mutex.Unlock()
		return slices.Contains(solicitedFrom, from)
	}
	start := func() (*Worker, context.CancelFunc) {
		w := NewWorker(zaptest.NewLogger(t).Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Minute, Rediscover: 2 * time.Second,
			IPv6: Family{Enabled: true, Listen: true, Active: true}})
		ctx, cancel := context.WithCancel(context.Background())
		if err := w.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return w, func() {
			cancel()
			w.Wait()
			w.State.Close()
		}
	}

	w, stop := start()
	waitFor(t, 30*time.Second, "the peer's address", func() bool { return has(w, peerMAC, peerAddr) })
	// Given while the worker runs: the peer advertises it, and it is learned.
	ip(t, "-n", peerNamespace, "addr", "add", second.String()+"/64", "dev", "veth-peer", "nodad")
	waitFor(t, 10*time.Second, "the second address, as it is given", func() bool { return has(w, peerMAC, second) })
	stop()

	// A worker of now: the peer answers its pings from its newest address, its preferred, and
	// the first is no source of anything it sends.
	w, stop = start()
	defer stop()
	waitFor(t, 15*time.Second, "the address the peer answers from", func() bool { return has(w, peerMAC, second) })
	time.Sleep(5 * time.Second)
	if has(w, peerMAC, peerAddr) {
		t.Fatalf("the restarted worker learned %s, which the peer sends nothing from: the test's premise is gone, and this test is to say what does tell it now", peerAddr)
	}

	// The peer speaks from it: without the worker among its neighbors, it solicits its MAC from
	// that address, and the worker learns it from the solicitation.
	ip(t, "-n", peerNamespace, "neigh", "flush", "dev", "veth-peer")
	if out, err := exec.Command("ip", "netns", "exec", peerNamespace, "ping", "-6", "-c", "1", "-W", "1", "-I", peerAddr.String(), workerAddr.String()).CombinedOutput(); err != nil {
		t.Fatalf("the peer's ping from %s: %v\n%s", peerAddr, err, out)
	}
	waitFor(t, 2*time.Second, "the first address, once the peer speaks from it", func() bool { return has(w, peerMAC, peerAddr) })
	if !solicited(peerAddr) {
		t.Errorf("learned, but no solicitation from %s came: %v", peerAddr, solicitedFrom)
	}
}
