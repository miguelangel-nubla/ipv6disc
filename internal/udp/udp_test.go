package udp

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// loopbackInterface is the machine's loopback interface.
func loopbackInterface(t *testing.T) *net.Interface {
	ifaces, _ := net.Interfaces()
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagLoopback != 0 {
			return &ifaces[i]
		}
	}
	t.Skip("no loopback interface")
	return nil
}

func TestListen(t *testing.T) {
	loopback := netip.MustParseAddr("::1")
	iface := loopbackInterface(t)
	found := make(chan netip.Addr, 2)
	var calls atomic.Int32
	conn, err := Listen(iface, loopback, func(addr netip.Addr) bool {
		found <- addr
		return calls.Add(1) == 1 // the first sender counts as a host found, the second not
	}, func(err error) { t.Error(err) })
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer conn.Close()

	port := int(conn.GetListenAddrPort().Port())
	for range 2 {
		if err := conn.Send(loopback, port, []byte("hello")); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		select {
		case addr := <-found:
			if addr != loopback {
				t.Errorf("got sender %s, want %s", addr, loopback)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no packet")
		}
	}
	// The counting follows the callback.
	deadline := time.Now().Add(2 * time.Second)
	for conn.HostsFound.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stats := conn.Stats()
	if stats["sent"] != uint64(2) || stats["recv"] != uint64(2) || stats["hosts"] != uint64(1) {
		t.Errorf("stats: %v", stats)
	}
}

// A listener hears only what comes in on its interface: the packets to its address that came in
// on another, as a host's routed in, aren't its interface's.
func TestListenOnItsInterfaceOnly(t *testing.T) {
	loopback := netip.MustParseAddr("::1")
	lo := loopbackInterface(t)
	other := &net.Interface{Index: lo.Index + 1000, Name: "other"}
	found := make(chan netip.Addr, 1)
	conn, err := Listen(other, loopback, func(addr netip.Addr) bool { found <- addr; return true }, func(err error) { t.Error(err) })
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer conn.Close()
	sender, err := Listen(lo, loopback, func(netip.Addr) bool { return false }, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if err := sender.Send(loopback, int(conn.GetListenAddrPort().Port()), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case addr := <-found:
		t.Errorf("heard %s, which came in on %s", addr, lo.Name)
	case <-time.After(500 * time.Millisecond):
	}
	if got := conn.Stats()["recv"]; got != uint64(0) {
		t.Errorf("counted %d packets of another interface", got)
	}
}
