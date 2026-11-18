package udp

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestListen(t *testing.T) {
	loopback := netip.MustParseAddr("::1")
	iface := &net.Interface{Name: ""}
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
