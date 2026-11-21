package udp

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
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

// Closing the listener ends its reading, which is no error to report: and a send on it fails then.
func TestListenClose(t *testing.T) {
	loopback := netip.MustParseAddr("::1")
	var errs atomic.Int32
	conn, err := Listen(loopbackInterface(t), loopback, func(netip.Addr) bool { return true }, func(error) { errs.Add(1) })
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	port := int(conn.GetListenAddrPort().Port())
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Send(loopback, port, []byte("hello")); err == nil {
		t.Error("sent on a closed listener")
	}
	// A reader that didn't end would report the closed socket's error over and over.
	time.Sleep(100 * time.Millisecond)
	if n := errs.Load(); n != 0 {
		t.Errorf("%d errors reported on close", n)
	}
}

// A destination's zone gives way to the listener's interface.
func TestSendOnItsInterface(t *testing.T) {
	loopback := netip.MustParseAddr("::1")
	found := make(chan netip.Addr, 1)
	conn, err := Listen(loopbackInterface(t), loopback, func(addr netip.Addr) bool { found <- addr; return true }, func(err error) { t.Error(err) })
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer conn.Close()
	if err := conn.Send(loopback.WithZone("no-such-interface"), int(conn.GetListenAddrPort().Port()), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-found:
	case <-time.After(2 * time.Second):
		t.Fatal("no packet")
	}
}

// A read error that stays doesn't spin the reading: each is reported, and the next read waits
// longer, 5ms then 10, 20, 40, 80: a handful in 100ms, not thousands. It still ends when closed.
func TestReadErrorsAreRetriedWithABackoff(t *testing.T) {
	var reads, errs atomic.Int32
	start := time.Now()
	failing := func([]byte) (int, *ipv6.ControlMessage, net.Addr, error) {
		reads.Add(1)
		if time.Since(start) > 100*time.Millisecond {
			return 0, nil, nil, net.ErrClosed
		}
		return 0, nil, nil, errors.New("network is down")
	}
	done := make(chan struct{})
	go func() {
		(&Conn{iface: &net.Interface{Index: 1}}).read(failing, func(netip.Addr) bool { return true }, func(error) { errs.Add(1) })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the reading did not end when closed")
	}
	// About 6, and fewer on a machine too busy to wake it in time: what must not be is the
	// thousands of a loop that doesn't wait.
	if n := reads.Load(); n < 2 || n > 8 {
		t.Errorf("%d reads in 100ms of errors, want about 6", n)
	}
	if errs.Load() != reads.Load()-1 {
		t.Errorf("%d errors reported of %d reads, the last one the close", errs.Load(), reads.Load())
	}
}

// A protocol that reads what the senders say gets each packet, with its sender.
func TestListenPackets(t *testing.T) {
	loopback := netip.MustParseAddr("::1")
	packets := make(chan string, 2)
	conn, err := ListenPackets(loopbackInterface(t), loopback, func(from netip.Addr, packet []byte) bool {
		packets <- from.String() + " " + string(packet)
		return true
	}, func(err error) { t.Error(err) })
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer conn.Close()
	for _, message := range []string{"the first", "and a second"} {
		if err := conn.Send(loopback, int(conn.GetListenAddrPort().Port()), []byte(message)); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-packets:
			if got != "::1 "+message {
				t.Errorf("got %q, want %q from ::1", got, message)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no packet")
		}
	}
}
