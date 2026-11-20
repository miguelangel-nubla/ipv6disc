package link

import (
	"net"
	"testing"

	"golang.org/x/net/ipv6"
)

func TestFrom(t *testing.T) {
	eth1 := &net.Interface{Index: 3, Name: "eth1"}
	for _, c := range []struct {
		cm   *ipv6.ControlMessage
		want bool
	}{
		{&ipv6.ControlMessage{IfIndex: 3}, true},
		{&ipv6.ControlMessage{IfIndex: 4}, false}, // another interface's multicast, or a routed packet
		{&ipv6.ControlMessage{}, true},            // a system that doesn't tell
		{nil, true},
	} {
		if got := From(c.cm, eth1); got != c.want {
			t.Errorf("%+v: %v, want %v", c.cm, got, c.want)
		}
	}
}

// RFC 4861 7.1.1 and 7.1.2: an NDP message with a hop limit other than 255 was forwarded, so it
// isn't of the link.
func TestOnLink(t *testing.T) {
	for _, c := range []struct {
		cm   *ipv6.ControlMessage
		told bool
		want bool
	}{
		{&ipv6.ControlMessage{HopLimit: 255}, true, true},
		{&ipv6.ControlMessage{HopLimit: 254}, true, false}, // through one router
		{&ipv6.ControlMessage{HopLimit: 64}, true, false},
		{&ipv6.ControlMessage{HopLimit: 0}, true, false},
		{nil, true, true}, // a system that doesn't tell
		{&ipv6.ControlMessage{HopLimit: 0}, false, true}, // the hop limit wasn't asked for: zero says nothing
		{&ipv6.ControlMessage{HopLimit: 64}, false, true},
	} {
		if got := OnLink(c.cm, c.told); got != c.want {
			t.Errorf("%+v, told %v: %v, want %v", c.cm, c.told, got, c.want)
		}
	}
}

// fakeConn records the flags asked of it, and fails those it doesn't have.
type fakeConn struct {
	asked ipv6.ControlFlags
	fails ipv6.ControlFlags
}

func (c *fakeConn) SetControlMessage(flags ipv6.ControlFlags, on bool) error {
	if flags&c.fails != 0 {
		return net.ErrClosed
	}
	c.asked |= flags
	return nil
}

// The hop limit is asked for apart from the interface, so that a system without the one still
// tells the other.
func TestEnable(t *testing.T) {
	conn := &fakeConn{}
	Enable(conn)
	if !EnableHopLimit(conn) || conn.asked != ipv6.FlagInterface|ipv6.FlagHopLimit {
		t.Errorf("asked %v", conn.asked)
	}
	conn = &fakeConn{fails: ipv6.FlagHopLimit}
	Enable(conn)
	if EnableHopLimit(conn) || conn.asked != ipv6.FlagInterface {
		t.Errorf("without the hop limit: asked %v", conn.asked)
	}
}
