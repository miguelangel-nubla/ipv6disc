package ping

import (
	"math"
	"net/netip"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

func message(t *testing.T, kind ipv6.ICMPType, body icmp.MessageBody) []byte {
	b, err := (&icmp.Message{Type: kind, Body: body}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIsEchoReply(t *testing.T) {
	// Of any identifier: another process's ping found a host too.
	reply := message(t, ipv6.ICMPTypeEchoReply, &icmp.Echo{ID: 0xbeef, Seq: 7, Data: make([]byte, 3000)})
	for name, c := range map[string]struct {
		b    []byte
		want bool
	}{
		"a reply":                     {reply, true},
		"a reply cut at the buffer":   {reply[:1500], true},
		"a reply without data":        {message(t, ipv6.ICMPTypeEchoReply, &icmp.Echo{}), true},
		"a request":                   {message(t, ipv6.ICMPTypeEchoRequest, &icmp.Echo{ID: 1, Seq: 1}), false},
		"a neighbor advertisement":    {message(t, ipv6.ICMPTypeNeighborAdvertisement, &icmp.RawBody{Data: make([]byte, 20)}), false},
		"a multicast listener report": {message(t, ipv6.ICMPTypeVersion2MulticastListenerReport, &icmp.RawBody{Data: make([]byte, 4)}), false},
		"a destination unreachable":   {message(t, ipv6.ICMPTypeDestinationUnreachable, &icmp.DstUnreach{Data: make([]byte, 48)}), false},
		"a type the library has not":  {[]byte{250, 0, 0, 0, 1, 2, 3, 4}, false},
	} {
		if got, err := isEchoReply(c.b); err != nil || got != c.want {
			t.Errorf("%s: %v, %v, want %v", name, got, err, c.want)
		}
	}
	// Shorter than its header, or than an echo's identifier and sequence.
	for _, short := range [][]byte{nil, {129}, {129, 0, 0}, {129, 0, 0, 0}} {
		if got, err := isEchoReply(short); err == nil || got {
			t.Errorf("% x: %v, %v, want an error", short, got, err)
		}
	}
}

// The identifier's counter goes past the 16 bits of the field, and past its own 32, without an
// error: nothing reads the identifier back.
func TestEchoRequest(t *testing.T) {
	saved := icmpIDCounter.Load()
	defer icmpIDCounter.Store(saved)
	for _, at := range []int32{0, 0xffff, math.MaxInt32, -2} {
		icmpIDCounter.Store(at)
		b, err := echoRequest()
		if err != nil {
			t.Fatalf("after %d: %v", at, err)
		}
		msg, err := icmp.ParseMessage(ipv6.ICMPTypeEchoRequest.Protocol(), b)
		if err != nil || msg.Type != ipv6.ICMPTypeEchoRequest {
			t.Fatalf("after %d: %v, %v", at, msg, err)
		}
		if echo := msg.Body.(*icmp.Echo); echo.ID != int(uint16(at+1)) || echo.Seq != 1 {
			t.Errorf("after %d: identifier %d, sequence %d", at, echo.ID, echo.Seq)
		}
	}
	if reply, err := isEchoReply(message(t, ipv6.ICMPTypeEchoRequest, &icmp.Echo{})); err != nil || reply {
		t.Errorf("a request read as a reply: %v", err)
	}
}

func TestAllNodes(t *testing.T) {
	if allNodes != netip.MustParseAddr("ff02::1") || !allNodes.IsLinkLocalMulticast() {
		t.Errorf("the multicast ping goes to %s", allNodes)
	}
}
