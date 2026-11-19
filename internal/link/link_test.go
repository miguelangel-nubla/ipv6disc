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
