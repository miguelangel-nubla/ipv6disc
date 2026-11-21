package ndp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/mdlayher/ndp"
)

func TestProcessNDPPacket(t *testing.T) {
	hw := net.HardwareAddr{0, 0x0c, 0xe3, 0x71, 0x45, 0x68}
	target := netip.MustParseAddr("2001:db8::5")
	linkLocal := netip.MustParseAddr("fe80::20c:e3ff:fe71:4568")
	tests := []struct {
		name string
		msg  ndp.Message
		from netip.Addr
		want []netip.Addr
	}{
		{"advertisement", &ndp.NeighborAdvertisement{Override: true, TargetAddress: target, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Target, Addr: hw}}}, target, []netip.Addr{target}},
		{"advertisement from another address", &ndp.NeighborAdvertisement{Override: true, TargetAddress: target, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Target, Addr: hw}}}, linkLocal, []netip.Addr{target, linkLocal}},
		{"advertisement without the target's link-layer address", &ndp.NeighborAdvertisement{Override: true, TargetAddress: target}, target, nil},
		{"proxy advertisement", &ndp.NeighborAdvertisement{TargetAddress: target, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Target, Addr: hw}}}, linkLocal, []netip.Addr{linkLocal}},
		{"solicitation", &ndp.NeighborSolicitation{TargetAddress: target, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: hw}}}, linkLocal, []netip.Addr{linkLocal}},
		{"duplicate address detection", &ndp.NeighborSolicitation{TargetAddress: target}, netip.IPv6Unspecified(), nil},
		// As ndp.Conn.ReadFrom gives the senders: with the zone of the interface, always.
		{"advertisement, zoned sender", &ndp.NeighborAdvertisement{Override: true, TargetAddress: target, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Target, Addr: hw}}}, target.WithZone("eth0"), []netip.Addr{target}},
		{"advertisement from another address, zoned sender", &ndp.NeighborAdvertisement{Override: true, TargetAddress: target, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Target, Addr: hw}}}, linkLocal.WithZone("eth0"), []netip.Addr{target, linkLocal}},
		{"proxy advertisement, zoned sender", &ndp.NeighborAdvertisement{TargetAddress: target, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Target, Addr: hw}}}, linkLocal.WithZone("eth0"), []netip.Addr{linkLocal}},
		{"solicitation, zoned sender", &ndp.NeighborSolicitation{TargetAddress: target, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: hw}}}, linkLocal.WithZone("eth0"), []netip.Addr{linkLocal}},
		{"duplicate address detection with a source link-layer address", &ndp.NeighborSolicitation{TargetAddress: target, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: hw}}}, netip.IPv6Unspecified(), nil},
		{"duplicate address detection with a source link-layer address, zoned sender", &ndp.NeighborSolicitation{TargetAddress: target, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: hw}}}, netip.IPv6Unspecified().WithZone("eth0"), nil},
		{"router solicitation", &ndp.RouterSolicitation{Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: hw}}}, linkLocal, nil},
	}
	for _, tt := range tests {
		var got []netip.Addr
		processNDPPacket(tt.msg, tt.from, func(addr netip.Addr, gotHw net.HardwareAddr, _ string) {
			if gotHw.String() != hw.String() {
				t.Errorf("%s: got MAC %s, want %s", tt.name, gotHw, hw)
			}
			got = append(got, addr)
		})
		if len(got) != len(tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
			}
		}
	}
}

// From #3: the counters of adjacent connections must take 64-bit atomic operations on 32-bit
// platforms too.
func TestConnStatisticsAreAtomicallyAccessible(t *testing.T) {
	connections := make([]Conn, 2)
	for i := range connections {
		conn := &connections[i]
		conn.HostsFound.Add(1)
		conn.DiscoveryRuns.Add(2)
		conn.PacketsSent.Add(3)
		conn.PacketsReceived.Add(4)
		for key, want := range map[string]uint64{"hosts": 1, "runs": 2, "sent": 3, "recv": 4} {
			if got := conn.Stats()[key]; got != want {
				t.Errorf("connection %d %s = %v, want %d", i, key, got, want)
			}
		}
	}
}

// Only an error of the socket makes the listener wait before its next read: a message that can't
// be parsed, which anyone on the link can send, doesn't slow down the reading of the others.
func TestIsSocketError(t *testing.T) {
	if !isSocketError(fmt.Errorf("error reading: %w", &net.OpError{Op: "read", Err: errors.New("network is down")})) {
		t.Error("an error of the read: not of the socket")
	}
	_, err := ndp.ParseMessage([]byte{135, 0})
	if err == nil || isSocketError(err) {
		t.Errorf("a message cut short: %v, taken as of the socket", err)
	}
}

// How a message tells an address: an advertisement's target, answered when solicited, announced
// when not; its sender, of another address, and a solicitation's, heard.
func TestProcessNDPPacketWays(t *testing.T) {
	hw, _ := net.ParseMAC("00:1a:2b:3c:4d:5e")
	target := netip.MustParseAddr("2001:db8::1")
	linkLocal := netip.MustParseAddr("fe80::1")
	targetLLA := []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Target, Addr: hw}}
	for _, c := range []struct {
		name string
		msg  ndp.Message
		from netip.Addr
		want []string
	}{
		{"a solicited advertisement", &ndp.NeighborAdvertisement{Override: true, Solicited: true, TargetAddress: target, Options: targetLLA}, target, []string{"2001:db8::1 answered"}},
		{"an unsolicited one", &ndp.NeighborAdvertisement{Override: true, TargetAddress: target, Options: targetLLA}, target, []string{"2001:db8::1 announced"}},
		{"one from another address", &ndp.NeighborAdvertisement{Override: true, Solicited: true, TargetAddress: target, Options: targetLLA}, linkLocal, []string{"2001:db8::1 answered", "fe80::1 heard"}},
		{"a proxy's", &ndp.NeighborAdvertisement{Solicited: true, TargetAddress: target, Options: targetLLA}, linkLocal, []string{"fe80::1 heard"}},
		{"a solicitation", &ndp.NeighborSolicitation{TargetAddress: linkLocal, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: hw}}}, target, []string{"2001:db8::1 heard"}},
	} {
		var got []string
		processNDPPacket(c.msg, c.from, func(addr netip.Addr, _ net.HardwareAddr, way string) {
			got = append(got, addr.String()+" "+way)
		})
		if strings.Join(got, ", ") != strings.Join(c.want, ", ") {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
