package ndp

import (
	"net"
	"net/netip"
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
		{"router solicitation", &ndp.RouterSolicitation{Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: hw}}}, linkLocal, nil},
	}
	for _, tt := range tests {
		var got []netip.Addr
		processNDPPacket(tt.msg, tt.from, func(addr netip.Addr, gotHw net.HardwareAddr) {
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
