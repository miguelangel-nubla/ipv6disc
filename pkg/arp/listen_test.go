package arp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

// arpPacket is an ARP packet: a request or a reply, of a sender for a target.
func arpPacket(op uint16, sender net.HardwareAddr, senderIP string, target net.HardwareAddr, targetIP string) []byte {
	b := request(sender, netip.MustParseAddr(senderIP), netip.MustParseAddr(targetIP))
	binary.BigEndian.PutUint16(b[6:8], op)
	copy(b[18:24], target)
	return b
}

// What a host sends tells it: its address at its MAC, when the frame is its own. A frame from
// another MAC than the sender's it tells names nobody, nor does a probe, nor a group's address.
func TestParseSender(t *testing.T) {
	host, other := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x20}, net.HardwareAddr{0x02, 0, 0, 0, 0, 0x66}
	everyone := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for name, c := range map[string]struct {
		packet []byte
		source net.HardwareAddr
		want   string
	}{
		"a request to all":               {arpPacket(opRequest, host, "192.168.1.20", nil, "192.168.1.1"), host, "192.168.1.20"},
		"a reply to this machine":        {arpPacket(opReply, host, "192.168.1.20", other, "192.168.1.5"), host, "192.168.1.20"},
		"a gratuitous request":           {arpPacket(opRequest, host, "192.168.1.20", nil, "192.168.1.20"), host, "192.168.1.20"},
		"a gratuitous reply":             {arpPacket(opReply, host, "192.168.1.20", everyone, "192.168.1.20"), host, "192.168.1.20"},
		"padded, as a frame is":          {append(arpPacket(opRequest, host, "192.168.1.20", nil, "192.168.1.1"), make([]byte, 18)...), host, "192.168.1.20"},
		"a probe, of no address yet":     {arpPacket(opRequest, host, "0.0.0.0", nil, "192.168.1.20"), host, ""},
		"another MAC than the frame's":   {arpPacket(opRequest, other, "192.168.1.66", nil, "192.168.1.1"), host, ""},
		"a proxy's answer for another":   {arpPacket(opReply, other, "192.168.1.66", host, "192.168.1.5"), host, ""},
		"the broadcast address":          {arpPacket(opRequest, host, "255.255.255.255", nil, "192.168.1.1"), host, ""},
		"a multicast address":            {arpPacket(opRequest, host, "224.0.0.1", nil, "192.168.1.1"), host, ""},
		"a group's MAC":                  {arpPacket(opRequest, everyone, "192.168.1.20", nil, "192.168.1.1"), everyone, ""},
		"no MAC":                         {arpPacket(opRequest, make(net.HardwareAddr, 6), "192.168.1.20", nil, "192.168.1.1"), make(net.HardwareAddr, 6), ""},
		"another operation":              {arpPacket(3, host, "192.168.1.20", nil, "192.168.1.1"), host, ""},
		"cut short":                      {arpPacket(opRequest, host, "192.168.1.20", nil, "192.168.1.1")[:27], host, ""},
		"a frame from a longer address":  {arpPacket(opRequest, host, "192.168.1.20", nil, "192.168.1.1"), append(net.HardwareAddr{}, 2, 0, 0, 0, 0, 0x20, 0, 0), ""},
		"a frame without a source":       {arpPacket(opRequest, host, "192.168.1.20", nil, "192.168.1.1"), nil, ""},
		"nothing":                        {nil, host, ""},
		"another hardware than Ethernet": {append([]byte{0, 6}, arpPacket(opRequest, host, "192.168.1.20", nil, "192.168.1.1")[2:]...), host, ""},
	} {
		mac, ip, ok := parseSender(c.packet, c.source)
		if ok != (c.want != "") || ok && (ip.String() != c.want || mac.String() != c.source.String()) {
			t.Errorf("%s: %s at %s, %v; want %q", name, ip, mac, ok, c.want)
		}
	}
}

func FuzzParseSender(f *testing.F) {
	host := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x20}
	f.Add(arpPacket(opRequest, host, "192.168.1.20", nil, "192.168.1.1"), []byte(host))
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, packet, source []byte) {
		mac, ip, ok := parseSender(packet, source)
		if !ok && (mac != nil || ip.IsValid()) {
			t.Errorf("nothing read, and something taken: %s at %s", ip, mac)
		}
		if ok && (!ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || len(mac) != 6 || mac[0]&1 != 0 || mac.String() != net.HardwareAddr(source).String()) {
			t.Errorf("read %s at %s, from %x", ip, mac, source)
		}
	})
}
