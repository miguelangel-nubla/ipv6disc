package lldp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"testing"
)

func tlv(kind int, value ...byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(kind<<9|len(value))), value...)
}

func frame(tlvs ...[]byte) []byte {
	return slices.Concat(tlvs...)
}

func management(family byte, address ...byte) []byte {
	value := append([]byte{byte(1 + len(address)), family}, address...)
	// How its interface is numbered, and no object identifier.
	return tlv(tlvManagement, append(value, 2, 0, 0, 0, 3, 0)...)
}

var (
	source  = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x31}
	chassis = tlv(tlvChassis, chassisMAC, 0x02, 0, 0, 0, 0, 0x30)
	port    = tlv(tlvPort, portMAC, 0x02, 0, 0, 0, 0, 0x31)
	ttl     = tlv(tlvTTL, 0, 120)
	name    = tlv(tlvSystemName, []byte("switch-1.lan")...)
	end     = tlv(tlvEnd)
)

func TestParse(t *testing.T) {
	v6 := netip.MustParseAddr("2001:db8::30").As16()
	n, ok := Parse(frame(chassis, port, ttl, tlv(4, []byte("port 1")...), name, tlv(6, []byte("a switch")...), tlv(7, 0, 4, 0, 4),
		management(familyIPv4, 192, 168, 1, 30), management(familyIPv6, v6[:]...), management(6, 2, 0, 0, 0, 0, 0x30),
		management(familyIPv4, 224, 0, 0, 1), management(familyIPv4, 1, 2), tlv(127, 0, 0x12, 0x0f, 1), end, []byte{0, 0, 0, 0}), source)
	if !ok || n.Name != "switch-1.lan" || n.Source.String() != source.String() || n.Chassis.String() != "02:00:00:00:00:30" || n.Port.String() != "02:00:00:00:00:31" ||
		!slices.Equal(n.Addrs, []netip.Addr{netip.MustParseAddr("192.168.1.30"), netip.MustParseAddr("2001:db8::30")}) {
		t.Errorf("a switch: %+v, %v", n, ok)
	}

	for what, c := range map[string]struct {
		payload []byte
		ok      bool
		name    string
	}{
		// A chassis and a port known by a name, as a host's interface, tell no MAC.
		"IDs that are names":      {frame(tlv(tlvChassis, 7, 'h', 'o', 's', 't'), tlv(tlvPort, 5, 'e', 't', 'h', '0'), ttl, name, end), true, "switch-1.lan"},
		"without its end":         {frame(chassis, port, ttl, name), true, "switch-1.lan"},
		"no name":                 {frame(chassis, port, ttl, end), true, ""},
		"it is going":             {frame(chassis, port, tlv(tlvTTL, 0, 0), name, end), false, ""},
		"a TLV longer than it is": {frame(chassis, port, ttl, name)[:30], false, ""},
		"no chassis":              {frame(port, ttl, name, end), false, ""},
		"nothing":                 {nil, false, ""},
		"its end alone":           {end, false, ""},
	} {
		n, ok := Parse(c.payload, source)
		if ok != c.ok || n.Name != c.name || what == "IDs that are names" && (n.Chassis != nil || n.Port != nil) {
			t.Errorf("%s: %+v, %v; want %v with the name %q", what, n, ok, c.ok, c.name)
		}
	}
	// A group's MAC, or none, as a chassis, is no host's.
	for _, mac := range [][]byte{{0x01, 0x80, 0xc2, 0, 0, 0x0e}, {0, 0, 0, 0, 0, 0}} {
		if n, _ := Parse(frame(tlv(tlvChassis, append([]byte{chassisMAC}, mac...)...), ttl, end), source); n.Chassis != nil {
			t.Errorf("the chassis %s taken as a host's MAC", net.HardwareAddr(mac))
		}
	}
	// No more addresses than a frame may tell.
	many := [][]byte{chassis, ttl}
	for i := range 3 * maxAddrs {
		many = append(many, management(familyIPv4, 10, 0, 0, byte(i+1)))
	}
	if n, ok := Parse(frame(many...), source); !ok || len(n.Addrs) != maxAddrs {
		t.Errorf("%d addresses taken of a frame, want %d at most", len(n.Addrs), maxAddrs)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(frame(chassis, port, ttl, name, management(familyIPv4, 192, 168, 1, 30), end))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, payload []byte) {
		n, ok := Parse(payload, source)
		if !ok && (n.Name != "" || n.Source != nil || len(n.Addrs) != 0) {
			t.Errorf("nothing read, and something taken: %+v", n)
		}
		if len(n.Addrs) > maxAddrs || len(n.Name) > 511 || n.Chassis != nil && len(n.Chassis) != 6 || n.Port != nil && len(n.Port) != 6 {
			t.Errorf("read %+v", n)
		}
		for _, addr := range n.Addrs {
			if !addr.IsValid() || addr.IsMulticast() || addr.IsUnspecified() {
				t.Errorf("an address that is no host's: %s", addr)
			}
		}
	})
}
