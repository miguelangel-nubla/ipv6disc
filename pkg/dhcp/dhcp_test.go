package dhcp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/bpf"
)

type option struct {
	code  byte
	value []byte
}

// message4 is a DHCPv4 message of a client at mac, with those options.
func message4(op byte, mac net.HardwareAddr, ciaddr, giaddr netip.Addr, options ...option) []byte {
	b := make([]byte, bootpLen+4)
	b[0], b[1], b[2] = op, 1, 6
	c, g := ciaddr.As4(), giaddr.As4()
	copy(b[12:16], c[:])
	copy(b[24:28], g[:])
	copy(b[28:34], mac)
	binary.BigEndian.PutUint32(b[bootpLen:], magicCookie)
	for _, o := range options {
		b = append(b, o.code, byte(len(o.value)))
		b = append(b, o.value...)
	}
	return append(b, optionEnd)
}

var (
	clientMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x20}
	none      = netip.IPv4Unspecified()
	kind      = func(t byte) option { return option{optionType, []byte{t}} }
	hostName  = func(name string) option { return option{optionHostName, []byte(name)} }
	requested = option{optionRequested, []byte{192, 168, 1, 20}}
)

func TestParse4(t *testing.T) {
	leased := netip.MustParseAddr("192.168.1.20")
	for name, c := range map[string]struct {
		packet []byte
		want   Message4
		ok     bool
	}{
		"a DISCOVER with its name": {message4(1, clientMAC, none, none, kind(Discover), hostName("Printer")),
			Message4{Type: Discover, MAC: clientMAC, Name: "Printer"}, true},
		// The address a DISCOVER asks for is one it would like: it doesn't have it.
		"a DISCOVER that asks for an address": {message4(1, clientMAC, none, none, kind(Discover), requested),
			Message4{Type: Discover, MAC: clientMAC}, true},
		"a REQUEST for the address offered": {message4(1, clientMAC, none, none, option{optionPad, nil}, kind(Request), requested, hostName("printer\x00")),
			Message4{Type: Request, MAC: clientMAC, Name: "printer", Addr: leased}, true},
		"a REQUEST that renews": {message4(1, clientMAC, leased, none, kind(Request), hostName("printer")),
			Message4{Type: Request, MAC: clientMAC, Name: "printer", Addr: leased}, true},
		"an INFORM": {message4(1, clientMAC, leased, none, kind(Inform)),
			Message4{Type: Inform, MAC: clientMAC, Addr: leased}, true},
		"its whole name, in ASCII": {message4(1, clientMAC, none, none, kind(Request), option{optionFQDN, append([]byte{0, 0, 0}, "printer.lan.example"...)}),
			Message4{Type: Request, MAC: clientMAC, Name: "printer"}, true},
		"its whole name, as DNS has it": {message4(1, clientMAC, none, none, kind(Request), option{optionFQDN, append([]byte{fqdnEncoded, 0, 0, 7}, "printer\x03lan\x00"...)}),
			Message4{Type: Request, MAC: clientMAC, Name: "printer"}, true},
		// A client that doesn't know its domain sends its first label alone, without an end.
		"a name without its domain, as DNS has it": {message4(1, clientMAC, none, none, kind(Request), option{optionFQDN, append([]byte{fqdnEncoded, 0, 0, 7}, "printer"...)}),
			Message4{Type: Request, MAC: clientMAC, Name: "printer"}, true},
		"a label longer than the option": {message4(1, clientMAC, none, none, kind(Request), option{optionFQDN, append([]byte{fqdnEncoded, 0, 0, 9}, "printer"...)}),
			Message4{Type: Request, MAC: clientMAC}, true},
		// The host name it gives comes before its whole name.
		"both names": {message4(1, clientMAC, none, none, kind(Request), option{optionFQDN, append([]byte{0, 0, 0}, "whole.lan"...)}, hostName("short")),
			Message4{Type: Request, MAC: clientMAC, Name: "short"}, true},
		"an address that is none": {message4(1, clientMAC, none, none, kind(Request), option{optionRequested, []byte{255, 255, 255, 255}}),
			Message4{Type: Request, MAC: clientMAC}, true},

		"a server's answer":        {message4(2, clientMAC, none, none, kind(5), hostName("evil")), Message4{}, false},
		"an OFFER sent as request": {message4(1, clientMAC, none, none, kind(2), hostName("evil")), Message4{}, false},
		"a RELEASE":                {message4(1, clientMAC, leased, none, kind(7)), Message4{}, false},
		"no message type":          {message4(1, clientMAC, none, none, hostName("bootp")), Message4{}, false},
		"relayed from elsewhere":   {message4(1, clientMAC, none, netip.MustParseAddr("10.0.0.1"), kind(Discover), hostName("far")), Message4{}, false},
		"a group's MAC":            {message4(1, net.HardwareAddr{0x01, 0, 0x5e, 0, 0, 1}, none, none, kind(Discover)), Message4{}, false},
		"no MAC":                   {message4(1, make(net.HardwareAddr, 6), none, none, kind(Discover)), Message4{}, false},
		"an option cut short":      {append(message4(1, clientMAC, none, none, kind(Discover))[:bootpLen+7], optionHostName, 9, 'x'), Message4{}, false},
		"no cookie":                {message4(1, clientMAC, none, none, kind(Discover))[:bootpLen], Message4{}, false},
		"empty":                    {nil, Message4{}, false},
	} {
		got, ok := Parse4(c.packet)
		if ok != c.ok || got.Type != c.want.Type || got.MAC.String() != c.want.MAC.String() || got.Name != c.want.Name || got.Addr != c.want.Addr {
			t.Errorf("%s: %+v, %v; want %+v, %v", name, got, ok, c.want, c.ok)
		}
	}
	other := message4(1, clientMAC, none, none, kind(Discover))
	other[1] = 6 // another hardware than Ethernet
	if _, ok := Parse4(other); ok {
		t.Error("a client that is not Ethernet's")
	}
}

// message6 is a DHCPv6 message with those options.
func message6(kind byte, options ...[]byte) []byte {
	b := []byte{kind, 1, 2, 3}
	for _, o := range options {
		b = append(b, o...)
	}
	return b
}

func option6(code uint16, value []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, code)
	b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
	return append(b, value...)
}

func TestParse6(t *testing.T) {
	clientID := option6(1, []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 0x20})
	fqdn := func(name string) []byte { return option6(option6FQDN, append([]byte{1}, name...)) }
	for name, c := range map[string]struct {
		packet []byte
		want   Message6
		ok     bool
	}{
		"a SOLICIT with its name":     {message6(Solicit6, clientID, fqdn("\x07printer\x03lan\x00")), Message6{Solicit6, "printer"}, true},
		"a REQUEST, its name cut":     {message6(Request6, fqdn("\x07printer"), clientID), Message6{Request6, "printer"}, true},
		"a RENEW without a name":      {message6(Renew6, clientID), Message6{Renew6, ""}, true},
		"a CONFIRM":                   {message6(Confirm6, fqdn("\x07printer\x00")), Message6{Confirm6, "printer"}, true},
		"an INFORMATION-REQUEST":      {message6(InformationRequest6, fqdn("\x07printer\x00")), Message6{InformationRequest6, "printer"}, true},
		"a REBIND":                    {message6(Rebind6, fqdn("\x07printer\x00")), Message6{Rebind6, "printer"}, true},
		"an empty name":               {message6(Solicit6, fqdn("\x00")), Message6{Solicit6, ""}, true},
		"a label longer than it is":   {message6(Solicit6, fqdn("\x09printer")), Message6{Solicit6, ""}, true},
		"a pointer in place of label": {message6(Solicit6, fqdn("\xc0\x0c")), Message6{Solicit6, ""}, true},
		"a server's ADVERTISE":        {message6(2, fqdn("\x04evil\x00")), Message6{}, false},
		"a server's REPLY":            {message6(7, fqdn("\x04evil\x00")), Message6{}, false},
		"what a relay forwards":       {message6(12, fqdn("\x04evil\x00")), Message6{}, false},
		"an option cut short":         {append(message6(Solicit6), 0, 39, 0, 9, 1), Message6{}, false},
		"cut in its header":           {[]byte{Solicit6, 1}, Message6{}, false},
	} {
		if got, ok := Parse6(c.packet); ok != c.ok || got != c.want {
			t.Errorf("%s: %+v, %v; want %+v, %v", name, got, ok, c.want, c.ok)
		}
	}
}

// packet4 is the IPv4 packet of a UDP one, with those ports and that payload.
func packet4(sourcePort, port uint16, payload []byte, headerOptions int) []byte {
	header := 20 + headerOptions
	b := make([]byte, header+8)
	b[0] = 0x40 | byte(header/4)
	binary.BigEndian.PutUint16(b[2:4], uint16(header+8+len(payload)))
	b[8], b[9] = 64, 17
	copy(b[16:20], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(b[header:], sourcePort)
	binary.BigEndian.PutUint16(b[header+2:], port)
	binary.BigEndian.PutUint16(b[header+4:], uint16(8+len(payload)))
	return append(b, payload...)
}

func packet6(from, to netip.Addr, port uint16, payload []byte) []byte {
	b := make([]byte, 48)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(8+len(payload)))
	b[6], b[7] = 17, 1
	f, d := from.As16(), to.As16()
	copy(b[8:24], f[:])
	copy(b[24:40], d[:])
	binary.BigEndian.PutUint16(b[40:], 546)
	binary.BigEndian.PutUint16(b[42:], port)
	binary.BigEndian.PutUint16(b[44:], uint16(8+len(payload)))
	return append(b, payload...)
}

// The filters of the sockets take the packets to the ports of the DHCP servers, and those alone;
// and what is read of a packet is what was sent in it.
func TestFiltersAndPackets(t *testing.T) {
	vm4, err := bpf.NewVM(filter4)
	if err != nil {
		t.Fatal(err)
	}
	vm6, err := bpf.NewVM(filter6)
	if err != nil {
		t.Fatal(err)
	}
	discover := message4(1, clientMAC, none, none, kind(Discover), hostName("printer"))
	fragment := packet4(68, 67, discover, 0)
	fragment[7] = 5 // not the first of its packet
	more := packet4(68, 67, discover, 0)
	more[6] = 0x20 // more fragments follow
	tcp := packet4(68, 67, discover, 0)
	tcp[9] = 6
	for name, c := range map[string]struct {
		packet        []byte
		taken, parsed bool
	}{
		"a client's message":            {packet4(68, 67, discover, 0), true, true},
		"with options in its IP header": {packet4(68, 67, discover, 8), true, true},
		"a server's answer":             {packet4(67, 68, discover, 0), false, false},
		"to another port":               {packet4(68, 53, discover, 0), false, false},
		"a later fragment":              {fragment, false, false},
		"a first fragment":              {more, true, false},
		"TCP":                           {tcp, false, false},
		"cut short":                     {packet4(68, 67, discover, 0)[:40], true, false},
	} {
		n, err := vm4.Run(c.packet)
		if err != nil || (n > 0) != c.taken {
			t.Errorf("%s: the filter takes %d bytes, %v; want taken %v", name, n, err, c.taken)
		}
		payload, ok := udp4(c.packet)
		if ok != c.parsed || ok && string(payload) != string(discover) {
			t.Errorf("%s: read %v, want %v", name, ok, c.parsed)
		}
	}

	client, servers := netip.MustParseAddr("fe80::20"), netip.MustParseAddr("ff02::1:2")
	solicit := message6(Solicit6, option6(option6FQDN, append([]byte{1}, "\x07printer\x00"...)))
	extension := packet6(client, servers, 547, solicit)
	extension[6] = 0 // a hop-by-hop header first
	for name, c := range map[string]struct {
		packet        []byte
		taken, parsed bool
	}{
		"a client's message":      {packet6(client, servers, 547, solicit), true, true},
		"to a server alone":       {packet6(client, netip.MustParseAddr("fe80::1"), 547, solicit), true, false},
		"a server's answer":       {packet6(netip.MustParseAddr("fe80::1"), client, 546, solicit), false, false},
		"with a header before it": {extension, false, false},
		"cut short":               {packet6(client, servers, 547, solicit)[:50], true, false},
	} {
		n, err := vm6.Run(c.packet)
		if err != nil || (n > 0) != c.taken {
			t.Errorf("IPv6, %s: the filter takes %d bytes, %v; want taken %v", name, n, err, c.taken)
		}
		from, payload, ok := udp6(c.packet)
		if ok != c.parsed || ok && (string(payload) != string(solicit) || from != client) {
			t.Errorf("IPv6, %s: read %v from %s, want %v", name, ok, from, c.parsed)
		}
	}
}

// What a Conn takes is told, and counted: a message of a client, its name when it gives one, and
// over DHCPv6 only from a link-local address, which is where a client sends from. And only what
// the client sent itself: a message with the MAC of a host, in a frame from another, is that
// other's word, and tells nothing.
func TestTake(t *testing.T) {
	var heard []string
	handler := Handler{
		Client4: func(m Message4) bool { heard = append(heard, m.MAC.String()+" "+m.Name); return m.Name != "" },
		Client6: func(from netip.Addr, hw net.HardwareAddr, m Message6) bool {
			heard = append(heard, from.String()+" "+hw.String()+" "+m.Name)
			return true
		},
	}
	other := net.HardwareAddr{2, 0, 0, 0, 0, 0x66}
	conn := &Conn{}
	conn.take4(packet4(68, 67, message4(1, clientMAC, none, none, kind(Discover), hostName("printer")), 0), clientMAC, handler)
	conn.take4(packet4(68, 67, message4(1, clientMAC, none, none, kind(Discover)), 0), clientMAC, handler)
	conn.take4(packet4(68, 67, message4(2, clientMAC, none, none, kind(5), hostName("evil")), 0), clientMAC, handler)
	// Another host says it is the client.
	conn.take4(packet4(68, 67, message4(1, clientMAC, none, none, kind(Request), requested, hostName("evil")), 0), other, handler)
	conn.take4(packet4(68, 67, message4(1, clientMAC, none, none, kind(Request), requested, hostName("evil")), 0), nil, handler)
	servers := netip.MustParseAddr("ff02::1:2")
	named := message6(Solicit6, option6(option6FQDN, append([]byte{1}, "\x07printer\x00"...)))
	conn.take6(packet6(netip.MustParseAddr("fe80::20"), servers, 547, named), clientMAC, handler)
	conn.take6(packet6(netip.MustParseAddr("2001:db8::66"), servers, 547, named), clientMAC, handler)
	conn.take6(packet6(netip.MustParseAddr("fe80::20"), servers, 547, message6(Solicit6)), clientMAC, handler)
	// The frame it came in is told with it: whose address that is, is the caller's to know.
	conn.take6(packet6(netip.MustParseAddr("fe80::20"), servers, 547, named), other, handler)
	conn.take6(packet6(netip.MustParseAddr("fe80::20"), servers, 547, named), nil, handler)
	want := []string{"02:00:00:00:00:20 printer", "02:00:00:00:00:20 ", "fe80::20 02:00:00:00:00:20 printer", "fe80::20 02:00:00:00:00:66 printer"}
	if !slices.Equal(heard, want) {
		t.Errorf("heard %q, want %q", heard, want)
	}
	if stats := conn.Stats(); stats["recv"] != uint64(6) || stats["hosts"] != uint64(3) || len(stats) != 2 {
		t.Errorf("stats: %v", stats)
	}
}

func FuzzParse4(f *testing.F) {
	f.Add(message4(1, clientMAC, none, none, kind(Request), requested, hostName("printer")))
	f.Add(message4(1, clientMAC, none, none, kind(Request), option{optionFQDN, append([]byte{fqdnEncoded, 0, 0, 7}, "printer\x00"...)}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		m, ok := Parse4(packet)
		if !ok && (m.MAC != nil || m.Name != "" || m.Addr.IsValid()) {
			t.Errorf("nothing read, and something taken: %+v", m)
		}
		if ok && (len(m.MAC) != 6 || m.Addr.IsValid() && !m.Addr.Is4() || len(m.Name) > 255) {
			t.Errorf("read %+v", m)
		}
		if payload, ok := udp4(packet); ok {
			Parse4(payload)
		}
	})
}

func FuzzParse6(f *testing.F) {
	f.Add(message6(Solicit6, option6(option6FQDN, append([]byte{1}, "\x07printer\x00"...))))
	f.Add(packet6(netip.MustParseAddr("fe80::20"), netip.MustParseAddr("ff02::1:2"), 547, message6(Solicit6)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		m, ok := Parse6(packet)
		if !ok && m != (Message6{}) {
			t.Errorf("nothing read, and something taken: %+v", m)
		}
		if len(m.Name) > 63 {
			t.Errorf("a label of %d bytes", len(m.Name))
		}
		if _, payload, ok := udp6(packet); ok {
			Parse6(payload)
		}
	})
}
