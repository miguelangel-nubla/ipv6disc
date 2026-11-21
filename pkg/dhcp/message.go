package dhcp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
)

// The messages of a DHCPv4 client that tell of it (RFC 2131, 2132).
const (
	Discover = 1
	Request  = 3
	Inform   = 8
)

// The messages of a DHCPv6 client that tell of it (RFC 8415).
const (
	Solicit6            = 1
	Request6            = 3
	Confirm6            = 4
	Renew6              = 5
	Rebind6             = 6
	InformationRequest6 = 11
)

const (
	bootRequest = 1
	// The fixed part of a BOOTP message, and the cookie that says options follow.
	bootpLen    = 236
	magicCookie = 0x63825363

	optionPad       = 0
	optionEnd       = 255
	optionHostName  = 12
	optionRequested = 50
	optionType      = 53
	optionFQDN      = 81
	// The flag of the FQDN option that says the name is in the encoding of DNS, not in ASCII.
	fqdnEncoded = 0x04

	option6FQDN = 39
)

// Message4 is what a DHCPv4 client says of itself, to all: in a DISCOVER, a REQUEST or an
// INFORM.
type Message4 struct {
	Type byte
	// The client's MAC, as the message has it: the one its server gives the lease to.
	MAC net.HardwareAddr
	// The host name it gives its server: the option 12, or without it the first label of the
	// option 81, its whole name. "" when it gives none.
	Name string
	// The address it asks for, or has: of a REQUEST, the requested address or, when it renews,
	// its own. Invalid when it tells none. It is the client's word, and no proof that it has it.
	Addr netip.Addr
}

// Parse4 reads a DHCPv4 message, the payload of a UDP packet to the port of the servers. Only
// what a client says itself is taken: a request, of an Ethernet client, not relayed, of one of
// the kinds above.
func Parse4(b []byte) (Message4, bool) {
	if len(b) < bootpLen+4 || b[0] != bootRequest || b[1] != 1 || b[2] != 6 || binary.BigEndian.Uint32(b[bootpLen:]) != magicCookie {
		return Message4{}, false
	}
	// Relayed, it comes from another link: the relay's word of a client that isn't here.
	if giaddr := netip.AddrFrom4([4]byte(b[24:28])); !giaddr.IsUnspecified() {
		return Message4{}, false
	}
	m := Message4{MAC: net.HardwareAddr(append([]byte(nil), b[28:34]...))}
	if m.MAC[0]&1 != 0 || allZero(m.MAC) {
		return Message4{}, false
	}
	ciaddr := netip.AddrFrom4([4]byte(b[12:16]))

	var fqdn string
	options := b[bootpLen+4:]
	for len(options) > 0 {
		code := options[0]
		if code == optionEnd {
			break
		}
		if code == optionPad {
			options = options[1:]
			continue
		}
		if len(options) < 2 || len(options) < 2+int(options[1]) {
			return Message4{}, false
		}
		value := options[2 : 2+int(options[1])]
		options = options[2+len(value):]
		switch code {
		case optionType:
			if len(value) == 1 {
				m.Type = value[0]
			}
		case optionHostName:
			if m.Name == "" {
				m.Name = strings.TrimRight(string(value), "\x00")
			}
		case optionRequested:
			if len(value) == 4 {
				m.Addr = netip.AddrFrom4([4]byte(value))
			}
		case optionFQDN:
			// Its flags and two bytes of no use now, then the name.
			if len(value) > 3 && fqdn == "" {
				if value[0]&fqdnEncoded != 0 {
					fqdn = firstLabel(value[3:])
				} else {
					fqdn, _, _ = strings.Cut(strings.TrimRight(string(value[3:]), "\x00"), ".")
				}
			}
		}
	}
	if m.Type != Discover && m.Type != Request && m.Type != Inform {
		return Message4{}, false
	}
	if m.Name == "" {
		m.Name = fqdn
	}
	// A DISCOVER may name the address the client would like, which it doesn't have.
	switch {
	case m.Type == Discover:
		m.Addr = netip.Addr{}
	case !m.Addr.IsValid() && !ciaddr.IsUnspecified():
		m.Addr = ciaddr
	}
	if m.Addr.IsValid() && (m.Addr.IsUnspecified() || m.Addr.IsMulticast() || m.Addr == netip.AddrFrom4([4]byte{255, 255, 255, 255})) {
		m.Addr = netip.Addr{}
	}
	return m, true
}

// Message6 is what a DHCPv6 client says of itself, to the servers of the link.
type Message6 struct {
	Type byte
	// The first label of the name it gives its server, the option 39: "" when it gives none.
	Name string
}

// Parse6 reads a DHCPv6 message, the payload of a UDP packet to the port of the servers. Only
// what a client says itself is taken: not what a relay forwards, nor what a server answers.
func Parse6(b []byte) (Message6, bool) {
	if len(b) < 4 {
		return Message6{}, false
	}
	m := Message6{Type: b[0]}
	switch m.Type {
	case Solicit6, Request6, Confirm6, Renew6, Rebind6, InformationRequest6:
	default:
		return Message6{}, false
	}
	// After the type, the transaction ID, of three bytes.
	options := b[4:]
	for len(options) > 0 {
		if len(options) < 4 || len(options) < 4+int(binary.BigEndian.Uint16(options[2:4])) {
			return Message6{}, false
		}
		code := binary.BigEndian.Uint16(options[0:2])
		value := options[4 : 4+int(binary.BigEndian.Uint16(options[2:4]))]
		options = options[4+len(value):]
		// Its flags, then the name, in the encoding of DNS.
		if code == option6FQDN && len(value) > 1 && m.Name == "" {
			m.Name = firstLabel(value[1:])
		}
	}
	return m, true
}

// firstLabel is the first label of a name in the encoding of DNS, whole or cut short, as a
// client that doesn't know its domain sends it: "" when there is none.
func firstLabel(b []byte) string {
	if len(b) < 2 || b[0] == 0 || b[0] > 63 || len(b) < 1+int(b[0]) {
		return ""
	}
	return string(b[1 : 1+int(b[0])])
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// The ports the clients send to, of each family.
const (
	serverPort  = 67
	serverPort6 = 547
)

// servers6 is the group of the DHCPv6 servers and relays of a link, which the clients send to.
var servers6 = netip.MustParseAddr("ff02::1:2")

// udp4 returns the payload of the UDP packet to the port of the DHCP servers that an IPv4 packet
// is, whole and not a fragment.
func udp4(packet []byte) ([]byte, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil, false
	}
	header := int(packet[0]&0xf) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if header < 20 || total < header+8 || total > len(packet) || packet[9] != 17 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return nil, false
	}
	return udpPayload(packet[header:total], serverPort)
}

// udp6 returns the sender and the payload of the UDP packet to the port of the DHCPv6 servers,
// at their group, that an IPv6 packet is: one with no header between the two, as the clients
// send them.
func udp6(packet []byte) (netip.Addr, []byte, bool) {
	if len(packet) < 40 || packet[0]>>4 != 6 || packet[6] != 17 {
		return netip.Addr{}, nil, false
	}
	length := int(binary.BigEndian.Uint16(packet[4:6]))
	if 40+length > len(packet) || netip.AddrFrom16([16]byte(packet[24:40])) != servers6 {
		return netip.Addr{}, nil, false
	}
	payload, ok := udpPayload(packet[40:40+length], serverPort6)
	return netip.AddrFrom16([16]byte(packet[8:24])), payload, ok
}

func udpPayload(datagram []byte, port uint16) ([]byte, bool) {
	if len(datagram) < 8 || binary.BigEndian.Uint16(datagram[2:4]) != port {
		return nil, false
	}
	length := int(binary.BigEndian.Uint16(datagram[4:6]))
	if length < 8 || length > len(datagram) {
		return nil, false
	}
	return datagram[8:length], true
}
