package arp

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

// An ARP packet over Ethernet for IPv4, RFC 826: without the Ethernet header, which the kernel
// adds.
const (
	packetLen    = 28
	hardwareEth  = 1
	protocolIPv4 = 0x0800
	opRequest    = 1
	opReply      = 2
)

// probeAddrs returns what a probe from local asks for of targets: the IPv4 ones, an IPv4-mapped
// IPv6 address as the IPv4 one it is, which is how the replies tell them. ARP has no other
// addresses: a local one that isn't IPv4 is an error, and such targets are left out.
func probeAddrs(local netip.Addr, targets []netip.Addr) (netip.Addr, []netip.Addr, error) {
	local = local.Unmap()
	if !local.Is4() {
		return netip.Addr{}, nil, fmt.Errorf("the local address %s is not IPv4", local)
	}
	v4 := make([]netip.Addr, 0, len(targets))
	for _, target := range targets {
		if target = target.Unmap(); target.Is4() {
			v4 = append(v4, target)
		}
	}
	return local, v4, nil
}

// request is the ARP request of sender, at senderIP, for target: both IPv4, as probeAddrs gives
// them.
func request(sender net.HardwareAddr, senderIP, target netip.Addr) []byte {
	b := make([]byte, packetLen)
	binary.BigEndian.PutUint16(b[0:2], hardwareEth)
	binary.BigEndian.PutUint16(b[2:4], protocolIPv4)
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:8], opRequest)
	copy(b[8:14], sender)
	s := senderIP.As4()
	copy(b[14:18], s[:])
	// The target hardware address, unknown, stays zero.
	t := target.As4()
	copy(b[24:28], t[:])
	return b
}

// parseReply returns the sender of an ARP reply.
func parseReply(b []byte) (net.HardwareAddr, netip.Addr, bool) {
	if len(b) < packetLen ||
		binary.BigEndian.Uint16(b[0:2]) != hardwareEth ||
		binary.BigEndian.Uint16(b[2:4]) != protocolIPv4 ||
		b[4] != 6 || b[5] != 4 ||
		binary.BigEndian.Uint16(b[6:8]) != opReply {
		return nil, netip.Addr{}, false
	}
	mac := net.HardwareAddr(append([]byte(nil), b[8:14]...))
	ip := netip.AddrFrom4([4]byte(b[14:18]))
	return mac, ip, true
}

// repliesTo tells whether an ARP reply is addressed to the host at mac and ip: the answer to its
// own request, not to another's, nor a gratuitous one.
func repliesTo(b []byte, mac net.HardwareAddr, ip netip.Addr) bool {
	return len(b) >= packetLen && net.HardwareAddr(b[18:24]).String() == mac.String() && netip.AddrFrom4([4]byte(b[24:28])) == ip
}
