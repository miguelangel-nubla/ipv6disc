package arp

import (
	"encoding/binary"
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

// request is the ARP request of sender, at senderIP, for target.
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
