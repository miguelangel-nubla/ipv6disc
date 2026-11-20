package arp

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// What parseNetlinkNeighbors reads of the netlink messages of Linux, from linux/netlink.h,
// linux/rtnetlink.h and linux/neighbour.h.
const (
	nlmsgHeaderLen = 16
	nlmsgDone      = 3
	rtmNewNeigh    = 28
	ndmsgLen       = 12
	ndaDst         = 1
	ndaLladdr      = 2
	afInet         = 2

	nudReachable = 0x02
	nudDelay     = 0x08
	nudProbe     = 0x10
	nudPermanent = 0x80
)

// parseNetlinkNeighbors reads the IPv4 neighbors of a dump of RTM_GETNEIGH. Those confirmed
// recently or permanent count, the states REACHABLE, DELAY, PROBE and PERMANENT: a stale entry can
// stay long after its host left, and FAILED, INCOMPLETE and NOARP ones, as the multicast groups',
// are no host's. An entry is REACHABLE for the kernel's base_reachable_time only, 15 to 45s, after
// it was confirmed: what a sweep resolved is to be read right after it. Those of a broadcast or
// multicast address, or of a MAC that isn't an Ethernet host's, are left out. interfaces names the
// interface of an index.
func parseNetlinkNeighbors(b []byte, interfaces func(int) string) []Neighbor {
	var neighbors []Neighbor
	for len(b) >= nlmsgHeaderLen {
		length := int(binary.NativeEndian.Uint32(b[0:4]))
		kind := binary.NativeEndian.Uint16(b[4:6])
		if length < nlmsgHeaderLen || length > len(b) || kind == nlmsgDone {
			break
		}
		if kind == rtmNewNeigh {
			if n, ok := parseNeighMessage(b[nlmsgHeaderLen:length], interfaces); ok {
				neighbors = append(neighbors, n)
			}
		}
		if align(length) >= len(b) {
			break
		}
		b = b[align(length):]
	}
	return neighbors
}

func parseNeighMessage(data []byte, interfaces func(int) string) (Neighbor, bool) {
	if len(data) < ndmsgLen || data[0] != afInet {
		return Neighbor{}, false
	}
	index := int(int32(binary.NativeEndian.Uint32(data[4:8])))
	state := binary.NativeEndian.Uint16(data[8:10])
	if state&(nudReachable|nudDelay|nudProbe|nudPermanent) == 0 {
		return Neighbor{}, false
	}

	var n Neighbor
	attributes := data[ndmsgLen:]
	for len(attributes) >= 4 {
		length := int(binary.NativeEndian.Uint16(attributes[0:2]))
		kind := binary.NativeEndian.Uint16(attributes[2:4])
		if length < 4 || length > len(attributes) {
			break
		}
		value := attributes[4:length]
		switch kind {
		case ndaDst:
			if ip, ok := netip.AddrFromSlice(value); ok && ip.Is4() {
				n.IP = ip
			}
		case ndaLladdr:
			if len(value) == 6 && !allZero(value) {
				n.MAC = net.HardwareAddr(append([]byte(nil), value...))
			}
		}
		attributes = attributes[min(align(length), len(attributes)):]
	}
	if !n.IP.IsValid() || n.MAC == nil || !isHost(n.IP, n.MAC) {
		return Neighbor{}, false
	}
	if interfaces != nil {
		n.Interface = interfaces(index)
	}
	return n, true
}

// align rounds a netlink length up to 4 bytes.
func align(n int) int {
	return (n + 3) &^ 3
}
