// Package arp reads IPv4 neighbor tables: the output of BSD's arp -an, and the kernel's own table.
package arp

import (
	"bufio"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// Neighbor is an IPv4 address and the MAC it was resolved to, with the interface.
type Neighbor struct {
	IP        netip.Addr
	MAC       net.HardwareAddr
	Interface string
}

// ParseBSD reads the neighbors in the output of arp -an, of FreeBSD and macOS:
//
//	? (192.168.1.10) at 00:11:22:33:44:55 on em0 expires in 1189 seconds [ethernet]
//	? (192.168.1.1) at 0:11:22:33:44:66 on en0 ifscope [ethernet]
//
// Incomplete entries, without a MAC, and expired ones, of hosts gone, are left out, and those of
// the broadcast addresses and the multicast groups, which macOS lists as any neighbor. It reads the
// arp -an of Linux's net-tools too, where the interface comes after the type:
//
//	? (192.168.1.10) at 00:11:22:33:44:55 [ether] on eth0
//
// A neighbor's MAC is of 6 bytes: an entry of another link layer, as Infiniband's, is left out.
func ParseBSD(output string) []Neighbor {
	var neighbors []Neighbor
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[2] != "at" || slices.Contains(fields, "expired") {
			continue
		}
		ip, err := netip.ParseAddr(strings.Trim(fields[1], "()"))
		if err != nil || !ip.Is4() {
			continue
		}
		mac, err := ParseMAC(fields[3])
		if err != nil || !isHost(ip, mac) {
			continue
		}
		var iface string
		for i := 4; i+1 < len(fields); i++ {
			if fields[i] == "on" {
				iface = fields[i+1]
				break
			}
		}
		neighbors = append(neighbors, Neighbor{IP: ip, MAC: mac, Interface: iface})
	}
	return neighbors
}

// isHost tells whether a table's entry is of a host: macOS lists the broadcast addresses, at
// ff:ff:ff:ff:ff:ff, and the multicast groups joined, at 01:00:5e:..., as any neighbor. A subnet's
// broadcast address doesn't tell by itself, so the group bit of the MAC is enough.
func isHost(ip netip.Addr, mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0]&1 == 0 &&
		!ip.IsMulticast() && !ip.IsUnspecified() && ip != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// ParseMAC reads a MAC as net.ParseMAC does, and also with octets of one digit, as macOS writes
// them: 0:11:22:3:44:55. As net.ParseMAC, it reads the addresses of 8 and 20 bytes too, and any
// MAC but the all-zero one, a group's as well: ParseBSD returns those of 6 bytes of a host only.
func ParseMAC(s string) (net.HardwareAddr, error) {
	octets := strings.Split(s, ":")
	if len(octets) == 6 {
		for i, o := range octets {
			if len(o) == 1 {
				octets[i] = "0" + o
			}
		}
		s = strings.Join(octets, ":")
	}
	mac, err := net.ParseMAC(s)
	if err != nil {
		return nil, err
	}
	// An all-zero MAC is no neighbor's.
	if allZero(mac) {
		return nil, &net.AddrError{Err: "no MAC", Addr: s}
	}
	return mac, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
