//go:build linux

package arp

import (
	"fmt"
	"net"
	"syscall"
)

// Table returns the IPv4 neighbors of the kernel's table, from netlink: no command needed.
func Table() ([]Neighbor, error) {
	dump, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("reading the neighbor table: %w", err)
	}
	names := make(map[int]string)
	return parseNetlinkNeighbors(dump, func(index int) string {
		if name, ok := names[index]; ok {
			return name
		}
		name := ""
		if iface, err := net.InterfaceByIndex(index); err == nil {
			name = iface.Name
		}
		names[index] = name
		return name
	}), nil
}
