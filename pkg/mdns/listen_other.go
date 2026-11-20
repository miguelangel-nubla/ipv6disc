//go:build !unix

package mdns

import (
	"context"
	"net"
	"net/netip"
	"syscall"
)

// listenGroup opens the socket that hears a group: bound to every address, where a socket can't
// be bound to a group, as on Windows, and sharing the port by SO_REUSEADDR, which there is all
// it takes. It then takes its share of the packets sent to this machine's port of mDNS alone
// too, which a responder of this machine would have had.
func listenGroup(group netip.Addr, _ *net.Interface) (net.PacketConn, error) {
	network, address := "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), Port)
	if group.Is6() {
		network, address = "udp6", netip.AddrPortFrom(netip.IPv6Unspecified(), Port)
	}
	config := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error { return reuse(c) }}
	return config.ListenPacket(context.Background(), network, address.String())
}
