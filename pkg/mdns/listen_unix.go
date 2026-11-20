//go:build unix

package mdns

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenGroup opens the socket that hears a group: bound to the group itself, on the interface,
// so that it takes what is sent to the group there and nothing else. A packet sent to this
// machine's port of mDNS alone is then never its own: it stays the responder's of this machine,
// which the system would otherwise give it to or not, by the order the two were started in.
//
// By the system's calls, as net binds a socket asked for a group's address to every address
// instead. The port is shared: SO_REUSEADDR, which is enough of UDP sockets on Linux when both
// have it, and SO_REUSEPORT, which macOS and the BSDs need. The responders set both.
func listenGroup(group netip.Addr, iface *net.Interface) (net.PacketConn, error) {
	family := unix.AF_INET6
	var address unix.Sockaddr = &unix.SockaddrInet6{Port: Port, Addr: group.As16(), ZoneId: uint32(iface.Index)}
	if group.Is4() {
		family = unix.AF_INET
		address = &unix.SockaddrInet4{Port: Port, Addr: group.As4()}
	}

	// As net does where a socket can't be made close-on-exec at once.
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	file := os.NewFile(uintptr(fd), "mdns")
	// The connection has its own copy of the descriptor.
	defer file.Close()

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return nil, fmt.Errorf("SO_REUSEADDR: %w", err)
	}
	if err := reusePort(fd); err != nil {
		return nil, fmt.Errorf("SO_REUSEPORT: %w", err)
	}
	if family == unix.AF_INET6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
			return nil, fmt.Errorf("IPV6_V6ONLY: %w", err)
		}
	}
	if err := unix.Bind(fd, address); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	return net.FilePacketConn(file)
}
