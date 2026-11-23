//go:build darwin

package ipv6disc

import (
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The flags of an IPv6 address the worker looks at, of those SIOCGIFAFLAG_IN6 tells
// (netinet6/in6_var.h), and the request itself: _IOWR('i', 73, struct in6_ifreq).
const (
	in6IffDeprecated = 0x10
	in6IffTemporary  = 0x80
	siocgifaflagIn6  = 0xc1206949
)

// in6Ifreq is struct in6_ifreq: the interface's name, and a union as large as its largest
// member, the interface's counters, of 272 bytes. The address asked about goes in at its start,
// and its flags come out there, an int.
type in6Ifreq struct {
	name [unix.IFNAMSIZ]byte
	addr unix.RawSockaddrInet6
	_    [272 - unix.SizeofSockaddrInet6]byte
}

// addrFlags returns the flags the kernel has for each of this machine's IPv6 addresses that is
// not link-local, asked one by one: nothing lists them. The keys have no zone, as the addresses
// checkInterfaces looks up in it. Nil when they can't be asked.
func addrFlags() map[netip.Addr]int32 {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil
	}
	defer unix.Close(fd)

	flags := make(map[netip.Addr]int32)
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok || addr.Is4() || addr.Is4In6() || addr.IsLinkLocalUnicast() {
				continue
			}
			var request in6Ifreq
			copy(request.name[:len(request.name)-1], iface.Name)
			request.addr = unix.RawSockaddrInet6{Len: unix.SizeofSockaddrInet6, Family: unix.AF_INET6, Addr: addr.As16()}
			// The system's ioctl, which macOS wants called and not the system call itself: the
			// package has it for the requests it knows, each with its type. This one takes the
			// request as it is, by the one of them that passes its pointer on, of a type that is
			// no larger.
			if err := unix.IoctlSetTermios(fd, siocgifaflagIn6, (*unix.Termios)(unsafe.Pointer(&request))); err != nil {
				continue
			}
			flags[addr] = *(*int32)(unsafe.Pointer(&request.addr))
		}
	}
	return flags
}

// temporaryAddrs returns this machine's IPv6 addresses the kernel says are temporary: privacy
// addresses (RFC 8981).
func temporaryAddrs() map[netip.Addr]bool { return addrsWith(in6IffTemporary) }

// unlistenableAddrs returns this machine's IPv6 addresses that can't be listened on though it
// has them: the deprecated ones, as the temporary addresses it replaced and keeps until they
// end. macOS doesn't let them be bound, and they are the source of nothing new it sends.
func unlistenableAddrs() map[netip.Addr]bool { return addrsWith(in6IffDeprecated) }

func addrsWith(flag int32) map[netip.Addr]bool {
	with := make(map[netip.Addr]bool)
	for addr, flags := range addrFlags() {
		if flags&flag != 0 {
			with[addr] = true
		}
	}
	return with
}
