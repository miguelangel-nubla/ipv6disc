// Package onlink tells whether an address is of the link of an interface: what the protocols that
// ask a host of the link, or take its word, need to know of whom they talk to.
package onlink

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// age is how long the addresses of the interface are kept before they are read again.
const age = 10 * time.Second

// Link is the link of an interface, by the addresses the interface has.
type Link struct {
	iface *net.Interface
	// What reads the prefixes of the interface: its addresses, unless a test says.
	read func() []netip.Prefix

	mutex    sync.Mutex
	prefixes []netip.Prefix
	at       time.Time
}

func Of(iface *net.Interface) *Link {
	return &Link{iface: iface, read: func() []netip.Prefix { return Prefixes(iface) }}
}

// Among is the link of those prefixes, which never change: for the tests.
func Among(prefixes ...netip.Prefix) *Link {
	return &Link{read: func() []netip.Prefix { return prefixes }}
}

// Where tells whether addr is of the link, a link-local address or one of a subnet the interface
// has an address in, and whether it is the interface's own.
func (l *Link) Where(addr netip.Addr) (onLink, own bool) {
	addr = addr.Unmap().WithZone("")
	l.mutex.Lock()
	if l.at.IsZero() || time.Since(l.at) > age {
		l.prefixes = l.read()
		l.at = time.Now()
	}
	prefixes := l.prefixes
	l.mutex.Unlock()

	if !addr.IsValid() || addr.IsMulticast() || addr.IsUnspecified() || addr.IsLoopback() {
		return false, false
	}
	onLink = addr.IsLinkLocalUnicast()
	for _, p := range prefixes {
		if p.Addr() == addr {
			own = true
		}
		if p.Contains(addr) {
			onLink = true
		}
	}
	return onLink, own
}

// Has tells whether addr is a host's of the link: of it, and not the interface's own.
func (l *Link) Has(addr netip.Addr) bool {
	onLink, own := l.Where(addr)
	return onLink && !own
}

// Prefixes are the addresses of an interface, each with the length of its subnet.
func Prefixes(iface *net.Interface) []netip.Prefix {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	var prefixes []netip.Prefix
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipNet.IP)
		ones, _ := ipNet.Mask.Size()
		if ip = ip.Unmap(); ok && ones <= ip.BitLen() {
			prefixes = append(prefixes, netip.PrefixFrom(ip, ones))
		}
	}
	return prefixes
}
