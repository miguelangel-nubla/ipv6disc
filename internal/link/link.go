// Package link tells which interface a packet came in on, for the listeners of an interface: a
// socket bound to a global or ULA address isn't bound to its interface, and on Linux it hears the
// multicast of every interface any socket joined the group on, and the unicast to its address
// routed in through another.
package link

import (
	"net"

	"golang.org/x/net/ipv6"
)

// Enable has the connection tell the interface of each packet it reads, where the system can:
// elsewhere, as on Windows, packets come without, and From takes them all.
func Enable(p interface {
	SetControlMessage(ipv6.ControlFlags, bool) error
}) {
	_ = p.SetControlMessage(ipv6.FlagInterface, true)
}

// From tells whether a packet came in on iface, by its control message: one without, from a
// system that doesn't tell, is taken.
func From(cm *ipv6.ControlMessage, iface *net.Interface) bool {
	return cm == nil || cm.IfIndex == 0 || cm.IfIndex == iface.Index
}
