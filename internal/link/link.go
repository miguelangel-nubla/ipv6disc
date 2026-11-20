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
// system that doesn't tell, is taken, so there the listeners of an interface hear the others' too.
func From(cm *ipv6.ControlMessage, iface *net.Interface) bool {
	return cm == nil || cm.IfIndex == 0 || cm.IfIndex == iface.Index
}

// EnableHopLimit has the connection tell the hop limit of each packet it reads, and returns
// whether the system does: where it doesn't, OnLink takes them all.
func EnableHopLimit(p interface {
	SetControlMessage(ipv6.ControlFlags, bool) error
}) bool {
	return p.SetControlMessage(ipv6.FlagHopLimit, true) == nil
}

// OnLink tells whether a packet was never forwarded, by its hop limit of 255, which a router
// lowers (RFC 4861 7.1): the only proof that an NDP message comes from the link. told is what
// EnableHopLimit returned: without it, a control message has a hop limit of zero whatever the
// packet's.
func OnLink(cm *ipv6.ControlMessage, told bool) bool {
	return !told || cm == nil || cm.HopLimit == 255
}
