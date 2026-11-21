package arp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/miguelangel-nubla/ipv6disc/internal/packet"
	"github.com/miguelangel-nubla/ipv6disc/pkg/stats"
)

// etherARP is the EtherType of ARP.
const etherARP = 0x0806

// Listener hears the ARP of an interface.
type Listener struct {
	stats.Counters
	conn *packet.Conn
}

// Listen hears every ARP packet that comes in on iface, the requests the hosts broadcast and
// the replies to this machine: heard is called with the address and the MAC of the sender of
// each, from the Listener's reading, and returns whether it is a host found, for the stats. It
// only listens: nothing is sent. It needs Linux and CAP_NET_RAW: elsewhere the error is
// errors.ErrUnsupported.
//
// A host is told at once by what it sends, as it asks for its router or announces its address,
// where the kernel's table has only those this machine talked to.
func Listen(iface *net.Interface, heard func(netip.Addr, net.HardwareAddr) bool, onError func(error)) (*Listener, error) {
	c, err := packet.Listen(iface, etherARP, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for ARP on %s: %w", iface.Name, err)
	}
	l := &Listener{conn: c}
	go c.Run(func(payload []byte, from net.HardwareAddr) {
		l.PacketsReceived.Add(1)
		if mac, ip, ok := parseSender(payload, from); ok && heard(ip, mac) {
			l.HostsFound.Add(1)
		}
	}, func(err error) {
		if onError != nil {
			onError(fmt.Errorf("read error: %w", err))
		}
	})
	return l, nil
}

// parseSender returns the sender of an ARP packet, a request or a reply, that came in a frame
// from source: the host that has the address it says it has, at its MAC.
//
// Only when the sender's MAC in the packet is the one the frame came from. The kernel's table
// takes the packet's alone, but the kernel only takes the answers to what it asked, and this
// hears everything: a frame from one MAC that says an address is at another is a proxy's, a
// bridge's that rewrites, or a lie, and none of them is that host saying it is there. A
// gratuitous one, which announces its own address to all, is taken as any other. One from the
// unspecified address is a probe, of a host that doesn't have the address yet (RFC 5227), and
// tells nothing; nor does one from a broadcast or multicast address, or a group's MAC.
func parseSender(b []byte, source net.HardwareAddr) (net.HardwareAddr, netip.Addr, bool) {
	if len(b) < packetLen ||
		binary.BigEndian.Uint16(b[0:2]) != hardwareEth ||
		binary.BigEndian.Uint16(b[2:4]) != protocolIPv4 ||
		b[4] != 6 || b[5] != 4 {
		return nil, netip.Addr{}, false
	}
	if op := binary.BigEndian.Uint16(b[6:8]); op != opRequest && op != opReply {
		return nil, netip.Addr{}, false
	}
	mac := net.HardwareAddr(append([]byte(nil), b[8:14]...))
	ip := netip.AddrFrom4([4]byte(b[14:18]))
	if !bytes.Equal(mac, source) || allZero(mac) || !isHost(ip, mac) {
		return nil, netip.Addr{}, false
	}
	return mac, ip, true
}

// Stats are the counters: nothing is sent, nor probed.
func (l *Listener) Stats() map[string]any {
	stats := l.Counters.Stats()
	delete(stats, "sent")
	delete(stats, "runs")
	return stats
}

// Close ends the listening.
func (l *Listener) Close() error {
	return l.conn.Close()
}
