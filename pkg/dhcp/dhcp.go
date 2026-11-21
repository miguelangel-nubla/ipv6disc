// Package dhcp hears what the DHCP clients of a link say of themselves as they ask for an
// address: their MAC and the host name they give, over DHCPv4, and their name over DHCPv6. It
// only listens, by packet sockets of Linux, which need no port: the DHCP server or client of this
// machine keeps its own, and nothing is ever sent.
package dhcp

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/net/bpf"

	"github.com/miguelangel-nubla/ipv6disc/internal/packet"
	"github.com/miguelangel-nubla/ipv6disc/pkg/stats"
)

// Handler is what a Conn tells of what it hears. Its functions are called from the Conn's
// reading, one at a time for each family: they must not wait.
type Handler struct {
	// Client4 is called with each message of a DHCPv4 client. It returns whether it tells a
	// host's name, for the stats.
	Client4 func(Message4) bool
	// Client6 is called with each message of a DHCPv6 client that gives a name, the link-local
	// address it sent it from, and the MAC its frame came from: the name is that address's host's
	// only if that is its MAC, which is the caller's to tell. It returns the same.
	Client6 func(from netip.Addr, hw net.HardwareAddr, m Message6) bool
	// Error is called with the errors of the sockets.
	Error func(error)
}

// Conn is the listening on an interface: a packet socket for each family, which takes the UDP
// packets to the port of the DHCP servers alone, whoever they are for.
type Conn struct {
	stats.Counters
	conns []*packet.Conn
}

// The EtherTypes of the two families.
const (
	etherIPv4 = 0x0800
	etherIPv6 = 0x86dd
)

// filter4 takes the IPv4 packets that are UDP, the first fragment or whole, to the port of the
// DHCP servers; filter6 the IPv6 ones that are UDP, with no header between, to the DHCPv6 one.
var (
	filter4 = []bpf.Instruction{
		bpf.LoadAbsolute{Off: 9, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 17, SkipTrue: 6},
		bpf.LoadAbsolute{Off: 6, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 4},
		bpf.LoadMemShift{Off: 0},
		bpf.LoadIndirect{Off: 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: serverPort, SkipTrue: 1},
		bpf.RetConstant{Val: 0xffff},
		bpf.RetConstant{Val: 0},
	}
	filter6 = []bpf.Instruction{
		bpf.LoadAbsolute{Off: 6, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 17, SkipTrue: 3},
		bpf.LoadAbsolute{Off: 42, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: serverPort6, SkipTrue: 1},
		bpf.RetConstant{Val: 0xffff},
		bpf.RetConstant{Val: 0},
	}
)

// Listen hears the DHCP clients of iface's link, over both families. It needs Linux and
// CAP_NET_RAW: elsewhere the error is errors.ErrUnsupported.
func Listen(iface *net.Interface, handler Handler) (*Conn, error) {
	conn := &Conn{}
	for protocol, filter := range map[uint16][]bpf.Instruction{etherIPv4: filter4, etherIPv6: filter6} {
		c, err := packet.Listen(iface, protocol, filter)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to listen for DHCP on %s: %w", iface.Name, err)
		}
		conn.conns = append(conn.conns, c)
		take := conn.take4
		if protocol == etherIPv6 {
			take = conn.take6
		}
		onError := func(err error) {
			if handler.Error != nil {
				handler.Error(fmt.Errorf("read error: %w", err))
			}
		}
		go c.Run(func(payload []byte, from net.HardwareAddr) { take(payload, from, handler) }, onError)
	}
	return conn, nil
}

// take4 is what is done of an IPv4 packet that came in a frame from source: a client's message is
// taken only from the client itself, whose MAC, as the message has it, is the one the frame came
// from. The message alone is anyone's word: any host of the link can write another's MAC in one,
// and would name it. What a relay forwards has a relay's address and is left by Parse4, and what
// a bridge that rewrites the MACs passes on is of a client the discovery finds at no MAC of its
// own.
func (conn *Conn) take4(ip []byte, source net.HardwareAddr, handler Handler) {
	payload, ok := udp4(ip)
	if !ok {
		return
	}
	m, ok := Parse4(payload)
	if !ok || !bytes.Equal(m.MAC, source) {
		return
	}
	conn.PacketsReceived.Add(1)
	if handler.Client4 != nil && handler.Client4(m) {
		conn.HostsFound.Add(1)
	}
}

// take6 is what is done of an IPv6 packet that came in a frame from source.
func (conn *Conn) take6(ip []byte, source net.HardwareAddr, handler Handler) {
	from, payload, ok := udp6(ip)
	// A client sends from its link-local address (RFC 8415 13): another's is not of the link.
	if !ok || !from.IsLinkLocalUnicast() {
		return
	}
	m, ok := Parse6(payload)
	if !ok {
		return
	}
	conn.PacketsReceived.Add(1)
	if m.Name != "" && len(source) == 6 && handler.Client6 != nil && handler.Client6(from, source, m) {
		conn.HostsFound.Add(1)
	}
}

// Stats are the counters, where hosts are the messages that told a host's name.
func (conn *Conn) Stats() map[string]any {
	stats := conn.Counters.Stats()
	// Nothing is sent, nor probed.
	delete(stats, "sent")
	delete(stats, "runs")
	return stats
}

// Close ends the listening.
func (conn *Conn) Close() error {
	var errs []error
	for _, c := range conn.conns {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}
