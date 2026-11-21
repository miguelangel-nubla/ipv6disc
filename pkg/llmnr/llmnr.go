// Package llmnr asks a host its name by LLMNR (RFC 4795), which Windows answers, and
// systemd-resolved: the PTR record of the reverse name of its address, over IPv4 and IPv6.
package llmnr

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/miguelangel-nubla/ipv6disc/internal/backoff"
	"github.com/miguelangel-nubla/ipv6disc/internal/onlink"
	"github.com/miguelangel-nubla/ipv6disc/internal/ptr"
	"github.com/miguelangel-nubla/ipv6disc/internal/questions"
	"github.com/miguelangel-nubla/ipv6disc/pkg/stats"
)

// Port is the port of LLMNR: the responders listen on it, in the groups, and answer from it.
const Port = 5355

// The groups of LLMNR, of each family.
var (
	group4 = netip.MustParseAddr("224.0.0.252")
	group6 = netip.MustParseAddr("ff02::1:3")
)

// Options are the families a Conn asks over.
type Options struct {
	IPv4, IPv6 bool
}

// Handler is what a Conn tells of what it hears. Its functions are called from the Conn's
// reading, one at a time for each socket: they must not wait.
type Handler struct {
	// Answered is called with the answer to AskName: the name of the host at asked, by the PTR
	// record of its reverse name, in a response with the ID of the question, and the question
	// itself, that came from the port of LLMNR at from, an address of the link. A responder
	// answers from the address its system chooses, which over IPv6 is its link-local one
	// whatever the address asked of: whether from is the host asked is the caller's to prove.
	Answered func(asked, from netip.Addr, name string)
	// Error is called with the errors of the sockets.
	Error func(error)
}

// Conn asks the hosts of an interface's link. It has one socket for each family, on a port of
// its own, which the questions are sent from and the answers come to, by unicast: no group is
// joined, and nothing of the port of LLMNR, which systemd-resolved may have on this machine, is
// touched.
//
// A question goes to the group, though it is for one host: a responder leaves out the UDP
// questions sent to it alone (RFC 4795 2.4 has those go over TCP, which Windows doesn't listen
// on). So every host of the link hears it, and the one that has the address answers.
type Conn struct {
	stats.Counters

	iface   *net.Interface
	link    *onlink.Link
	handler Handler
	conn4   *ipv4.PacketConn
	conn6   *ipv6.PacketConn
	closers []net.PacketConn
	asked   questions.Table
}

// Listen opens the sockets the hosts of iface's link are asked from, of the families of options.
// A family that can't be is an error, with nothing left open.
func Listen(iface *net.Interface, options Options, handler Handler) (*Conn, error) {
	conn := &Conn{iface: iface, link: onlink.Of(iface), handler: handler}
	open := func(network, address string) (net.PacketConn, error) {
		c, err := net.ListenPacket(network, address)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to listen for the answers of LLMNR on %s: %w", network, err)
		}
		conn.closers = append(conn.closers, c)
		return c, nil
	}
	if options.IPv4 {
		c, err := open("udp4", "0.0.0.0:0")
		if err != nil {
			return nil, err
		}
		conn.conn4 = ipv4.NewPacketConn(c)
		// Only what comes in on the interface. Where the system doesn't tell, all is taken.
		_ = conn.conn4.SetControlMessage(ipv4.FlagInterface, true)
		// A question never leaves the link.
		_ = conn.conn4.SetMulticastTTL(1)
		_ = conn.conn4.SetMulticastInterface(iface)
		_ = conn.conn4.SetMulticastLoopback(false)
	}
	if options.IPv6 {
		c, err := open("udp6", "[::]:0")
		if err != nil {
			return nil, err
		}
		conn.conn6 = ipv6.NewPacketConn(c)
		_ = conn.conn6.SetControlMessage(ipv6.FlagInterface, true)
		_ = conn.conn6.SetMulticastHopLimit(1)
		_ = conn.conn6.SetMulticastInterface(iface)
		_ = conn.conn6.SetMulticastLoopback(false)
	}
	if conn.conn4 != nil {
		go conn.read(func(b []byte) (int, int, net.Addr, error) {
			n, cm, from, err := conn.conn4.ReadFrom(b)
			if cm == nil {
				return n, 0, from, err
			}
			return n, cm.IfIndex, from, err
		})
	}
	if conn.conn6 != nil {
		go conn.read(func(b []byte) (int, int, net.Addr, error) {
			n, cm, from, err := conn.conn6.ReadFrom(b)
			if cm == nil {
				return n, 0, from, err
			}
			return n, cm.IfIndex, from, err
		})
	}
	return conn, nil
}

func (conn *Conn) read(readFrom func([]byte) (int, int, net.Addr, error)) {
	buf := make([]byte, 2048)
	var retry backoff.Delay
	for {
		n, index, remote, err := readFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if conn.handler.Error != nil {
				conn.handler.Error(fmt.Errorf("read error: %w", err))
			}
			retry.Wait()
			continue
		}
		retry.Reset()
		if index != 0 && index != conn.iface.Index {
			continue
		}
		if udpAddr, ok := remote.(*net.UDPAddr); ok {
			conn.take(udpAddr.AddrPort(), buf[:n])
		}
	}
}

// take is what is done of a packet: only the answer to a question that waits is taken, with its
// ID and the question itself, from the port of LLMNR at an address of the link that isn't the
// interface's own. The sockets are no group's: anyone can send to them, with whatever source, so
// what answers nothing is left without a word.
func (conn *Conn) take(from netip.AddrPort, packet []byte) {
	sender := from.Addr().Unmap().WithZone("")
	if from.Port() != Port || !conn.link.Has(sender) {
		return
	}
	answer, err := ptr.Parse(packet)
	if err != nil || !answer.Response {
		return
	}
	var name string
	asked, waited := conn.asked.Answered(answer.ID, func(asked netip.Addr) bool {
		// Over the family it was asked over, and to the question asked. One that has no
		// name, or an error, answers it too: the host has nothing to say.
		if asked.Is4() != sender.Is4() || answer.Question == "" {
			return false
		}
		name, _ = answer.Name(asked)
		return answer.Asks(asked)
	})
	if !waited {
		return
	}
	conn.PacketsReceived.Add(1)
	if name != "" && conn.handler.Answered != nil {
		conn.HostsFound.Add(1)
		conn.handler.Answered(asked, sender, name)
	}
}

// Asks tells whether AskName can ask the host at addr: over a family it asks over, at an address
// of the interface's link, which is where the group reaches.
func (conn *Conn) Asks(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.Is4() && conn.conn4 == nil || addr.Is6() && conn.conn6 == nil {
		return false
	}
	return conn.link.Has(addr)
}

// AskName asks the host at addr its name: the PTR record of the address's reverse name, by a
// question sent to the group of its family, out of the interface. Its answer, if it comes, is
// told to Handler.Answered.
func (conn *Conn) AskName(addr netip.Addr) error {
	addr = addr.Unmap().WithZone("")
	if !conn.Asks(addr) {
		return fmt.Errorf("%s is not asked on %s: %w", addr, conn.iface.Name, errors.ErrUnsupported)
	}
	msg, err := ptr.Query(conn.asked.Ask(addr), addr, false)
	if err != nil {
		return err
	}
	conn.PacketsSent.Add(1)
	if addr.Is4() {
		_, err = conn.conn4.WriteTo(msg, nil, &net.UDPAddr{IP: group4.AsSlice(), Port: Port})
	} else {
		_, err = conn.conn6.WriteTo(msg, nil, &net.UDPAddr{IP: group6.AsSlice(), Port: Port, Zone: conn.iface.Name})
	}
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	return nil
}

// Stats are the counters, where hosts are those that told a name.
func (conn *Conn) Stats() map[string]any {
	return conn.Counters.Stats()
}

// Close ends the listening.
func (conn *Conn) Close() error {
	var errs []error
	for _, c := range conn.closers {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}
