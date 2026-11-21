// Package netbios asks a host its NetBIOS name: a node status request (RFC 1002), sent to it
// alone, over IPv4, which a Windows machine answers, and Samba's nmbd, with the names it has.
package netbios

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"

	"github.com/miguelangel-nubla/ipv6disc/internal/backoff"
	"github.com/miguelangel-nubla/ipv6disc/internal/onlink"
	"github.com/miguelangel-nubla/ipv6disc/internal/questions"
	"github.com/miguelangel-nubla/ipv6disc/pkg/stats"
)

// Port is the port of the NetBIOS name service: a node answers a node status from it.
const Port = 137

// Handler is what a Conn tells of what it hears. Its functions are called from the Conn's
// reading, one at a time: they must not wait.
type Handler struct {
	// Answered is called with the answer to AskName: the name the host at asked has as a
	// workstation, in a response with the ID of the question, from the address and the port it
	// was sent to.
	Answered func(asked netip.Addr, name string)
	// Error is called with the errors of the socket.
	Error func(error)
}

// Conn asks the hosts of an interface's link. It has one socket, on a port of its own, which
// everything is sent from and the answers come to: nothing is joined, and the port of NetBIOS,
// which Samba or Windows may have on this machine, is left alone.
type Conn struct {
	stats.Counters

	iface   *net.Interface
	link    *onlink.Link
	handler Handler
	conn    *ipv4.PacketConn
	closer  net.PacketConn
	asked   questions.Table
}

// Listen opens the socket the hosts of iface's link are asked from.
func Listen(iface *net.Interface, handler Handler) (*Conn, error) {
	c, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen for the answers of NetBIOS: %w", err)
	}
	conn := &Conn{iface: iface, link: onlink.Of(iface), handler: handler, conn: ipv4.NewPacketConn(c), closer: c}
	// Only what comes in on the interface. Where the system doesn't tell, all is taken.
	_ = conn.conn.SetControlMessage(ipv4.FlagInterface, true)
	go conn.read()
	return conn, nil
}

func (conn *Conn) read() {
	buf := make([]byte, 2048)
	var retry backoff.Delay
	for {
		n, cm, remote, err := conn.conn.ReadFrom(buf)
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
		if cm != nil && cm.IfIndex != 0 && cm.IfIndex != conn.iface.Index {
			continue
		}
		if udpAddr, ok := remote.(*net.UDPAddr); ok {
			conn.take(udpAddr.AddrPort(), buf[:n])
		}
	}
}

// take is what is done of a packet: only the answer to a question that waits is taken, from the
// address it was sent to and the port of NetBIOS. The socket is no group's: anyone can send to
// it, with whatever source, so what answers nothing is left without a word.
func (conn *Conn) take(from netip.AddrPort, packet []byte) {
	status, err := Parse(packet)
	if err != nil || from.Port() != Port {
		return
	}
	sender := from.Addr().Unmap().WithZone("")
	asked, waited := conn.asked.Answered(status.ID, func(asked netip.Addr) bool { return asked == sender })
	if !waited {
		return
	}
	conn.PacketsReceived.Add(1)
	if status.Name != "" && conn.handler.Answered != nil {
		conn.HostsFound.Add(1)
		conn.handler.Answered(asked, status.Name)
	}
}

// Asks tells whether AskName can ask the host at addr: an IPv4 address of the interface's link.
func (conn *Conn) Asks(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.Is4() && conn.link.Has(addr)
}

// AskName asks the host at addr its name, by a node status request sent to it alone. Its answer,
// if it comes, is told to Handler.Answered.
func (conn *Conn) AskName(addr netip.Addr) error {
	addr = addr.Unmap().WithZone("")
	if !conn.Asks(addr) {
		return fmt.Errorf("%s is not asked on %s: %w", addr, conn.iface.Name, errors.ErrUnsupported)
	}
	conn.PacketsSent.Add(1)
	// Out of the interface, whatever the routes say of the address.
	cm := &ipv4.ControlMessage{IfIndex: conn.iface.Index}
	if _, err := conn.conn.WriteTo(query(conn.asked.Ask(addr)), cm, &net.UDPAddr{IP: addr.AsSlice(), Port: Port}); err != nil {
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
	return conn.closer.Close()
}
