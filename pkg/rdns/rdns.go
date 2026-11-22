// Package rdns asks DNS servers the name of an address: the PTR record of its reverse name, as
// the dnsmasq of a router has for the clients of its DHCP. Only the servers it is given: never
// the system's resolver, which may be a program that asks this very package.
package rdns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/miguelangel-nubla/ipv6disc/internal/backoff"
	"github.com/miguelangel-nubla/ipv6disc/internal/ptr"
	"github.com/miguelangel-nubla/ipv6disc/internal/questions"
	"github.com/miguelangel-nubla/ipv6disc/pkg/stats"
)

// Port is the port of DNS, of a server given without one.
const Port = 53

// Handler is what a Conn tells of what it hears. Its functions are called from the Conn's
// reading, one at a time for each socket: they must not wait.
type Handler struct {
	// Answered is called with the answer to AskName: what the PTR record of the reverse name
	// of asked points to, whole, in a response without an error, with the ID of the question
	// and the question itself, from the server it was sent to.
	Answered func(asked netip.Addr, name string)
	// Error is called with the errors of the sockets.
	Error func(error)
}

// Conn asks the servers it was made with, each from a socket of its family on a port of its own.
type Conn struct {
	stats.Counters

	handler Handler
	servers []asked
	closers []net.PacketConn
}

// asked is a server asked, the socket it is asked from, and the questions sent to it that wait.
type asked struct {
	addr  netip.AddrPort
	conn  net.PacketConn
	asked *questions.Table
}

// Dial opens the sockets the servers are asked from. Nothing is sent before a host is asked of.
func Dial(servers []netip.AddrPort, handler Handler) (*Conn, error) {
	conn := &Conn{handler: handler}
	sockets := make(map[string]net.PacketConn)
	for _, addr := range servers {
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		if !addr.IsValid() || addr.Port() == 0 {
			conn.Close()
			return nil, fmt.Errorf("invalid DNS server %s", addr)
		}
		if slices.ContainsFunc(conn.servers, func(s asked) bool { return s.addr == addr }) {
			continue
		}
		network, local := "udp6", "[::]:0"
		if addr.Addr().Is4() {
			network, local = "udp4", "0.0.0.0:0"
		}
		if sockets[network] == nil {
			c, err := net.ListenPacket(network, local)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to listen for the answers of DNS on %s: %w", network, err)
			}
			sockets[network] = c
			conn.closers = append(conn.closers, c)
		}
		conn.servers = append(conn.servers, asked{addr: addr, conn: sockets[network], asked: &questions.Table{}})
	}
	// Once the servers are all there: a packet that comes at once is looked up among them.
	for _, c := range conn.closers {
		go conn.read(c)
	}
	return conn, nil
}

func (conn *Conn) read(c net.PacketConn) {
	buf := make([]byte, 4096)
	var retry backoff.Delay
	for {
		n, remote, err := c.ReadFrom(buf)
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
		if udpAddr, ok := remote.(*net.UDPAddr); ok {
			conn.take(udpAddr.AddrPort(), buf[:n])
		}
	}
}

// take is what is done of a packet: only the answer of a server to a question sent to it that
// waits is taken, with its ID and the question itself. Anyone can send to the sockets, with
// whatever source, so what answers nothing is left without a word.
func (conn *Conn) take(from netip.AddrPort, packet []byte) {
	from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
	i := slices.IndexFunc(conn.servers, func(s asked) bool {
		return s.addr.Port() == from.Port() && s.addr.Addr().WithZone("") == from.Addr().WithZone("")
	})
	if i < 0 {
		return
	}
	answer, err := ptr.Parse(packet)
	if err != nil || !answer.Response {
		return
	}
	asked, waited := conn.servers[i].asked.Answered(answer.ID, answer.Asks)
	if !waited {
		return
	}
	conn.PacketsReceived.Add(1)
	if name, ok := answer.Name(asked); ok && conn.handler.Answered != nil {
		conn.HostsFound.Add(1)
		conn.handler.Answered(asked, name)
	}
}

// Asks tells whether AskName can ask of addr: any address a server can have a name for, which
// a link-local one is not, the same on every link.
func (conn *Conn) Asks(addr netip.Addr) bool {
	addr = addr.Unmap()
	return len(conn.servers) > 0 && addr.IsValid() && !addr.IsLinkLocalUnicast() && !addr.IsLoopback() && !addr.IsMulticast() && !addr.IsUnspecified()
}

// AskName asks each server the name of addr, with recursion desired, as a resolver does: a
// server that doesn't have it may ask others. The first answer with a name, if one comes, is
// told to Handler.Answered, and so are those of the other servers.
func (conn *Conn) AskName(addr netip.Addr) error {
	addr = addr.Unmap().WithZone("")
	if !conn.Asks(addr) {
		return fmt.Errorf("%s is not asked of the DNS servers: %w", addr, errors.ErrUnsupported)
	}
	var errs []error
	for _, s := range conn.servers {
		msg, err := ptr.Query(s.asked.Ask(addr), addr, true)
		if err != nil {
			return err
		}
		conn.PacketsSent.Add(1)
		if _, err := s.conn.WriteTo(msg, net.UDPAddrFromAddrPort(s.addr)); err != nil {
			errs = append(errs, fmt.Errorf("failed to write message to %s: %w", s.addr, err))
		}
	}
	return errors.Join(errs...)
}

// Stats are the counters, where hosts are the answers that told a name.
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

// ParseServer reads a DNS server as it is written: an address, alone or with a port, the one
// of an IPv6 address in brackets. Without a port, it is at Port.
func ParseServer(s string) (netip.AddrPort, error) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return netip.AddrPortFrom(addr, Port), nil
	}
	server, err := netip.ParseAddrPort(s)
	if err != nil || server.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("invalid DNS server %q: an address, as 192.168.1.1, or one with its port, as 192.168.1.1:5353 or [fd00::1]:53", s)
	}
	return server, nil
}
