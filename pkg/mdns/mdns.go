// Package mdns hears multicast DNS (RFC 6762) on an interface, over IPv4 and IPv6: who sends it,
// and the names the responses tell; and asks: every host for its services, so that those that have
// any answer and are heard, and one host for the name of its address.
package mdns

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/miguelangel-nubla/ipv6disc/internal/backoff"
	"github.com/miguelangel-nubla/ipv6disc/pkg/stats"
)

// Port is the port of mDNS: the responders listen on it, and answer from it.
const Port = 5353

// The groups of mDNS, of each family.
var (
	group4 = netip.MustParseAddr("224.0.0.251")
	group6 = netip.MustParseAddr("ff02::fb")
)

// Options are the families a Conn listens over, and those it sends the query for the services
// over, of the first.
type Options struct {
	IPv4, IPv6             bool
	ActiveIPv4, ActiveIPv6 bool
}

// Handler is what a Conn tells of what it hears. Its functions are called from the Conn's
// reading, one at a time for each socket: they must not wait.
type Handler struct {
	// Heard is called with the sender of each message taken, query or response: a host of the
	// link. It returns whether it is a host found, for the stats.
	Heard func(from netip.Addr) bool
	// Said is called with each record of a response: from says that name has addr, which onLink
	// tells to be of the interface's link, as OnLink does. A response can carry the records of
	// other hosts, as a proxy's does, so this is no more than what from says: whether addr is
	// its own is the caller's to prove.
	Said func(from netip.Addr, name string, addr netip.Addr, onLink bool)
	// Answered is called with the answer to AskName: the name of the host at asked, by the PTR
	// record of its reverse name, in a response with the ID of the question sent to it alone.
	Answered func(asked netip.Addr, name string)
	// Error is called with the errors of the sockets.
	Error func(error)
}

// Conn is the mDNS of an interface. It has two sockets for each family.
//
// One on the port of mDNS, in the group, which only hears what the hosts send to all. The
// responder of this machine, if it has one, has that port too, and the system gives a unicast
// packet to it to one only of the sockets that share it: so this one is bound to the group's
// address, where the system lets it be, and takes nothing sent to this machine alone, which stays
// the responder's. On Windows, which doesn't, it is bound to every address, and can take them.
//
// And one on a port of its own, which nobody shares, that everything is sent from: asked from
// another port than mDNS's, a responder answers to that port alone, by unicast, whether the
// question went to it or to the group (RFC 6762 6.7). So the answers come where only this Conn
// listens, whatever else of this machine has the port of mDNS, and a link of many hosts answers
// the query for the services without a multicast packet from each.
type Conn struct {
	stats.Counters

	iface   *net.Interface
	options Options
	handler Handler

	group4, lookup4 *ipv4.PacketConn
	group6, lookup6 *ipv6.PacketConn
	closers         []net.PacketConn

	mutex sync.Mutex
	// The questions sent and still waited for, by their ID: one to a host, which its answer
	// takes, and the query for the services, which every host answers.
	questions map[uint16]question
	// The addresses of the interface, as last read.
	prefixes   []netip.Prefix
	prefixesAt time.Time
}

// question is one sent: to the host at addr, or, without one, to all.
type question struct {
	addr netip.Addr
	at   time.Time
}

// questionTimeout is how long the answers to a question are waited for: one that comes later
// answers nothing, and is left.
const questionTimeout = 5 * time.Second

// prefixesAge is how long the addresses of the interface are kept before they are read again.
const prefixesAge = 10 * time.Second

// Listen joins the groups of mDNS on iface, of the families of options, on the port of mDNS,
// which it shares with the responder of this machine, if it has one, as avahi or mDNSResponder.
// It takes the messages that come in on iface from an address of its link that isn't its own. A
// family that can't be listened on is an error, with nothing left open.
func Listen(iface *net.Interface, options Options, handler Handler) (*Conn, error) {
	conn := &Conn{iface: iface, options: options, handler: handler, questions: make(map[uint16]question)}
	// A socket in a group, and one on a port of its own.
	hear := func(group netip.Addr) (net.PacketConn, error) {
		c, err := listenGroup(group, iface)
		if err != nil {
			return nil, fmt.Errorf("failed to listen for mDNS on port %d, for %s on %s: %w", Port, group, iface.Name, err)
		}
		conn.closers = append(conn.closers, c)
		return c, nil
	}
	open := func(network, address string) (net.PacketConn, error) {
		c, err := net.ListenPacket(network, address)
		if err != nil {
			return nil, fmt.Errorf("failed to listen for the answers of mDNS on %s: %w", network, err)
		}
		conn.closers = append(conn.closers, c)
		return c, nil
	}
	fail := func(err error) (*Conn, error) {
		conn.Close()
		return nil, err
	}

	if options.IPv4 {
		c, err := hear(group4)
		if err != nil {
			return fail(err)
		}
		conn.group4 = ipv4.NewPacketConn(c)
		if err := conn.group4.JoinGroup(iface, &net.UDPAddr{IP: group4.AsSlice()}); err != nil {
			return fail(fmt.Errorf("failed to join %s on %s: %w", group4, iface.Name, err))
		}
		if c, err = open("udp4", "0.0.0.0:0"); err != nil {
			return fail(err)
		}
		conn.lookup4 = ipv4.NewPacketConn(c)
		for _, p := range []*ipv4.PacketConn{conn.group4, conn.lookup4} {
			// Only what comes in on the interface: the socket hears the group on every
			// interface any socket joined it on. Where the system doesn't tell, all is taken.
			_ = p.SetControlMessage(ipv4.FlagInterface, true)
			// What mDNS is sent with (RFC 6762 11).
			_ = p.SetTTL(255)
			_ = p.SetMulticastTTL(255)
			_ = p.SetMulticastInterface(iface)
		}
	}
	if options.IPv6 {
		c, err := hear(group6)
		if err != nil {
			return fail(err)
		}
		conn.group6 = ipv6.NewPacketConn(c)
		if err := conn.group6.JoinGroup(iface, &net.UDPAddr{IP: group6.AsSlice()}); err != nil {
			return fail(fmt.Errorf("failed to join %s on %s: %w", group6, iface.Name, err))
		}
		if c, err = open("udp6", "[::]:0"); err != nil {
			return fail(err)
		}
		conn.lookup6 = ipv6.NewPacketConn(c)
		for _, p := range []*ipv6.PacketConn{conn.group6, conn.lookup6} {
			_ = p.SetControlMessage(ipv6.FlagInterface, true)
			_ = p.SetHopLimit(255)
			_ = p.SetMulticastHopLimit(255)
			_ = p.SetMulticastInterface(iface)
		}
	}

	if options.IPv4 {
		go conn.read(readFrom4(conn.group4), false)
		go conn.read(readFrom4(conn.lookup4), true)
	}
	if options.IPv6 {
		go conn.read(readFrom6(conn.group6), false)
		go conn.read(readFrom6(conn.lookup6), true)
	}
	return conn, nil
}

// reader reads a packet of a socket: its length, the index of the interface it came in on, zero
// when the system doesn't tell, and its sender.
type reader func([]byte) (int, int, net.Addr, error)

func readFrom4(p *ipv4.PacketConn) reader {
	return func(b []byte) (int, int, net.Addr, error) {
		n, cm, from, err := p.ReadFrom(b)
		if cm == nil {
			return n, 0, from, err
		}
		return n, cm.IfIndex, from, err
	}
}

func readFrom6(p *ipv6.PacketConn) reader {
	return func(b []byte) (int, int, net.Addr, error) {
		n, cm, from, err := p.ReadFrom(b)
		if cm == nil {
			return n, 0, from, err
		}
		return n, cm.IfIndex, from, err
	}
}

// read takes the packets of a socket until it is closed, which ends it without a call of Error:
// any other error of a read is reported, and the next read tried, after a wait that grows while
// they fail. lookup is of the socket the questions to one host are sent from.
func (conn *Conn) read(readFrom reader, lookup bool) {
	// The longest message of mDNS (RFC 6762 17).
	buf := make([]byte, 9000)
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
			conn.take(udpAddr.AddrPort().Addr(), buf[:n], lookup)
		}
	}
}

// take is what is done of a packet that came in on the interface, from from. Only one from the
// link is taken (RFC 6762 11): a link-local address, or one of a subnet of the interface, and
// not the interface's own, as those of this machine's responder are. One that is no DNS message
// is left, without a word: anyone can send anything to the group.
//
// And on the socket of the Conn's own port, which is no group's and takes what is sent to this
// machine from anywhere, only a response with the ID of a question that waits: a responder
// repeats it in what it answers there (RFC 6762 6.7). The source of a packet proves nothing of
// where it came from, and what is sent to the group doesn't cross a router, but this would.
func (conn *Conn) take(from netip.Addr, packet []byte, lookup bool) {
	from = from.Unmap().WithZone("")
	onLink, own := conn.where(from)
	if !onLink || own {
		return
	}
	message, err := Parse(packet)
	if err != nil {
		return
	}
	var asked netip.Addr
	if lookup {
		var waited bool
		if asked, waited = conn.answered(message.ID); !waited || !message.Response {
			return
		}
	}
	conn.PacketsReceived.Add(1)
	if conn.handler.Heard != nil && conn.handler.Heard(from) {
		conn.HostsFound.Add(1)
	}
	if !message.Response {
		return
	}
	for _, r := range message.Records {
		if r.PTR && asked.IsValid() && r.Addr == asked {
			if conn.handler.Answered != nil {
				conn.handler.Answered(asked, r.Name)
			}
			continue
		}
		if conn.handler.Said != nil {
			conn.handler.Said(from, r.Name, r.Addr, conn.OnLink(r.Addr))
		}
	}
}

// OnLink tells whether addr is of the link of the interface, and not the interface's own: a
// link-local address, or one of a subnet the interface has an address in.
func (conn *Conn) OnLink(addr netip.Addr) bool {
	onLink, own := conn.where(addr.Unmap().WithZone(""))
	return onLink && !own
}

// where tells whether addr is of the link of the interface, and whether it is the interface's
// own, by the addresses the interface has, read again when they are old.
func (conn *Conn) where(addr netip.Addr) (onLink, own bool) {
	conn.mutex.Lock()
	if conn.prefixesAt.IsZero() || time.Since(conn.prefixesAt) > prefixesAge {
		conn.prefixes = interfacePrefixes(conn.iface)
		conn.prefixesAt = time.Now()
	}
	prefixes := conn.prefixes
	conn.mutex.Unlock()
	return whereAmong(prefixes, addr)
}

func whereAmong(prefixes []netip.Prefix, addr netip.Addr) (onLink, own bool) {
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

func interfacePrefixes(iface *net.Interface) []netip.Prefix {
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

// DiscoverMulticast asks every host of the link for the kinds of service it has, over the
// families it probes: those that have any answer, and are heard. The question goes to the group
// from the Conn's own port, so each answers to that port, by unicast: not to the group, nor to the
// port of mDNS, where the bit of a question that asks for a unicast response (RFC 6762 5.4) would
// have the answers sent, to whichever socket of this machine the system gives them.
func (conn *Conn) DiscoverMulticast() error {
	conn.DiscoveryRuns.Add(1)
	msg, err := query(conn.ask(netip.Addr{}), servicesName)
	if err != nil {
		return err
	}
	var errs []error
	if conn.lookup4 != nil && conn.options.ActiveIPv4 {
		conn.PacketsSent.Add(1)
		if _, err := conn.lookup4.WriteTo(msg, nil, &net.UDPAddr{IP: group4.AsSlice(), Port: Port}); err != nil {
			errs = append(errs, fmt.Errorf("failed to write message: %w", err))
		}
	}
	if conn.lookup6 != nil && conn.options.ActiveIPv6 {
		conn.PacketsSent.Add(1)
		if _, err := conn.lookup6.WriteTo(msg, nil, &net.UDPAddr{IP: group6.AsSlice(), Port: Port, Zone: conn.iface.Name}); err != nil {
			errs = append(errs, fmt.Errorf("failed to write message: %w", err))
		}
	}
	return errors.Join(errs...)
}

// Asks tells whether AskName can ask the host at addr: over a family it listens on, at an
// address of the interface's link, which is where a responder takes a question from.
func (conn *Conn) Asks(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.Is4() && conn.lookup4 == nil || addr.Is6() && conn.lookup6 == nil {
		return false
	}
	return conn.OnLink(addr)
}

// AskName asks the host at addr its name: the PTR record of the address's reverse name, by a
// question sent to its port of mDNS alone, out of the interface. Its answer, if it comes, is
// told to Handler.Answered. Nothing is sent to the group, and no host but that one hears it.
func (conn *Conn) AskName(addr netip.Addr) error {
	addr = addr.Unmap().WithZone("")
	if !conn.Asks(addr) {
		return fmt.Errorf("%s is not asked on %s: %w", addr, conn.iface.Name, errors.ErrUnsupported)
	}
	msg, err := query(conn.ask(addr), ReverseName(addr))
	if err != nil {
		return err
	}
	conn.PacketsSent.Add(1)
	destination := &net.UDPAddr{IP: addr.AsSlice(), Port: Port}
	if addr.Is4() {
		_, err = conn.lookup4.WriteTo(msg, nil, destination)
	} else {
		if addr.IsLinkLocalUnicast() {
			destination.Zone = conn.iface.Name
		}
		_, err = conn.lookup6.WriteTo(msg, nil, destination)
	}
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	return nil
}

// ask returns the ID of a question, which waits for its answers: one no question waiting has,
// and not zero, which is the ID of what a responder sends to all. To the host at addr, or,
// when it isn't valid, to all.
func (conn *Conn) ask(addr netip.Addr) uint16 {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	now := time.Now()
	for id, q := range conn.questions {
		if now.Sub(q.at) > questionTimeout {
			delete(conn.questions, id)
		}
	}
	for {
		id := uint16(rand.Uint32())
		if _, taken := conn.questions[id]; id != 0 && !taken {
			conn.questions[id] = question{addr, now}
			return id
		}
	}
}

// answered tells whether a question with that ID still waits for an answer, and the address it
// was sent to, if to one host: once, as that one answers once. The query for the services has
// no address, and waits for the answers of all until its time is over.
func (conn *Conn) answered(id uint16) (asked netip.Addr, waited bool) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	q, ok := conn.questions[id]
	if !ok || time.Since(q.at) > questionTimeout {
		return netip.Addr{}, false
	}
	if q.addr.IsValid() {
		delete(conn.questions, id)
	}
	return q.addr, true
}

// Close ends the listening, and leaves the groups.
func (conn *Conn) Close() error {
	var errs []error
	for _, c := range conn.closers {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}
