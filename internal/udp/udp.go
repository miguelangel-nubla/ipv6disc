// Package udp has what the UDP discovery protocols share: a listener on an ephemeral port that
// sends a multicast query and reports who answers.
package udp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/miguelangel-nubla/ipv6disc/internal/backoff"
	"github.com/miguelangel-nubla/ipv6disc/internal/link"
	"github.com/miguelangel-nubla/ipv6disc/pkg/stats"
	"golang.org/x/net/ipv6"
)

type Conn struct {
	net.PacketConn
	stats.Counters

	listenAddrPort netip.AddrPort
	iface          *net.Interface
}

func (conn *Conn) GetListenAddrPort() *netip.AddrPort {
	return &conn.listenAddrPort
}

// Send writes msg to target on port, out of the listener's interface: the zone of target, if any,
// gives way to it. That is what keeps a multicast or link-local destination on the listener's
// link, as its socket, bound to a global address, isn't bound to the interface.
func (conn *Conn) Send(target netip.Addr, port int, msg []byte) error {
	conn.PacketsSent.Add(1)
	destination := &net.UDPAddr{IP: net.IP(target.AsSlice()), Port: port, Zone: conn.iface.Name}
	if _, err := conn.WriteTo(msg, destination); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	return nil
}

// Listen opens an ephemeral port on addr, and calls onFoundAddr with the sender of each packet. It
// returns whether the sender is a host found, for the stats. Closing the connection ends the
// listening, without a call of onError: any other error of a read is reported, and the next read
// tried, after a wait that grows while they fail.
func Listen(iface *net.Interface, addr netip.Addr, onFoundAddr func(netip.Addr) bool, onError func(error)) (*Conn, error) {
	return ListenPackets(iface, addr, func(from netip.Addr, _ []byte) bool { return onFoundAddr(from) }, onError)
}

// ListenPackets is Listen, for a protocol that reads what the senders say too: onPacket gets each
// packet with its sender, and must not keep it.
func ListenPackets(iface *net.Interface, addr netip.Addr, onPacket func(netip.Addr, []byte) bool, onError func(error)) (*Conn, error) {
	conn, err := net.ListenPacket("udp6", netip.AddrPortFrom(addr, 0).String())
	if err != nil {
		return nil, err
	}

	// Only the answers that come in on the interface: one routed in through another is that one's.
	pc := ipv6.NewPacketConn(conn)
	link.Enable(pc)

	result := &Conn{
		PacketConn:     conn,
		listenAddrPort: conn.LocalAddr().(*net.UDPAddr).AddrPort(),
		iface:          iface,
	}

	go result.readPackets(pc.ReadFrom, onPacket, onError)

	return result, nil
}

// read is the listening of Listen, on what readFrom reads, until it says the connection closed.
func (conn *Conn) read(readFrom func([]byte) (int, *ipv6.ControlMessage, net.Addr, error), onFoundAddr func(netip.Addr) bool, onError func(error)) {
	conn.readPackets(readFrom, func(from netip.Addr, _ []byte) bool { return onFoundAddr(from) }, onError)
}

func (conn *Conn) readPackets(readFrom func([]byte) (int, *ipv6.ControlMessage, net.Addr, error), onPacket func(netip.Addr, []byte) bool, onError func(error)) {
	buf := make([]byte, 4096)
	var retry backoff.Delay
	for {
		n, cm, remote, err := readFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if onError != nil {
				onError(fmt.Errorf("read error: %w", err))
			}
			// Not taken as passing: one that stays must not spin the loop.
			retry.Wait()
			continue
		}
		retry.Reset()
		if !link.From(cm, conn.iface) {
			continue
		}
		conn.PacketsReceived.Add(1)
		if udpAddr, ok := remote.(*net.UDPAddr); ok {
			if onPacket(udpAddr.AddrPort().Addr().Unmap(), buf[:n]) {
				conn.HostsFound.Add(1)
			}
		}
	}
}
