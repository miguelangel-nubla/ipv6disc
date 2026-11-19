// Package udp has what the UDP discovery protocols share: a listener on an ephemeral port that
// sends a multicast query and reports who answers.
package udp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

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

// Send writes msg to target on port, out of the listener's interface.
func (conn *Conn) Send(target netip.Addr, port int, msg []byte) error {
	conn.PacketsSent.Add(1)
	destination := &net.UDPAddr{IP: net.IP(target.AsSlice()), Port: port, Zone: conn.iface.Name}
	if _, err := conn.WriteTo(msg, destination); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	return nil
}

// Listen opens an ephemeral port on addr, and calls onFoundAddr with the sender of each packet. It
// returns whether the sender is a host found, for the stats.
func Listen(iface *net.Interface, addr netip.Addr, onFoundAddr func(netip.Addr) bool, onError func(error)) (*Conn, error) {
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

	go func() {
		buf := make([]byte, 4096)
		for {
			_, cm, remote, err := pc.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if onError != nil {
					onError(fmt.Errorf("read error: %w", err))
				}
				continue
			}
			if !link.From(cm, iface) {
				continue
			}
			result.PacketsReceived.Add(1)
			if udpAddr, ok := remote.(*net.UDPAddr); ok {
				if onFoundAddr(udpAddr.AddrPort().Addr().Unmap()) {
					result.HostsFound.Add(1)
				}
			}
		}
	}()

	return result, nil
}
