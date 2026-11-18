package ping

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"

	"github.com/miguelangel-nubla/ipv6disc/pkg/stats"
)

var allNodes = netip.MustParseAddr("ff02::1")

var icmpIDCounter atomic.Int32

type Conn struct {
	*icmp.PacketConn
	stats.Counters

	iface *net.Interface
}

func (conn *Conn) GetListenAddr() *netip.Addr {
	addr, _ := netip.ParseAddr(conn.LocalAddr().String())
	return &addr
}

// DiscoverMulticast pings all the nodes on the link.
func (conn *Conn) DiscoverMulticast() error {
	conn.DiscoveryRuns.Add(1)
	return conn.SendPing(&allNodes)
}

func (conn *Conn) SendPing(target *netip.Addr) error {
	conn.PacketsSent.Add(1)
	m := &icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:  int(icmpIDCounter.Add(1)),
			Seq: 1,
		},
	}

	b, err := m.Marshal(nil)
	if err != nil {
		return fmt.Errorf("error marshaling echo request: %w", err)
	}

	destination := &net.IPAddr{IP: net.IP(target.AsSlice()), Zone: conn.iface.Name}
	if _, err := conn.WriteTo(b, destination); err != nil {
		return fmt.Errorf("error sending echo request: %w", err)
	}

	return nil
}

// ListenForICMP calls onFoundAddr with the sender of each echo reply. It returns whether the sender
// is a host found, for the stats.
func ListenForICMP(iface *net.Interface, addr netip.Addr, onFoundAddr func(netip.Addr) bool, onError func(error)) (*Conn, error) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("error listening for ICMPv6 packets on %v: %w", addr, err)
	}

	result := &Conn{
		PacketConn: conn,
		iface:      iface,
	}

	go func() {
		packet := make([]byte, 1500)
		for {
			n, remote, err := conn.ReadFrom(packet)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if onError != nil {
					onError(fmt.Errorf("error reading packet: %w", err))
				}
				continue
			}

			msg, err := icmp.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), packet[:n])
			if err != nil {
				if onError != nil {
					onError(fmt.Errorf("error parsing ICMPv6 message: %w", err))
				}
				continue
			}

			if msg.Type != ipv6.ICMPTypeEchoReply {
				continue
			}
			result.PacketsReceived.Add(1)
			if remoteAddr, err := netip.ParseAddr(remote.String()); err == nil && onFoundAddr(remoteAddr) {
				result.HostsFound.Add(1)
			}
		}
	}()

	return result, nil
}
