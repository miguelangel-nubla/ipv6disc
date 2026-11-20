package ping

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"

	"github.com/miguelangel-nubla/ipv6disc/internal/backoff"
	"github.com/miguelangel-nubla/ipv6disc/internal/link"
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

// SendPing sends an echo request to target, out of the connection's interface.
func (conn *Conn) SendPing(target *netip.Addr) error {
	conn.PacketsSent.Add(1)
	b, err := echoRequest()
	if err != nil {
		return fmt.Errorf("error marshaling echo request: %w", err)
	}

	destination := &net.IPAddr{IP: net.IP(target.AsSlice()), Zone: conn.iface.Name}
	if _, err := conn.WriteTo(b, destination); err != nil {
		return fmt.Errorf("error sending echo request: %w", err)
	}

	return nil
}

// echoRequest is an echo request with the next identifier, of which the 16 low bits go out: the
// replies aren't matched to it. Its checksum is the kernel's to fill in.
func echoRequest() ([]byte, error) {
	m := &icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:  int(icmpIDCounter.Add(1)),
			Seq: 1,
		},
	}
	return m.Marshal(nil)
}

// isEchoReply tells whether an ICMPv6 message is an echo reply, of any identifier and sequence.
// The socket hears every ICMPv6 message to this machine, NDP and MLD too, which aren't. A reply
// longer than the buffer it was read in is cut short, and still one.
func isEchoReply(b []byte) (bool, error) {
	msg, err := icmp.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), b)
	if err != nil {
		return false, fmt.Errorf("error parsing ICMPv6 message: %w", err)
	}
	return msg.Type == ipv6.ICMPTypeEchoReply, nil
}

// ListenForICMP calls onFoundAddr with the sender of each echo reply that comes in on iface, a
// link-local one with its zone. It returns whether the sender is a host found, for the stats.
// Any echo reply counts, of another process's ping too: its sender is a host all the same. Closing
// the connection ends the listening, without a call of onError: any other error of a read is
// reported, and the next read tried, after a wait that grows while they fail.
func ListenForICMP(iface *net.Interface, addr netip.Addr, onFoundAddr func(netip.Addr) bool, onError func(error)) (*Conn, error) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("error listening for ICMPv6 packets on %v: %w", addr, err)
	}

	// Only the replies that come in on the interface: one routed in through another is that one's.
	pc := conn.IPv6PacketConn()
	link.Enable(pc)

	result := &Conn{
		PacketConn: conn,
		iface:      iface,
	}

	go func() {
		packet := make([]byte, 1500)
		var retry backoff.Delay
		for {
			n, cm, remote, err := pc.ReadFrom(packet)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if onError != nil {
					onError(fmt.Errorf("error reading packet: %w", err))
				}
				// Not taken as passing: one that stays must not spin the loop.
				retry.Wait()
				continue
			}
			retry.Reset()

			if !link.From(cm, iface) {
				continue
			}
			reply, err := isEchoReply(packet[:n])
			if err != nil {
				if onError != nil {
					onError(err)
				}
				continue
			}
			if !reply {
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
