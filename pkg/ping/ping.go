package ping

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

var icmpIDCounter int32

func getNextICMPID() int {
	return int(atomic.AddInt32(&icmpIDCounter, 1))
}

type Conn struct {
	*icmp.PacketConn
	iface *net.Interface

	stats Stats
}

type Stats struct {
	DiscoveryRuns   uint64
	HostsFound      uint64
	PacketsSent     uint64
	PacketsReceived uint64
}

func (conn *Conn) Stats() map[string]any {
	return map[string]any{
		"runs":  atomic.LoadUint64(&conn.stats.DiscoveryRuns),
		"hosts": atomic.LoadUint64(&conn.stats.HostsFound),
		"sent":  atomic.LoadUint64(&conn.stats.PacketsSent),
		"recv":  atomic.LoadUint64(&conn.stats.PacketsReceived),
	}
}

func (conn *Conn) GetListenAddr() *netip.Addr {
	addr := netip.MustParseAddr(conn.LocalAddr().String())
	return &addr
}

func (conn *Conn) IncrementHostsFound() {
	atomic.AddUint64(&conn.stats.HostsFound, 1)
}

func (conn *Conn) DiscoverMulticast() error {
	atomic.AddUint64(&conn.stats.DiscoveryRuns, 1)
	target := netip.MustParseAddr("ff02::1")
	return conn.SendPing(&target)
}

func (conn *Conn) SendPing(target *netip.Addr) error {
	atomic.AddUint64(&conn.stats.PacketsSent, 1)
	m := &icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   getNextICMPID(),
			Seq:  1,
			Data: []byte(""),
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

func ListenForICMP(iface *net.Interface, addr netip.Addr, onFoundAddr func(netip.Addr)) (*Conn, error) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("error listening for ICMPv6 packets on %v: %v", addr, err)
	}

	connStats := &Conn{
		PacketConn: conn,
		iface:      iface,
	}

	//conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	packet := make([]byte, 1500)

	go func() {
		for {
			n, remoteAddrPort, err := conn.ReadFrom(packet)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					fmt.Printf("Timeout listening ICMP: %s", err)
					return
				}
				fmt.Printf("Error reading packet: %s", err)
				continue
			}

			msg, err := icmp.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), packet[:n])
			if err != nil {
				fmt.Printf("Error parsing ICMPv6 message: %s", err)
				continue
			}

			if msg.Type == ipv6.ICMPTypeEchoReply {
				atomic.AddUint64(&connStats.stats.PacketsReceived, 1)
				remoteAddr := netip.MustParseAddr(remoteAddrPort.String())
				onFoundAddr(remoteAddr)
			}
		}
	}()

	return connStats, nil
}
