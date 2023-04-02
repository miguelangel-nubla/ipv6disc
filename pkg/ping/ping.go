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
}

func (conn *Conn) GetListenAddr() *netip.Addr {
	addr := netip.MustParseAddr(conn.LocalAddr().String())
	return &addr
}

func (conn *Conn) DiscoverMulticast() error {
	target := netip.MustParseAddr("ff02::1")
	return conn.SendPing(&target)
}

func (conn *Conn) SendPing(target *netip.Addr) error {
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

	destination := &net.IPAddr{IP: net.IP(target.AsSlice())}
	if _, err := conn.WriteTo(b, destination); err != nil {
		return fmt.Errorf("error sending echo request: %w", err)
	}

	return nil
}

func ListenForICMP(addr netip.Addr, onFoundAddr func(netip.Addr)) (*Conn, error) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("error listening for ICMPv6 packets on %v: %v", addr, err)
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
				remoteAddr := netip.MustParseAddr(remoteAddrPort.String())
				onFoundAddr(remoteAddr)
			}
		}
	}()

	return &Conn{conn}, nil
}
