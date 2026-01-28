package wsd

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/google/uuid"
)

const (
	wsDiscoveryMulticastAddress = "ff02::c"
	wsDiscoveryPort             = 3702
	wsDiscoveryMessage          = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <soap:Header>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:%s</wsa:MessageID>
  </soap:Header>
  <soap:Body>
    <wsd:Probe />
  </soap:Body>
</soap:Envelope>
`
)

type Conn struct {
	net.PacketConn
	listenAddrPort *netip.AddrPort
	iface          *net.Interface

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

func (conn *Conn) GetListenAddrPort() *netip.AddrPort {
	return conn.listenAddrPort
}

func (conn *Conn) IncrementHostsFound() {
	atomic.AddUint64(&conn.stats.HostsFound, 1)
}

func (conn *Conn) DiscoverMulticast() error {
	atomic.AddUint64(&conn.stats.DiscoveryRuns, 1)
	target := netip.MustParseAddr(wsDiscoveryMulticastAddress)
	return conn.SendProbe(&target)
}

func (conn *Conn) SendProbe(target *netip.Addr) error {
	atomic.AddUint64(&conn.stats.PacketsSent, 1)
	destination := &net.UDPAddr{IP: net.IP(target.AsSlice()), Port: wsDiscoveryPort, Zone: conn.iface.Name}

	msg := fmt.Sprintf(wsDiscoveryMessage, uuid.New().String())
	if _, err := conn.WriteTo([]byte(msg), destination); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

func ListenForWSD(iface *net.Interface, addr netip.Addr, onFoundAddr func(netip.Addr), onError func(error)) (*Conn, error) {
	listenAddrPort := netip.AddrPortFrom(addr, 0)
	conn, err := net.ListenPacket("udp6", listenAddrPort.String())
	if err != nil {
		return nil, fmt.Errorf("failed to listen for WSD packets: %v", err)
	}

	listenAddrPort = netip.MustParseAddrPort(conn.LocalAddr().(*net.UDPAddr).String())

	connStats := &Conn{
		PacketConn:     conn,
		listenAddrPort: &listenAddrPort,
		iface:          iface,
	}

	//conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, 4096)

	go func() {
		for {
			_, remoteAddrPort, err := conn.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					break
				}
				if onError != nil {
					onError(fmt.Errorf("read error: %w", err))
				}
				continue
			}
			atomic.AddUint64(&connStats.stats.PacketsReceived, 1)
			remoteAddr := netip.MustParseAddrPort(remoteAddrPort.String()).Addr()
			onFoundAddr(remoteAddr)
		}
	}()

	return connStats, nil
}
