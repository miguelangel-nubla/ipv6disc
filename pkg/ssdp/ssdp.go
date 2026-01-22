package ssdp

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync/atomic"
)

const (
	ssdpMulticastAddress = "ff02::c"
	ssdpPort             = 1900
	ssdpMessage          = `M-SEARCH * HTTP/1.1
Host: %s
Man: "ssdp:discover"
ST: ssdp:all
MX: 3
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
	target := netip.MustParseAddr(ssdpMulticastAddress)
	return conn.SendSSDPRequest(&target)
}

func (conn *Conn) SendSSDPRequest(target *netip.Addr) error {
	atomic.AddUint64(&conn.stats.PacketsSent, 1)
	destination := &net.UDPAddr{IP: net.IP(target.AsSlice()), Port: ssdpPort, Zone: conn.iface.Name}

	msg := fmt.Sprintf(ssdpMessage, conn.listenAddrPort)
	if _, err := conn.WriteTo([]byte(msg), destination); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

func ListenForSSDP(iface *net.Interface, addr netip.Addr, onFoundAddr func(netip.Addr)) (*Conn, error) {
	listenAddrPort := netip.AddrPortFrom(addr, 0)
	conn, err := net.ListenPacket("udp6", listenAddrPort.String())
	if err != nil {
		log.Fatalf("failed to listen for SSDP packets: %v", err)
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
				log.Printf("read error: %v", err)
				continue
			}
			atomic.AddUint64(&connStats.stats.PacketsReceived, 1)
			remoteAddr := netip.MustParseAddrPort(remoteAddrPort.String()).Addr()
			onFoundAddr(remoteAddr)
		}
	}()

	return connStats, nil
}
