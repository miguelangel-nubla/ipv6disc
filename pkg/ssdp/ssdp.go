package ssdp

import (
	"fmt"
	"log"
	"net"
	"net/netip"
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
}

func (conn *Conn) GetListenAddrPort() *netip.AddrPort {
	return conn.listenAddrPort
}

func (conn *Conn) DiscoverMulticast() error {
	target := netip.MustParseAddr(ssdpMulticastAddress)
	return conn.SendSSDPRequest(&target)
}

func (conn *Conn) SendSSDPRequest(target *netip.Addr) error {
	destination := &net.UDPAddr{IP: net.IP(target.AsSlice()), Port: ssdpPort}

	msg := fmt.Sprintf(ssdpMessage, conn.listenAddrPort)
	if _, err := conn.WriteTo([]byte(msg), destination); err != nil {
		return fmt.Errorf("failed to write message: %v", err)
	}

	return nil
}

func ListenForSSDP(addr netip.Addr, onFoundAddr func(netip.Addr)) (*Conn, error) {
	listenAddrPort := netip.AddrPortFrom(addr, 0)
	conn, err := net.ListenPacket("udp6", listenAddrPort.String())
	if err != nil {
		log.Fatalf("failed to listen for SSDP packets: %v", err)
	}

	listenAddrPort = netip.MustParseAddrPort(conn.LocalAddr().(*net.UDPAddr).String())

	//conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, 4096)

	go func() {
		for {
			_, remoteAddrPort, err := conn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					break
				}
				log.Printf("read error: %v", err)
				continue
			}
			remoteAddr := netip.MustParseAddrPort(remoteAddrPort.String()).Addr()
			onFoundAddr(remoteAddr)
		}
	}()

	return &Conn{conn, &listenAddrPort}, nil
}
