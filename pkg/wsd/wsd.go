package wsd

import (
	"fmt"
	"log"
	"net"
	"net/netip"

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
}

func (conn *Conn) GetListenAddrPort() *netip.AddrPort {
	return conn.listenAddrPort
}

func (conn *Conn) DiscoverMulticast() error {
	target := netip.MustParseAddr(wsDiscoveryMulticastAddress)
	return conn.SendProbe(&target)
}

func (conn *Conn) SendProbe(target *netip.Addr) error {
	destination := &net.UDPAddr{IP: net.IP(target.AsSlice()), Port: wsDiscoveryPort}

	msg := fmt.Sprintf(wsDiscoveryMessage, uuid.New().String())
	if _, err := conn.WriteTo([]byte(msg), destination); err != nil {
		return fmt.Errorf("failed to write message: %v", err)
	}

	return nil
}

func ListenForWSD(addr netip.Addr, onFoundAddr func(netip.Addr)) (*Conn, error) {
	listenAddr := netip.AddrPortFrom(addr, wsDiscoveryPort)
	conn, err := net.ListenPacket("udp6", listenAddr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}

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

	return &Conn{conn, &listenAddr}, nil
}
