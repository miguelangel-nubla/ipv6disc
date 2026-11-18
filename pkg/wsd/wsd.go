package wsd

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/google/uuid"

	"github.com/miguelangel-nubla/ipv6disc/internal/udp"
)

const (
	wsDiscoveryPort    = 3702
	wsDiscoveryMessage = `<?xml version="1.0" encoding="utf-8"?>
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

// The link-local scope WS-Discovery multicast address.
var wsDiscoveryMulticastAddress = netip.MustParseAddr("ff02::c")

type Conn struct {
	*udp.Conn
}

// DiscoverMulticast probes for every WS-Discovery target service on the link.
func (conn *Conn) DiscoverMulticast() error {
	conn.DiscoveryRuns.Add(1)
	return conn.SendProbe(&wsDiscoveryMulticastAddress)
}

func (conn *Conn) SendProbe(target *netip.Addr) error {
	return conn.Send(*target, wsDiscoveryPort, fmt.Appendf(nil, wsDiscoveryMessage, uuid.New().String()))
}

func ListenForWSD(iface *net.Interface, addr netip.Addr, onFoundAddr func(netip.Addr) bool, onError func(error)) (*Conn, error) {
	conn, err := udp.Listen(iface, addr, onFoundAddr, onError)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for WSD packets: %w", err)
	}
	return &Conn{conn}, nil
}
