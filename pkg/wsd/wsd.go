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

// The link-local scope WS-Discovery multicast address: SSDP's too, on another port.
var wsDiscoveryMulticastAddress = netip.MustParseAddr("ff02::c")

type Conn struct {
	*udp.Conn
	// The learning of names, when it was asked for: nil without.
	names *names
}

// DiscoverMulticast probes for every WS-Discovery target service on the link.
func (conn *Conn) DiscoverMulticast() error {
	conn.DiscoveryRuns.Add(1)
	return conn.SendProbe(&wsDiscoveryMulticastAddress)
}

func (conn *Conn) SendProbe(target *netip.Addr) error {
	id := uuid.New().String()
	if conn.names != nil {
		conn.names.probed(uuidURN(id))
	}
	return conn.Send(*target, wsDiscoveryPort, probeMessageWith(id))
}

// probeMessage is a Probe for every target service, of SOAP 1.2 and WS-Addressing 2004/08, with
// a message ID of its own: a service ignores a probe it has seen.
func probeMessage() []byte {
	return probeMessageWith(uuid.New().String())
}

func probeMessageWith(id string) []byte {
	return fmt.Appendf(nil, wsDiscoveryMessage, id)
}

func ListenForWSD(iface *net.Interface, addr netip.Addr, onFoundAddr func(netip.Addr) bool, onError func(error)) (*Conn, error) {
	conn, err := udp.Listen(iface, addr, onFoundAddr, onError)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for WSD packets: %w", err)
	}
	return &Conn{Conn: conn}, nil
}

// ListenForWSDNames is ListenForWSD, which also learns the name of each computer that answers a
// probe, from its metadata: a Resolve sent to it alone when its answer doesn't tell where that
// is, and one HTTP request to the address it answered from, bounded as internal/fetch says.
func ListenForWSDNames(iface *net.Interface, addr netip.Addr, onFoundAddr func(netip.Addr) bool, handler Names, onError func(error)) (*Conn, error) {
	n := newNames(iface, handler)
	conn, err := udp.ListenPackets(iface, addr, func(from netip.Addr, packet []byte) bool {
		n.take(from, packet)
		return onFoundAddr(from)
	}, onError)
	if err != nil {
		n.fetcher.Close()
		return nil, fmt.Errorf("failed to listen for WSD packets: %w", err)
	}
	// Before any probe is sent: nothing is taken until one is.
	n.mutex.Lock()
	n.conn = conn
	n.mutex.Unlock()
	return &Conn{Conn: conn, names: n}, nil
}

// Close ends the listening, and what is being fetched.
func (conn *Conn) Close() error {
	err := conn.Conn.Close()
	if conn.names != nil {
		conn.names.fetcher.Close()
	}
	return err
}
