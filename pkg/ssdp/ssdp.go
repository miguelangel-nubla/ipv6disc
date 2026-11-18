package ssdp

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/miguelangel-nubla/ipv6disc/internal/udp"
)

const ssdpPort = 1900

// The link-local scope SSDP multicast address.
var ssdpMulticastAddress = netip.MustParseAddr("ff02::c")

type Conn struct {
	*udp.Conn
}

// DiscoverMulticast asks every SSDP device on the link to announce itself.
func (conn *Conn) DiscoverMulticast() error {
	conn.DiscoveryRuns.Add(1)
	return conn.SendSSDPRequest(&ssdpMulticastAddress)
}

func (conn *Conn) SendSSDPRequest(target *netip.Addr) error {
	return conn.Send(*target, ssdpPort, searchMessage(*target))
}

// searchMessage is an M-SEARCH request for every device and service. Its Host header is the
// address it is sent to, and as an HTTP request its lines end in CRLF, with an empty one last.
func searchMessage(target netip.Addr) []byte {
	host := net.JoinHostPort(target.String(), strconv.Itoa(ssdpPort))
	return fmt.Appendf(nil, "M-SEARCH * HTTP/1.1\r\nHOST: %s\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n", host)
}

func ListenForSSDP(iface *net.Interface, addr netip.Addr, onFoundAddr func(netip.Addr) bool, onError func(error)) (*Conn, error) {
	conn, err := udp.Listen(iface, addr, onFoundAddr, onError)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for SSDP packets: %w", err)
	}
	return &Conn{conn}, nil
}
