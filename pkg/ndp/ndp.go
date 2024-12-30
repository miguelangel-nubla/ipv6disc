package ndp

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/ndp"
)

type Conn struct {
	*ndp.Conn
	iface      *net.Interface
	listenAddr *netip.Addr
}

func (conn *Conn) GetListenAddr() *netip.Addr {
	return conn.listenAddr
}

func (conn *Conn) DiscoverMulticast() error {
	target := netip.MustParseAddr("ff02::1")
	return conn.SendNeighborSolicitation(&target)
}

func (conn *Conn) SendNeighborSolicitation(target *netip.Addr) error {
	// Always multicast to the target's solicited-node multicast address to discover MAC address.
	solicitedNodeMulticast, err := ndp.SolicitedNodeMulticast(*target)
	if err != nil {
		return fmt.Errorf("failed to determine solicited-node multicast address: %w", err)
	}

	m := &ndp.NeighborSolicitation{
		TargetAddress: *target,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      conn.iface.HardwareAddr,
			},
		},
	}

	if err := conn.WriteTo(m, nil, solicitedNodeMulticast); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

func ListenForNDP(iface *net.Interface, addr netip.Addr, processNDP func(netip.Addr, net.HardwareAddr)) (*Conn, error) {
	conn, _, err := ndp.Listen(iface, ndp.Addr(addr.String()))
	if err != nil {
		return nil, fmt.Errorf("failed to listen for NDP packets: %v", err)
	}

	go func() {
		for {
			msg, _, from, err := conn.ReadFrom()
			if err != nil {
				fmt.Printf("Error reading: %v", err)
				continue
			}

			processNDPPacket(msg, from, processNDP)
		}
	}()

	return &Conn{conn, iface, &addr}, nil
}

func processNDPPacket(message ndp.Message, from netip.Addr, processNDP func(netip.Addr, net.HardwareAddr)) {
	switch msg := message.(type) {
	case *ndp.NeighborAdvertisement:
		processNDPOptions(&msg.Options, from, processNDP)
	case *ndp.NeighborSolicitation:
		processNDPOptions(&msg.Options, from, processNDP)
	default:

	}
}

func processNDPOptions(options *[]ndp.Option, from netip.Addr, processNDP func(netip.Addr, net.HardwareAddr)) {
	for _, o := range *options {
		if linkLayerAddr, ok := o.(*ndp.LinkLayerAddress); ok {
			processNDP(from, linkLayerAddr.Addr)
		}
	}
}

func SolicitedNodeMulticast(addr netip.Addr) (netip.Addr, error) {
	return ndp.SolicitedNodeMulticast(addr)
}
