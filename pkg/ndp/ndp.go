package ndp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/ndp"

	"github.com/miguelangel-nubla/ipv6disc/internal/link"
	"github.com/miguelangel-nubla/ipv6disc/pkg/stats"
)

type Conn struct {
	*ndp.Conn
	stats.Counters

	iface      *net.Interface
	listenAddr *netip.Addr
}

func (conn *Conn) GetListenAddr() *netip.Addr {
	return conn.listenAddr
}

// SendNeighborSolicitation asks for the link-layer address of target, on its solicited-node
// multicast address.
func (conn *Conn) SendNeighborSolicitation(target *netip.Addr) error {
	conn.PacketsSent.Add(1)
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

// ListenForNDP calls processNDP with each address and MAC the messages tell. It returns whether the
// address is a host found, for the stats.
func ListenForNDP(iface *net.Interface, addr netip.Addr, processNDP func(netip.Addr, net.HardwareAddr) bool, onError func(error)) (*Conn, error) {
	conn, _, err := ndp.Listen(iface, ndp.Addr(addr.String()))
	if err != nil {
		return nil, fmt.Errorf("failed to listen for NDP packets: %w", err)
	}
	// The socket, bound to an address that isn't link-local, hears the multicast NDP of the other
	// interfaces too: their hosts aren't on this link.
	link.Enable(conn)

	result := &Conn{
		Conn:       conn,
		iface:      iface,
		listenAddr: &addr,
	}

	go func() {
		for {
			msg, cm, from, err := conn.ReadFrom()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if onError != nil {
					onError(fmt.Errorf("error reading: %w", err))
				}
				continue
			}
			if !link.From(cm, iface) {
				continue
			}
			result.PacketsReceived.Add(1)
			processNDPPacket(msg, from, func(addr netip.Addr, hw net.HardwareAddr) {
				if processNDP(addr, hw) {
					result.HostsFound.Add(1)
				}
			})
		}
	}()

	return result, nil
}

// processNDPPacket reports the addresses a message tells the link-layer address of.
func processNDPPacket(message ndp.Message, from netip.Addr, processNDP func(netip.Addr, net.HardwareAddr)) {
	switch msg := message.(type) {
	case *ndp.NeighborAdvertisement:
		// The answer to a solicitation: the target address is the one asked for, and the sender
		// can answer from another of its addresses. A proxy answers for others with its own
		// MAC, and without the override flag: then only the sender's address is its own.
		if hw := linkLayerAddr(msg.Options, ndp.Target); hw != nil {
			if msg.Override {
				processNDP(msg.TargetAddress, hw)
			}
			if from != msg.TargetAddress || !msg.Override {
				processNDP(from, hw)
			}
		}
	case *ndp.NeighborSolicitation:
		// Duplicate address detection solicits from the unspecified address.
		if hw := linkLayerAddr(msg.Options, ndp.Source); hw != nil && !from.IsUnspecified() {
			processNDP(from, hw)
		}
	}
}

func linkLayerAddr(options []ndp.Option, direction ndp.Direction) net.HardwareAddr {
	for _, o := range options {
		if lla, ok := o.(*ndp.LinkLayerAddress); ok && lla.Direction == direction {
			return lla.Addr
		}
	}
	return nil
}

func SolicitedNodeMulticast(addr netip.Addr) (netip.Addr, error) {
	return ndp.SolicitedNodeMulticast(addr)
}
