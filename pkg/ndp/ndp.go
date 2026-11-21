package ndp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/ndp"

	"github.com/miguelangel-nubla/ipv6disc/internal/backoff"
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

// How a message told an address, as ipv6disc's records say it.
const (
	// An unsolicited advertisement: the host says the address is its own, as when it takes it.
	Announced = "announced"
	// A solicited advertisement: the answer to a solicitation.
	Answered = "answered"
	// The sender of a solicitation, or of an advertisement for another address: the host used it.
	Heard = "heard"
)

// ListenForNDP calls processNDP with each address and MAC the messages tell, and how, of those
// that came in on iface and were never forwarded. It returns whether the address is a host found, for the stats.
// The addresses have no zone: iface is their link. Closing the connection ends the listening,
// without a call of onError: any other error of a read is reported, and the next read tried, after
// a wait that grows while they fail.
func ListenForNDP(iface *net.Interface, addr netip.Addr, processNDP func(netip.Addr, net.HardwareAddr, string) bool, onError func(error)) (*Conn, error) {
	conn, _, err := ndp.Listen(iface, ndp.Addr(addr.String()))
	if err != nil {
		return nil, fmt.Errorf("failed to listen for NDP packets: %w", err)
	}
	// The socket, bound to an address that isn't link-local, hears the multicast NDP of the other
	// interfaces too: their hosts aren't on this link.
	link.Enable(conn)
	// And, bound to such an address, the messages routed to it from anywhere: only a hop limit of
	// 255 proves that one comes from the link (RFC 4861 7.1). The kernel checks it for its own
	// neighbor cache, not for what a raw socket reads.
	hopLimit := link.EnableHopLimit(conn)

	result := &Conn{
		Conn:       conn,
		iface:      iface,
		listenAddr: &addr,
	}

	go func() {
		var retry backoff.Delay
		for {
			msg, cm, from, err := conn.ReadFrom()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if onError != nil {
					onError(fmt.Errorf("error reading: %w", err))
				}
				// Of the socket, it is not taken as passing: one that stays must not spin the
				// loop. A message that can't be parsed was read all the same, and the next is.
				if isSocketError(err) {
					retry.Wait()
				} else {
					retry.Reset()
				}
				continue
			}
			retry.Reset()
			if !link.From(cm, iface) || !link.OnLink(cm, hopLimit) {
				continue
			}
			result.PacketsReceived.Add(1)
			processNDPPacket(msg, from, func(addr netip.Addr, hw net.HardwareAddr, way string) {
				if processNDP(addr, hw, way) {
					result.HostsFound.Add(1)
				}
			})
		}
	}()

	return result, nil
}

// isSocketError tells an error of the read itself from one of the message read, which
// ndp.Conn.ReadFrom returns alike: the network's errors are the socket's.
func isSocketError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr)
}

// processNDPPacket reports the addresses a message tells the link-layer address of, without a zone,
// and how: an advertisement's target is answered when solicited, announced when not; its sender, of
// another address, and a solicitation's, are heard.
func processNDPPacket(message ndp.Message, from netip.Addr, processNDP func(netip.Addr, net.HardwareAddr, string)) {
	// ndp.Conn.ReadFrom gives every sender the zone of the interface, a global or the unspecified
	// address too, and a message's target address has none: with it, the sender would never equal
	// its own target, nor be the unspecified address.
	from = from.WithZone("")
	switch msg := message.(type) {
	case *ndp.NeighborAdvertisement:
		// The answer to a solicitation: the target address is the one asked for, and the sender
		// can answer from another of its addresses. A proxy answers for others with its own
		// MAC, and without the override flag: then only the sender's address is its own.
		if hw := linkLayerAddr(msg.Options, ndp.Target); hw != nil {
			if msg.Override {
				way := Announced
				if msg.Solicited {
					way = Answered
				}
				processNDP(msg.TargetAddress, hw, way)
			}
			if from != msg.TargetAddress || !msg.Override {
				processNDP(from, hw, Heard)
			}
		}
	case *ndp.NeighborSolicitation:
		// Duplicate address detection solicits from the unspecified address, which is no host's:
		// with a source link-layer address, which RFC 4861 forbids there, neither.
		if hw := linkLayerAddr(msg.Options, ndp.Source); hw != nil && !from.IsUnspecified() {
			processNDP(from, hw, Heard)
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
