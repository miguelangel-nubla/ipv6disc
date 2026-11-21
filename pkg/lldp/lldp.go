// Package lldp hears what the neighbors of an interface say of themselves by LLDP (IEEE
// 802.1AB): the switch a port is plugged into, or a host that runs lldpd, tells its name and the
// addresses it is managed at. It only listens, by a packet socket of Linux: nothing is ever sent.
package lldp

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/miguelangel-nubla/ipv6disc/internal/packet"
	"github.com/miguelangel-nubla/ipv6disc/pkg/stats"
)

// EtherType is LLDP's.
const EtherType = 0x88cc

// The groups LLDP is sent to: the nearest bridge's, which no bridge forwards, and those that
// reach a little further.
var groups = []net.HardwareAddr{
	{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e},
	{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03},
	{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00},
}

// Neighbor is what an LLDP frame says of its sender.
type Neighbor struct {
	// The MAC the frame came from: the port's that sent it.
	Source net.HardwareAddr
	// The chassis's MAC and the port's, when their IDs are MACs: nil otherwise.
	Chassis, Port net.HardwareAddr
	// The system's name, as it has it: "" when it tells none.
	Name string
	// The addresses it says it is managed at: its word, and no proof that it has them.
	Addrs []netip.Addr
}

const (
	tlvEnd        = 0
	tlvChassis    = 1
	tlvPort       = 2
	tlvTTL        = 3
	tlvSystemName = 5
	tlvManagement = 8

	chassisMAC = 4
	portMAC    = 3
	// The families of a management address, of IANA's numbers.
	familyIPv4 = 1
	familyIPv6 = 2

	// maxAddrs bounds the management addresses taken of a frame.
	maxAddrs = 8
)

// Parse reads an LLDP frame's payload, from source. One whose TLVs can't be read is no
// neighbor's, and one that says its sender is going, with a time to live of zero, neither.
func Parse(b []byte, source net.HardwareAddr) (Neighbor, bool) {
	n := Neighbor{Source: source}
	seen := false
	for len(b) >= 2 {
		header := binary.BigEndian.Uint16(b[0:2])
		kind, length := int(header>>9), int(header&0x1ff)
		if len(b) < 2+length {
			return Neighbor{}, false
		}
		value := b[2 : 2+length]
		b = b[2+length:]
		switch kind {
		case tlvEnd:
			return known(n, seen)
		case tlvChassis:
			seen = true
			if len(value) == 7 && value[0] == chassisMAC {
				n.Chassis = hostMAC(value[1:])
			}
		case tlvPort:
			if len(value) == 7 && value[0] == portMAC {
				n.Port = hostMAC(value[1:])
			}
		case tlvTTL:
			if len(value) != 2 || binary.BigEndian.Uint16(value) == 0 {
				return Neighbor{}, false
			}
		case tlvSystemName:
			if n.Name == "" {
				n.Name = strings.TrimRight(string(value), "\x00")
			}
		case tlvManagement:
			// The length of the address with its family, the family, and the address.
			if len(value) < 2 || int(value[0]) < 1 || len(value) < 1+int(value[0]) || len(n.Addrs) >= maxAddrs {
				continue
			}
			var addr netip.Addr
			switch address := value[2 : 1+int(value[0])]; {
			case value[1] == familyIPv4 && len(address) == 4:
				addr = netip.AddrFrom4([4]byte(address))
			case value[1] == familyIPv6 && len(address) == 16:
				addr = netip.AddrFrom16([16]byte(address))
			}
			if addr.IsValid() && !addr.IsUnspecified() && !addr.IsMulticast() && !addr.IsLoopback() {
				n.Addrs = append(n.Addrs, addr)
			}
		}
	}
	// Without its end, it is as far as it was read: a frame can be padded, and can lack it.
	return known(n, seen)
}

// known is a neighbor that told its chassis, as every frame of LLDP must: without, nothing.
func known(n Neighbor, chassis bool) (Neighbor, bool) {
	if !chassis {
		return Neighbor{}, false
	}
	return n, true
}

// hostMAC is a MAC of a host: not a group's, nor all zeros.
func hostMAC(b []byte) net.HardwareAddr {
	if b[0]&1 != 0 || (b[0]|b[1]|b[2]|b[3]|b[4]|b[5]) == 0 {
		return nil
	}
	return net.HardwareAddr(append([]byte(nil), b...))
}

// Conn is the listening on an interface.
type Conn struct {
	stats.Counters
	conn *packet.Conn
}

// Listen hears the LLDP neighbors of iface: heard is called with each, from the Conn's reading,
// and returns whether it tells a host's name, for the stats. It needs Linux and CAP_NET_RAW:
// elsewhere the error is errors.ErrUnsupported.
func Listen(iface *net.Interface, heard func(Neighbor) bool, onError func(error)) (*Conn, error) {
	c, err := packet.Listen(iface, EtherType, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for LLDP on %s: %w", iface.Name, err)
	}
	for _, group := range groups {
		if err := c.Join(iface, group); err != nil {
			c.Close()
			return nil, fmt.Errorf("failed to join %s on %s: %w", group, iface.Name, err)
		}
	}
	conn := &Conn{conn: c}
	go c.Run(func(payload []byte, from net.HardwareAddr) {
		if len(from) != 6 || hostMAC(from) == nil {
			return
		}
		n, ok := Parse(payload, from)
		if !ok {
			return
		}
		conn.PacketsReceived.Add(1)
		if heard(n) {
			conn.HostsFound.Add(1)
		}
	}, func(err error) {
		if onError != nil {
			onError(fmt.Errorf("read error: %w", err))
		}
	})
	return conn, nil
}

// Stats are the counters, where hosts are the frames that told a host's name.
func (conn *Conn) Stats() map[string]any {
	stats := conn.Counters.Stats()
	// Nothing is sent, nor probed.
	delete(stats, "sent")
	delete(stats, "runs")
	return stats
}

// Close ends the listening, and leaves the groups.
func (conn *Conn) Close() error {
	return conn.conn.Close()
}
