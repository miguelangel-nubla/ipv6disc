package arp

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// MaxSweepBits bounds a sweep: a subnet larger than a /22, 1022 addresses, is swept in the /24
// of the address.
const MaxSweepBits = 10

// SweepTargets returns the addresses a sweep from local, on its subnet, sends to: every one but
// the network's, the broadcast and local's own. A subnet larger than a /22 is swept in the /24 of
// local only.
func SweepTargets(local netip.Prefix) []netip.Addr {
	if !local.Addr().Is4() {
		return nil
	}
	prefix := local.Masked()
	if 32-prefix.Bits() > MaxSweepBits {
		prefix = netip.PrefixFrom(local.Addr(), 24).Masked()
	}
	first, last := prefix.Addr(), lastAddr(prefix)
	// A /31 is two hosts, a /32 none but itself.
	if prefix.Bits() < 31 {
		first, last = first.Next(), last.Prev()
	}
	var targets []netip.Addr
	for a := first; a.IsValid() && a.Compare(last) <= 0; a = a.Next() {
		if a != local.Addr() {
			targets = append(targets, a)
		}
	}
	return targets
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// sweepPort is the discard port, which nothing answers on: another for tests.
var sweepPort uint16 = 9

// sweepPace is the time between two packets of a sweep: 1022 addresses take 2s.
const sweepPace = 2 * time.Millisecond

// Sweep sends a UDP packet to the discard port of each target, from local: to send it, the kernel
// resolves the target's MAC with ARP, so a host there lands in its neighbor table, whether it
// answers the packet or not. No privilege is needed. It returns once all were sent, or ctx is done.
func Sweep(ctx context.Context, local netip.Addr, targets []netip.Addr) error {
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)))
	if err != nil {
		return err
	}
	defer conn.Close()

	ticker := time.NewTicker(sweepPace)
	defer ticker.Stop()
	for _, target := range targets {
		// A host that isn't there, or a full queue: the next sweep tries again.
		conn.WriteToUDPAddrPort([]byte{0}, netip.AddrPortFrom(target, sweepPort))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	return nil
}
