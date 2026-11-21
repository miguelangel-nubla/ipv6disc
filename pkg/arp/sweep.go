package arp

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// DefaultSweepPrefix bounds a sweep, unless it is told: a subnet larger than a /22, 1022
// addresses, is swept in the /24 of the address. MaxSweepBits is the same, in bits of host.
const (
	DefaultSweepPrefix = 22
	MaxSweepBits       = 32 - DefaultSweepPrefix
)

// SweepTargets returns the addresses a sweep from local, on its subnet, sends to: every one but
// the network's, the broadcast and local's own. A subnet larger than a /22 is swept in the /24 of
// local only.
func SweepTargets(local netip.Prefix) []netip.Addr {
	return SweepTargetsWithin(local, DefaultSweepPrefix)
}

// SweepTargetsWithin is SweepTargets with another bound than a /22: a subnet larger than a
// /maxPrefix is swept in the /24 of local only, or in its /maxPrefix when that is smaller.
func SweepTargetsWithin(local netip.Prefix, maxPrefix int) []netip.Addr {
	if !local.Addr().Is4() {
		return nil
	}
	prefix := local.Masked()
	if prefix.Bits() < maxPrefix {
		prefix = netip.PrefixFrom(local.Addr(), max(24, min(maxPrefix, 32))).Masked()
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

// MaxProbeAddrs bounds the addresses a probe of one host asks for on one subnet: a /20.
const MaxProbeAddrs = 4096

// ProbeTargets returns the addresses of local's subnet, but the network's, the broadcast and
// local's own, that are in within. Without within, those of a sweep: the subnet, or the /24 of
// local in a subnet larger than a /22. At most MaxProbeAddrs: those nearest local.
func ProbeTargets(local netip.Prefix, within netip.Prefix) []netip.Addr {
	if !within.IsValid() {
		return SweepTargets(local)
	}
	subnet := local.Masked()
	within = within.Masked()
	if !local.Addr().Is4() || !within.Addr().Is4() || !subnet.Overlaps(within) {
		return nil
	}
	// Of two overlapping prefixes, the longer is in the other.
	span := subnet
	if within.Bits() > subnet.Bits() {
		span = within
	}
	first, last := span.Addr(), lastAddr(span)
	// A span too large for the cap: the window of it around local.
	if size := uint64(1) << (32 - span.Bits()); size > MaxProbeAddrs {
		lo, hi, at := toUint(first), toUint(last), toUint(local.Addr())
		start := max(int64(at)-MaxProbeAddrs/2, int64(lo))
		start = min(start, int64(hi)-MaxProbeAddrs+1)
		first, last = fromUint(uint32(start)), fromUint(uint32(start+MaxProbeAddrs-1))
	}
	subnetFirst, subnetLast := subnet.Addr(), lastAddr(subnet)
	var targets []netip.Addr
	for a := first; a.IsValid() && a.Compare(last) <= 0 && len(targets) < MaxProbeAddrs; a = a.Next() {
		if a == local.Addr() || subnet.Bits() < 31 && (a == subnetFirst || a == subnetLast) {
			continue
		}
		targets = append(targets, a)
	}
	return targets
}

func toUint(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func fromUint(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
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

// The bounds of Settle: the answers to a sweep take a few seconds to land, and settings that would
// have it wait longer than half a minute are taken as that.
const (
	minSettle = 3 * time.Second
	maxSettle = 30 * time.Second
)
