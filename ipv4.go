package ipv6disc

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/arp"
	"go.uber.org/zap"
)

// sweepSettle is how long after a sweep its answers take to land in the neighbor table.
const sweepSettle = 3 * time.Second

// discoverIPv4 reads the kernel's IPv4 neighbor table every interfaceCheckInterval and, with active
// discovery, sweeps the local subnets at every rediscovery first, so that the hosts there that
// stay quiet are in it too. It returns when ctx is done, or the system has no table to read.
func (w *Worker) discoverIPv4(ctx context.Context) {
	ticker := time.NewTicker(interfaceCheckInterval)
	defer ticker.Stop()

	var lastSweep time.Time
	for {
		if w.discoveryActive && time.Since(lastSweep) >= w.rediscover {
			lastSweep = time.Now()
			w.sweepIPv4(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(sweepSettle):
			}
		}

		if err := w.readIPv4Table(); errors.Is(err, errors.ErrUnsupported) {
			w.logger.Warnf("no local IPv4 discovery: %s", err)
			return
		} else if err != nil {
			w.logger.Errorf("IPv4 discovery: %s", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// ipv4Interface is an interface IPv4 discovery runs on, with its IPv4 addresses.
type ipv4Interface struct {
	iface    net.Interface
	prefixes []netip.Prefix
}

// ipv4Interfaces returns the interfaces that can have IPv4 neighbors: up, broadcast, not
// loopback, with an IPv4 address.
func ipv4Interfaces() map[string]ipv4Interface {
	result := make(map[string]ipv4Interface)
	ifaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagBroadcast == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		var prefixes []netip.Prefix
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			ones, _ := ipNet.Mask.Size()
			if ip = ip.Unmap(); ok && ip.Is4() && !ip.IsLinkLocalUnicast() {
				prefixes = append(prefixes, netip.PrefixFrom(ip, ones))
			}
		}
		if len(prefixes) > 0 {
			result[iface.Name] = ipv4Interface{iface: iface, prefixes: prefixes}
		}
	}
	return result
}

func (w *Worker) sweepIPv4(ctx context.Context) {
	for _, i := range ipv4Interfaces() {
		for _, prefix := range i.prefixes {
			targets := arp.SweepTargets(prefix)
			w.logger.Debugw("IPv4 sweep",
				zap.String("interface", i.iface.Name),
				zap.String("prefix", prefix.String()),
				zap.Int("addresses", len(targets)),
			)
			if err := arp.Sweep(ctx, prefix.Addr(), targets); err != nil && ctx.Err() == nil {
				w.logger.Errorw("IPv4 sweep failed", zap.String("interface", i.iface.Name), zap.Error(err))
			}
		}
	}
}

// readIPv4Table registers the neighbors of the kernel's table on the interfaces discovery runs
// on, and the interfaces' own addresses.
func (w *Worker) readIPv4Table() error {
	interfaces := ipv4Interfaces()
	for name, i := range interfaces {
		for _, prefix := range i.prefixes {
			w.State.Register(i.iface.HardwareAddr, prefix.Addr(), name, w.lifetime, nil)
		}
	}

	neighbors, err := arp.Table()
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		if _, ok := interfaces[n.Interface]; !ok {
			continue
		}
		w.State.Register(n.MAC, n.IP, n.Interface, w.lifetime, nil)
	}
	return nil
}
