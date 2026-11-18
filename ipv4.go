package ipv6disc

import (
	"context"
	"errors"
	"fmt"
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
		if w.config.probesIPv4() && time.Since(lastSweep) >= w.rediscover {
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

// SolicitIPv4 asks each MAC, by ARP requests sent to it alone, for every address of the local
// subnets, and registers those it answers for: the IPv4 addresses of a host that stays quiet, with
// nothing broadcast. It needs Linux and CAP_NET_RAW, and the state taking IPv4. It returns how many
// addresses were found.
func (w *Worker) SolicitIPv4(ctx context.Context, macs []net.HardwareAddr) (int, error) {
	if !w.State.IPv4() {
		return 0, errors.New("soliciting IPv4 addresses: the state doesn't take IPv4")
	}
	found := 0
	var errs []error
	for name, i := range ipv4Interfaces() {
		for _, prefix := range i.prefixes {
			targets := arp.SweepTargets(prefix)
			for _, mac := range macs {
				addrs, err := arp.Probe(ctx, &i.iface, prefix.Addr(), mac, targets)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s on %s: %w", mac, name, err))
					if errors.Is(err, errors.ErrUnsupported) || ctx.Err() != nil {
						return found, errors.Join(errs...)
					}
					continue
				}
				for _, ip := range addrs {
					if _, existing := w.State.Register(mac, ip, name, w.lifetime, nil); !existing {
						found++
					}
				}
			}
		}
	}
	return found, errors.Join(errs...)
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
