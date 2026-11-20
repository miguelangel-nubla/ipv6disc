package ipv6disc

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/arp"
	"go.uber.org/zap"
)

// sweepSettle is how long after a sweep its answers take to land in the neighbor table.
const sweepSettle = 3 * time.Second

// arpTable reads the kernel's IPv4 neighbor table: a variable for the tests.
var arpTable = arp.Table

// discoverIPv4 reads the kernel's IPv4 neighbor table every interfaceCheckInterval and, with active
// discovery, sweeps the local subnets at every rediscovery first, so that the hosts there that
// stay quiet are in it too. Each time it registers the interfaces' own addresses, and takes out
// those they no longer have, which is all it does where the system has no table to read: nothing
// is swept there. It returns when ctx is done.
func (w *Worker) discoverIPv4(ctx context.Context) {
	ticker := time.NewTicker(interfaceCheckInterval)
	defer ticker.Stop()

	// Asked before the first sweep, which is for the table.
	_, err := arpTable()
	neighbors := !w.tableUnsupported(err)

	var lastSweep time.Time
	own := make(map[workerKey]bool)
	for {
		if neighbors && w.config.probesIPv4() && time.Since(lastSweep) >= w.config.Rediscover {
			lastSweep = time.Now()
			w.sweepIPv4(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(sweepSettle):
			}
		}

		interfaces, err := w.listIPv4Interfaces()
		own = w.syncSelfIPv4(own, interfaces, err == nil)
		if neighbors {
			if err := w.readIPv4Table(interfaces); w.tableUnsupported(err) {
				neighbors = false
			} else if err != nil {
				w.logger.Errorf("IPv4 discovery: %s", err)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// tableUnsupported tells whether err says the system has no neighbor table to read, and logs it.
func (w *Worker) tableUnsupported(err error) bool {
	if !errors.Is(err, errors.ErrUnsupported) {
		return false
	}
	w.logger.Warnf("no local IPv4 neighbor discovery, this machine's own addresses only: %s", err)
	return true
}

// IPv4Target is a host SolicitIPv4 asks for its IPv4 addresses: its MAC, and the prefixes its
// addresses are wanted in. Without prefixes, every address of the local subnets is asked.
type IPv4Target struct {
	MAC      net.HardwareAddr
	Prefixes []netip.Prefix
}

// SolicitIPv4 asks each target, by ARP requests sent to its MAC alone, for each address of the
// local subnets in its prefixes (arp.ProbeTargets), and registers those it answers for: the IPv4
// addresses of a host that stays quiet, with nothing broadcast. A subnet none of its addresses can
// be in isn't asked. Without prefixes, only the interfaces the state saw the MAC on are, if any. It
// needs Linux and CAP_NET_RAW, and the state taking IPv4. It returns how many addresses were
// found.
func (w *Worker) SolicitIPv4(ctx context.Context, targets []IPv4Target) (int, error) {
	if !w.State.IPv4() {
		return 0, errors.New("soliciting IPv4 addresses: the state doesn't take IPv4")
	}
	found := 0
	var errs []error
	interfaces := w.ipv4Interfaces()
	for _, target := range targets {
		for _, p := range w.ipv4Probes(target, interfaces) {
			addrs, err := arp.Probe(ctx, &p.iface.iface, p.local.Addr(), target.MAC, p.asked)
			// What was found before an error counts too.
			for _, ip := range addrs {
				if _, existing := w.State.registerLocal(target.MAC, ip, p.name, w.config.Lifetime, nil); !existing {
					found++
				}
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s on %s: %w", target.MAC, p.name, err))
				if errors.Is(err, errors.ErrUnsupported) || ctx.Err() != nil {
					return found, errors.Join(errs...)
				}
			}
		}
	}
	return found, errors.Join(errs...)
}

// ipv4Probe is what SolicitIPv4 asks a target on an interface: the addresses of one of its subnets.
type ipv4Probe struct {
	name  string
	iface ipv4Interface
	local netip.Prefix
	asked []netip.Addr
}

// ipv4Probes are the probes of a target. With prefixes, on each interface with a subnet a prefix
// covers part of: they say where its addresses are, wherever the state saw the MAC, as a host
// heard over IPv6 on one interface and with its IPv4 address on another, beside it on the same
// wire. Without, on the interfaces the state saw it on, if any: else every subnet of every
// interface would be asked.
func (w *Worker) ipv4Probes(target IPv4Target, interfaces map[string]ipv4Interface) []ipv4Probe {
	names := slices.Sorted(maps.Keys(interfaces))
	if len(target.Prefixes) == 0 {
		names = w.interfacesOf(target.MAC, interfaces)
	}
	var probes []ipv4Probe
	for _, name := range names {
		i := interfaces[name]
		for _, local := range i.prefixes {
			if asked := probeTargets(local, target.Prefixes); len(asked) > 0 {
				probes = append(probes, ipv4Probe{name: name, iface: i, local: local, asked: asked})
			}
		}
	}
	return probes
}

// probeTargets returns the addresses of the subnet of local to ask, in one of the prefixes: all of
// them without prefixes.
func probeTargets(local netip.Prefix, prefixes []netip.Prefix) []netip.Addr {
	if len(prefixes) == 0 {
		return arp.ProbeTargets(local, netip.Prefix{})
	}
	seen := make(map[netip.Addr]bool)
	var targets []netip.Addr
	for _, p := range prefixes {
		for _, a := range arp.ProbeTargets(local, p) {
			if !seen[a] {
				seen[a] = true
				targets = append(targets, a)
			}
		}
	}
	return targets
}

// interfacesOf returns the interfaces to ask mac on: the local interfaces that saw its addresses,
// of either family, when there are; all of them otherwise, in order. A plugin's name, even an
// interface's, doesn't count.
func (w *Worker) interfacesOf(mac net.HardwareAddr, interfaces map[string]ipv4Interface) []string {
	var seenOn []string
	for _, addr := range w.State.FilterMACs([]net.HardwareAddr{mac}).Get() {
		for _, source := range addr.Interfaces() {
			if _, ok := interfaces[source]; ok && !slices.Contains(seenOn, source) {
				seenOn = append(seenOn, source)
			}
		}
	}
	if len(seenOn) > 0 {
		slices.Sort(seenOn)
		return seenOn
	}
	return slices.Sorted(maps.Keys(interfaces))
}

// ipv4Interface is an interface IPv4 discovery runs on, with its IPv4 addresses.
type ipv4Interface struct {
	iface    net.Interface
	prefixes []netip.Prefix
}

// ipv4Interfaces returns the interfaces IPv4 discovery runs on: those the configuration takes
// which can have IPv4 neighbors, up, broadcast, not loopback, with an IPv4 address.
func (w *Worker) ipv4Interfaces() map[string]ipv4Interface {
	result, _ := w.listIPv4Interfaces()
	return result
}

// listIPv4Interfaces is ipv4Interfaces, with the error that left interfaces out, if any: what is
// missing then is not known to be gone.
func (w *Worker) listIPv4Interfaces() (map[string]ipv4Interface, error) {
	result := make(map[string]ipv4Interface)
	ifaces, err := net.Interfaces()
	if err != nil {
		return result, err
	}
	var errs []error
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagBroadcast == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 || !w.config.usesInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			errs = append(errs, err)
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
	return result, errors.Join(errs...)
}

func (w *Worker) sweepIPv4(ctx context.Context) {
	for _, i := range w.ipv4Interfaces() {
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

// registerSelfIPv4 registers the own addresses of the interfaces discovery runs on, or refreshes
// them: every time the table is read, and as often where there is none. It returns them, by
// interface name, MAC and address.
func (w *Worker) registerSelfIPv4(interfaces map[string]ipv4Interface) map[workerKey]bool {
	own := make(map[workerKey]bool)
	for name, i := range interfaces {
		for _, prefix := range i.prefixes {
			w.State.RegisterSelf(i.iface.HardwareAddr, prefix.Addr(), name, false, w.config.Lifetime, nil)
			own[workerKey{name: name, addr: prefix.Addr(), hw: i.iface.HardwareAddr.String()}] = true
		}
	}
	return own
}

// syncSelfIPv4 is registerSelfIPv4, which also takes out of the state the addresses registered
// before, previous, that the interfaces no longer have: at once, not after their lifetime, as they
// are not this machine's any more. Not when the interfaces aren't all known, complete: those
// missing stay, and are looked for again the next time. It returns the addresses registered so
// far.
func (w *Worker) syncSelfIPv4(previous map[workerKey]bool, interfaces map[string]ipv4Interface, complete bool) map[workerKey]bool {
	own := w.registerSelfIPv4(interfaces)
	for key := range previous {
		if own[key] {
			continue
		}
		if complete {
			w.State.removeSelf(key.hw, key.addr, key.name)
		} else {
			own[key] = true
		}
	}
	return own
}

// readIPv4Table registers the neighbors of the kernel's table on the interfaces discovery runs
// on.
func (w *Worker) readIPv4Table(interfaces map[string]ipv4Interface) error {
	neighbors, err := arpTable()
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		if _, ok := interfaces[n.Interface]; !ok {
			continue
		}
		w.State.registerLocal(n.MAC, n.IP, n.Interface, w.config.Lifetime, nil)
	}
	return nil
}
