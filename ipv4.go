package ipv6disc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/arp"
	"go.uber.org/zap"
)

// arpTable reads the kernel's IPv4 neighbor table, and arpSettle says how long after a sweep it has
// the answers: variables for the tests.
var (
	arpTable  = arp.Table
	arpSettle = arp.Settle
)

// discoverIPv4 reads the kernel's IPv4 neighbor table every interfaceCheckInterval and, with active
// discovery, sweeps the local subnets at every rediscovery first, so that the hosts there that
// stay quiet are in it too: each of the three when its protocol is enabled, arp, arp-sweep, and
// arp-listen for the ARP heard. Each time it registers the interfaces' own addresses, and takes
// out those they no longer have, which is all it does where the system has no table to read:
// nothing is swept there. The naming layer has it read the table sooner, for an address it heard of. It
// returns when ctx is done.
func (w *Worker) discoverIPv4(ctx context.Context) {
	ticker := time.NewTicker(interfaceCheckInterval)
	defer ticker.Stop()

	// The table, when it is to be read: asked before the first sweep, which is for it.
	neighbors := w.config.runs(ProtocolARP)
	if neighbors {
		_, err := arpTable()
		neighbors = !w.tableUnsupported(err)
	}

	// The ARP of the interfaces is heard too, when it is to be, where the system lets it be:
	// until it is known not to.
	passive := w.config.runs(ProtocolARPListen)
	defer w.stopARPListeners()

	var lastSweep time.Time
	own := make(map[workerKey]bool)
	for {
		// The start of the sweep this reading follows, if it follows one.
		var swept time.Time
		// Swept for what tells the answers: the table, or the ARP heard.
		if (neighbors || passive) && w.config.runs(ProtocolARPSweep) && time.Since(lastSweep) >= w.config.Rediscover {
			// Without the table, the answers are told by the ARP heard alone: from before the
			// sweep, then, not from the reading after it, as there is none.
			if passive && !neighbors {
				interfaces, err := w.listIPv4Interfaces()
				passive = w.syncARPListeners(ctx, interfaces, err == nil)
			}
			lastSweep = time.Now()
			swept = lastSweep
			settle := w.sweepIPv4(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(settle):
			}
		}

		interfaces, err := w.listIPv4Interfaces()
		own = w.syncSelfIPv4(own, interfaces, err == nil)
		if passive {
			passive = w.syncARPListeners(ctx, interfaces, err == nil)
		}
		if neighbors {
			if err := w.readIPv4Table(interfaces, swept); w.tableUnsupported(err) {
				neighbors = false
			} else if err != nil {
				w.logger.Errorf("IPv4 discovery: %s", err)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-w.ipv4Wake:
			// An address heard of, by the naming layer, which had the kernel resolve it: read
			// once it has, and those heard of meanwhile with it.
			select {
			case <-ctx.Done():
				return
			case <-time.After(ipv4WakeSettle):
			}
		}
	}
}

// arpKey is what a passive ARP listener runs on: an interface, and the subnets it has there,
// whose hosts are the ones it takes. When any changes it stops, and another starts.
type arpKey struct {
	index    int
	name, hw string
	prefixes string
}

// syncARPListeners has the ARP of each interface the IPv4 discovery runs on heard, and stops the
// listeners of those that went or changed: not when the interfaces aren't all known, complete.
// What a host sends tells it at once: its address at its MAC, registered as the neighbor
// table's are, which otherwise wait for the kernel to talk to the host and for the next reading.
// It returns whether to try again: not where the system has no packet sockets, nor without the
// privilege for them, which is told once. The table is read as before, with or without.
func (w *Worker) syncARPListeners(ctx context.Context, interfaces map[string]ipv4Interface, complete bool) bool {
	if ctx.Err() != nil {
		return false
	}
	found := make(map[arpKey]ipv4Interface)
	for name, i := range interfaces {
		found[arpKey{i.iface.Index, name, i.iface.HardwareAddr.String(), fmt.Sprint(i.prefixes)}] = i
	}
	w.pcMutex.Lock()
	defer w.pcMutex.Unlock()
	for key, listener := range w.arpListeners {
		if _, ok := found[key]; !ok && complete {
			listener.Close()
			delete(w.arpListeners, key)
		}
	}
	for key, i := range found {
		if _, ok := w.arpListeners[key]; ok {
			continue
		}
		iface := i.iface
		listener, err := arp.Listen(&iface, w.heardARP(i), func(err error) {
			w.logger.Errorw("ARP error", zap.String("interface", iface.Name), zap.Error(err))
		})
		if errors.Is(err, errors.ErrUnsupported) {
			w.logger.Debugf("not listening for ARP: %s", err)
			return false
		}
		if errors.Is(err, os.ErrPermission) {
			w.logger.Warnf("not listening for ARP, which needs CAP_NET_RAW: the IPv4 hosts are found by the neighbor table alone, at each reading: %s", err)
			return false
		}
		if err != nil {
			// As an interface that went meanwhile: the next time tries again.
			w.logger.Errorw("error listening for ARP", zap.String("interface", iface.Name), zap.Error(err))
			continue
		}
		w.arpListeners[key] = listener
	}
	return true
}

// arpNewMost is how many hosts the ARP heard on an interface may tell that the state didn't have,
// in an interfaceCheckInterval: the kernel's table has a bound too, and takes only the answers to
// what it asked. A link where frames are made up, each from another MAC, fills no more than this:
// those over it wait for the table, as all did.
const arpNewMost = 1024

// heardARP is what is done of the sender of an ARP packet heard on an interface: registered, as
// a neighbor of the table is, when it is a host of a subnet of the interface, and not the
// interface itself: its address, or its MAC, in a frame of another's. Nor the address of the
// subnet itself, or its broadcast one, which the kernel resolves for nobody and so never had in
// its table. It returns whether it is a host found.
func (w *Worker) heardARP(i ipv4Interface) func(netip.Addr, net.HardwareAddr) bool {
	name, own, prefixes := i.iface.Name, i.iface.HardwareAddr.String(), i.prefixes
	// The listener calls it from its one reading.
	var since time.Time
	found := 0
	return func(ip netip.Addr, mac net.HardwareAddr) bool {
		if !slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return hostOf(p, ip) }) ||
			slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Addr() == ip }) || mac.String() == own {
			return false
		}
		if !w.State.has(mac, ip, name) {
			if now := time.Now(); now.Sub(since) >= interfaceCheckInterval {
				since, found = now, 0
			}
			if found >= arpNewMost {
				return false
			}
			found++
		}
		_, existing := w.State.registerLocal(mac, ip, name, w.config.Lifetime, nil)
		return !existing
	}
}

// hostOf tells whether ip can be a host's of the subnet of an interface's address: in it, and
// neither its first address, the subnet's own, nor its last, which is all its hosts, where it
// has those: a subnet of two addresses, or one, has only hosts.
func hostOf(subnet netip.Prefix, ip netip.Addr) bool {
	if !subnet.Contains(ip) {
		return false
	}
	if subnet.Bits() >= 31 {
		return true
	}
	bits := ip.As4()
	host := binary.BigEndian.Uint32(bits[:]) & (1<<(32-subnet.Bits()) - 1)
	return host != 0 && host != 1<<(32-subnet.Bits())-1
}

// stopARPListeners closes the passive ARP listeners, as the IPv4 discovery stops.
func (w *Worker) stopARPListeners() {
	w.pcMutex.Lock()
	defer w.pcMutex.Unlock()
	for key, listener := range w.arpListeners {
		listener.Close()
		delete(w.arpListeners, key)
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
			// What the state had of it before it was asked: an address it answers for is found
			// if it wasn't there then, whether this registers it or what hears its answer on
			// the interface did, a moment sooner.
			known := make(map[netip.Addr]bool)
			for _, addr := range w.State.FilterMACs([]net.HardwareAddr{target.MAC}).Get() {
				known[addr.WithZone("")] = true
			}
			addrs, err := arp.Probe(ctx, &p.iface.iface, p.local.Addr(), target.MAC, p.asked)
			// What was found before an error counts too.
			for _, ip := range addrs {
				w.State.registerLocal(target.MAC, ip, p.name, w.config.Lifetime, nil)
				if !known[ip] {
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
			if asked := probeTargets(local, target.Prefixes, w.config.sweepPrefix()); len(asked) > 0 {
				probes = append(probes, ipv4Probe{name: name, iface: i, local: local, asked: asked})
			}
		}
	}
	return probes
}

// probeTargets returns the addresses of the subnet of local to ask, in one of the prefixes: without
// prefixes, those a sweep would ask, of a subnet no larger than a /maxPrefix.
func probeTargets(local netip.Prefix, prefixes []netip.Prefix, maxPrefix int) []netip.Addr {
	if len(prefixes) == 0 {
		return arp.SweepTargetsWithin(local, maxPrefix)
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

// sweepIPv4 sweeps the subnets of the interfaces discovery runs on, and returns how long the table
// then takes to have the answers: the longest of the interfaces swept.
func (w *Worker) sweepIPv4(ctx context.Context) time.Duration {
	settle := time.Duration(0)
	for _, i := range w.ipv4Interfaces() {
		if len(i.prefixes) > 0 {
			settle = max(settle, arpSettle(i.iface.Name))
		}
		for _, prefix := range i.prefixes {
			targets := arp.SweepTargetsWithin(prefix, w.config.sweepPrefix())
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
	return settle
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
// on. Those the kernel confirmed since swept, the start of the sweep the reading follows, are
// there now: seen as they are read. The others, where the table says when the kernel last
// confirmed them, as seen then, so that an entry it is still to check, of a host that left,
// extends nothing.
func (w *Worker) readIPv4Table(interfaces map[string]ipv4Interface, swept time.Time) error {
	neighbors, err := arpTable()
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		if _, ok := interfaces[n.Interface]; !ok {
			continue
		}
		if n.Confirmed.IsZero() || !swept.IsZero() && !n.Confirmed.Before(swept) || !n.Confirmed.Before(time.Now()) {
			w.State.registerLocal(n.MAC, n.IP, n.Interface, w.config.Lifetime, nil)
		} else {
			w.State.registerLocalSeen(n.MAC, n.IP, n.Interface, w.config.Lifetime, n.Confirmed)
		}
	}
	return nil
}
