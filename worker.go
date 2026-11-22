package ipv6disc

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/arp"
	"github.com/miguelangel-nubla/ipv6disc/pkg/ndp"
	"github.com/miguelangel-nubla/ipv6disc/pkg/ping"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
	"github.com/miguelangel-nubla/ipv6disc/pkg/ssdp"
	"github.com/miguelangel-nubla/ipv6disc/pkg/wsd"
	"go.uber.org/zap"
)

type InvalidInterfaceError struct {
	iface *net.Interface
}

func (e *InvalidInterfaceError) Error() string {
	return fmt.Sprintf("invalid interface: %s", e.iface.Name)
}

type Worker struct {
	*State
	logger        *zap.SugaredLogger
	plugins       []Plugin
	protocolConns map[workerKey]*InterfaceProcesses
	workerCancels map[workerKey]context.CancelFunc
	// Of both maps. Taken before the State's locks, as when an address that went is removed, never
	// after: the expiration events, which ping, run with none of the State's held.
	pcMutex sync.RWMutex
	// The naming protocols of each interface, as the discovery's above, with the same lock; the
	// naming layer, which asks them; and what wakes the IPv4 discovery to read the neighbor
	// table, for an address heard of.
	nameConns   map[nameKey]*nameProcesses
	nameCancels map[nameKey]context.CancelFunc
	naming      *namer
	ipv4Wake    chan struct{}
	// What protocols saw of addresses whose MACs are being asked.
	causes causes
	// The naming protocols of no interface, as the reverse DNS, and the passive listeners of
	// the IPv4 discovery, by interface: with the same lock too.
	nameGlobal   []*NameProtocol
	arpListeners map[arpKey]*arp.Listener
	// What can't be heard, and was told so.
	unheard sync.Map
	// The goroutines Start starts, for Wait.
	running sync.WaitGroup
	started atomic.Bool

	config Config
}

// workerKey is what a discovery worker runs on: an address of an interface. The interface's index,
// name and MAC are part of it, not the address alone: an address can move to another interface, an
// interface made again has a new index, and its MAC can be changed, while the sockets of a worker,
// its multicast groups and the packets it takes are of the interface it started on, and the MAC it
// registers the address with, and solicits from, is the one it started with. Such a worker is
// stopped, and another started. The same address on two interfaces has a worker on each.
type workerKey struct {
	index int
	name  string
	addr  netip.Addr
	// The interface's MAC, as net.HardwareAddr.String: the state's key of it.
	hw string
}

func keyOf(iface *net.Interface, addr netip.Addr) workerKey {
	return workerKey{iface.Index, iface.Name, addr, iface.HardwareAddr.String()}
}

func (k workerKey) compare(other workerKey) int {
	return cmp.Or(cmp.Compare(k.index, other.index), cmp.Compare(k.name, other.name), k.addr.Compare(other.addr), cmp.Compare(k.hw, other.hw))
}

// diffWorkers tells the workers to start, those found that aren't running, and to stop, those
// running that weren't found, both sorted.
func diffWorkers[R, F any](running map[workerKey]R, found map[workerKey]F) (start, stop []workerKey) {
	for key := range found {
		if _, ok := running[key]; !ok {
			start = append(start, key)
		}
	}
	for key := range running {
		if _, ok := found[key]; !ok {
			stop = append(stop, key)
		}
	}
	slices.SortFunc(start, workerKey.compare)
	slices.SortFunc(stop, workerKey.compare)
	return start, stop
}

type worker interface {
	Stats() map[string]any
}

type DiscoveryProtocol struct {
	Name   string
	Worker worker
}

type InterfaceProcesses struct {
	InterfaceName string
	Address       netip.Addr
	Protocols     []*DiscoveryProtocol
}

// NewWorker makes a worker that discovers addresses as config says; Start runs it.
func NewWorker(logger *zap.SugaredLogger, config Config) *Worker {
	s := NewState()
	s.SetLogger(logger)
	s.SetFamilies(config.IPv6.Enabled, config.IPv4.Enabled)
	// The families' own lifetimes, as given: without, each registration's.
	s.SetLifetimes(config.IPv6.Lifetime, config.IPv4.Lifetime)
	// And the names', the same.
	s.SetNames(true, config.Hostnames.Lifetime)
	config = config.withDefaults()

	w := &Worker{
		State:         s,
		logger:        logger,
		config:        config,
		plugins:       make([]Plugin, 0),
		protocolConns: make(map[workerKey]*InterfaceProcesses),
		workerCancels: make(map[workerKey]context.CancelFunc),
		nameConns:     make(map[nameKey]*nameProcesses),
		nameCancels:   make(map[nameKey]context.CancelFunc),
		ipv4Wake:      make(chan struct{}, 1),
		arpListeners:  make(map[arpKey]*arp.Listener),
	}
	w.naming = newNamer(s, logger, config)
	w.naming.askers = w.nameProtocols
	return w
}

// RegisterPlugin adds a plugin for Start to run. It is for before Start, and not for concurrent
// use: a plugin added later is never started.
func (w *Worker) RegisterPlugin(p Plugin) {
	w.logger.Infof("registering plugin: %s", p.Name())
	w.plugins = append(w.plugins, p)
}

// Protocols returns the protocols of the local discovery that run, as the configuration names
// them and in the order of ProtocolNames: those enabled whose family is on, and listens, or for
// the sweep probes. PrettyPrintStats shows them first.
func (w *Worker) Protocols() []string {
	return w.config.running()
}

// PrettyPrintStats is StatsPage as text.
func (w *Worker) PrettyPrintStats(prefix string) string {
	return w.StatsPage(prefix).String()
}

// StatsPage is the page of what runs: the protocols, the counters of each on each interface, and
// those of the plugins.
func (w *Worker) StatsPage(prefix string) pretty.Page {
	var page pretty.Page
	heading := func(text, rest string) {
		page.Add(pretty.Span{Text: prefix}, pretty.As(pretty.Heading, text), pretty.Span{Text: rest})
	}

	// What the configuration runs, then what of it is running, on each interface.
	running := "none"
	if protocols := w.config.running(); len(protocols) > 0 {
		running = strings.Join(protocols, ", ")
	}
	heading("Protocols:", " "+running)
	heading("Protocol Workers:", "")
	w.pcMutex.RLock()
	// Group by interface
	ifaceMap := make(map[string][]*InterfaceProcesses)
	for _, ip := range w.protocolConns {
		ifaceMap[ip.InterfaceName] = append(ifaceMap[ip.InterfaceName], ip)
	}
	// The naming protocols are of the interface, not of an address of it.
	names := make(map[string][]*NameProtocol)
	for _, key := range slices.SortedFunc(maps.Keys(w.nameConns), nameKey.compare) {
		processes := w.nameConns[key]
		names[processes.InterfaceName] = append(names[processes.InterfaceName], processes.Protocols...)
		if _, ok := ifaceMap[processes.InterfaceName]; !ok {
			ifaceMap[processes.InterfaceName] = nil
		}
	}
	// And the passive listeners of the IPv4 discovery.
	ipv4 := make(map[string]*arp.Listener)
	for key, listener := range w.arpListeners {
		ipv4[key.name] = listener
		if _, ok := ifaceMap[key.name]; !ok {
			ifaceMap[key.name] = nil
		}
	}
	global := slices.Clone(w.nameGlobal)
	w.pcMutex.RUnlock()

	// Sort interface names
	ifaceNames := make([]string, 0, len(ifaceMap))
	for name := range ifaceMap {
		ifaceNames = append(ifaceNames, name)
	}
	sort.Strings(ifaceNames)

	printStats := func(name string, stats map[string]any) {
		var result strings.Builder
		fmt.Fprintf(&result, "%s            %-5s:", prefix, name)
		// Sort keys for consistent output
		sKeys := make([]string, 0, len(stats))
		for sk := range stats {
			sKeys = append(sKeys, sk)
		}
		sort.Strings(sKeys)
		for _, sk := range sKeys {
			fmt.Fprintf(&result, " %s=%v", sk, stats[sk])
		}
		page.Add(pretty.As(pretty.Detail, result.String()))
	}

	for _, name := range ifaceNames {
		page.Add(pretty.Span{Text: prefix + "    " + name + ":"})
		ips := ifaceMap[name]
		// Sort by IP within interface
		sort.Slice(ips, func(i, j int) bool {
			return ips[i].Address.String() < ips[j].Address.String()
		})

		for _, ip := range ips {
			page.Add(pretty.As(pretty.Detail, prefix+"        "+ip.Address.String()+":"))

			for _, p := range ip.Protocols {
				printStats(p.Name, p.Worker.Stats())
			}
		}
		if listener, ok := ipv4[name]; ok {
			page.Add(pretty.As(pretty.Detail, prefix+"        ipv4:"))
			printStats(ProtocolARPListen, listener.Stats())
		}
		if len(names[name]) > 0 {
			page.Add(pretty.As(pretty.Detail, prefix+"        names:"))
			for _, p := range names[name] {
				printStats(p.Name, p.Worker.Stats())
			}
		}
	}
	// The naming protocols of no interface.
	if len(global) > 0 {
		page.Add(pretty.Span{Text: prefix + "    names:"})
		for _, p := range global {
			printStats(p.Name, p.Worker.Stats())
		}
	}

	heading("Plugins:", "")
	for _, p := range w.plugins {
		stats := p.Stats()
		var result strings.Builder
		// Sort keys for consistent output
		sKeys := make([]string, 0, len(stats))
		for k := range stats {
			sKeys = append(sKeys, k)
		}
		sort.Strings(sKeys)
		for _, k := range sKeys {
			v := stats[k]
			if t, ok := v.(time.Time); ok {
				fmt.Fprintf(&result, " %s=%s", k, t.Format("15:04:05"))
			} else {
				fmt.Fprintf(&result, " %s=%v", k, v)
			}
		}
		page.Add(pretty.Span{Text: prefix + "    " + p.Name() + ":"}, pretty.As(pretty.Detail, result.String()))
	}

	return page
}

// Start runs the plugins and, when listening is enabled, the discovery on every interface address,
// which it keeps in step with the addresses the system has: by the protocols enabled, which the
// log names.
// The discovery stops when ctx is done: Wait waits for it to. A worker starts once: a second
// Start is an error, also after the first stopped.
func (w *Worker) Start(ctx context.Context) error {
	if err := w.config.validate(); err != nil {
		return err
	}
	if len(w.plugins) == 0 && !w.config.listensIPv6() && !w.config.listensIPv4() {
		return fmt.Errorf("no plugins configured and no local discovery: nothing to do")
	}
	if w.started.Swap(true) {
		return errors.New("worker already started")
	}
	for _, warning := range w.config.warnings() {
		w.logger.Warn(warning)
	}
	if protocols := w.config.running(); len(protocols) > 0 {
		w.logger.Infof("protocols of the local discovery: %s", strings.Join(protocols, ", "))
	} else {
		w.logger.Info("protocols of the local discovery: none")
	}

	for _, p := range w.plugins {
		w.running.Add(1)
		go func() {
			defer w.running.Done()
			err := p.Start(ctx, w.State, func(err error) {
				w.logger.Errorf("plugin %s error: %s", p.Name(), err)
			})
			if err != nil {
				w.logger.Errorf("plugin %s failed to start: %s", p.Name(), err)
			}
		}()
	}

	if w.config.listensIPv6() {
		w.running.Add(1)
		go func() {
			defer w.running.Done()
			ticker := time.NewTicker(interfaceCheckInterval)
			defer ticker.Stop()

			for {
				w.checkInterfaces(ctx)
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}

	if w.config.listensIPv4() {
		w.running.Add(1)
		go func() {
			defer w.running.Done()
			w.discoverIPv4(ctx)
		}()
	}

	// The protocols of the naming layer, after the discovery they need: on the interfaces it
	// runs on, for the families it listens over.
	if w.config.namesLocally() {
		w.naming.discover = func(iface string, addr netip.Addr) bool { return w.discoverAddr(ctx, iface, addr) }
		w.running.Add(1)
		go func() {
			defer w.running.Done()
			ticker := time.NewTicker(interfaceCheckInterval)
			defer ticker.Stop()

			for {
				w.checkNameInterfaces(ctx)
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	// And the layer itself, which has the discovery find what they heard of, and asks: the hosts
	// the local discovery found, and, by the DNS servers given, those the plugins did too.
	if w.config.naming() {
		w.startNameServers(ctx)
		w.running.Add(1)
		go func() {
			defer w.running.Done()
			w.naming.run(ctx)
		}()
	}

	return nil
}

// Wait returns once the discovery stopped, after the context of Start is done: the listeners are
// closed, and the plugins returned. The addresses of the State stay, and keep expiring, each with
// its goroutine, until State.Close.
func (w *Worker) Wait() {
	w.running.Wait()
}

// interfaceCheckInterval is how often the worker looks for interface addresses that came or went.
const interfaceCheckInterval = time.Minute

// Prefixes returns the /64 networks of the addresses being listened on, whatever the length of
// their prefix on the interface.
func (w *Worker) Prefixes() []netip.Prefix {
	w.pcMutex.RLock()
	defer w.pcMutex.RUnlock()

	seen := make(map[netip.Prefix]bool)
	var result []netip.Prefix
	for _, processes := range w.protocolConns {
		prefix := netip.PrefixFrom(processes.Address, 64).Masked()
		if !seen[prefix] {
			seen[prefix] = true
			result = append(result, prefix)
		}
	}
	return result
}

// Solicit sends a neighbor solicitation for target on the links that have its /64. If the address
// is there, its answer registers it as any other discovered address. It returns how many links it
// was sent on, one solicitation each, whatever addresses of the interface share the /64: an address
// that stays quiet is otherwise never found. A listener that fails is told in the error, also when
// another of the interface sent it.
func (w *Worker) Solicit(target netip.Addr) (int, error) {
	w.pcMutex.RLock()
	defer w.pcMutex.RUnlock()

	sent := 0
	interfaces := make(map[string]bool)
	var errs []error
	for _, processes := range w.protocolConns {
		if interfaces[processes.InterfaceName] || !netip.PrefixFrom(processes.Address, 64).Masked().Contains(target) {
			continue
		}
		for _, protocol := range processes.Protocols {
			conn, ok := protocol.Worker.(solicitor)
			if !ok {
				continue
			}
			if err := conn.SendNeighborSolicitation(&target); err != nil {
				errs = append(errs, err)
				continue
			}
			interfaces[processes.InterfaceName] = true
			sent++
		}
	}
	return sent, errors.Join(errs...)
}

// solicitor and pinger are what Solicit and the ping before an expiration need of a listener: the
// NDP and the ping connections.
type solicitor interface {
	SendNeighborSolicitation(target *netip.Addr) error
}

type pinger interface {
	SendPing(target *netip.Addr) error
}

// pingerFor returns the listener to ping target from, of those running on the interfaces that saw
// it, and what it listens on: one whose address shares the /64 of target if there is, the first in
// order otherwise. The listener is found when the ping is due, not kept from the registration:
// the worker that first saw an address can be gone, as when its own address was a temporary one,
// while others of the interface listen.
func pingerFor(conns map[workerKey]*InterfaceProcesses, interfaces []string, target netip.Addr) (pinger, *InterfaceProcesses) {
	var best *InterfaceProcesses
	var bestPinger pinger
	sameNet := func(p *InterfaceProcesses) bool {
		return netip.PrefixFrom(p.Address, 64).Masked().Contains(target.WithZone(""))
	}
	for _, key := range slices.SortedFunc(maps.Keys(conns), workerKey.compare) {
		processes := conns[key]
		if !slices.Contains(interfaces, processes.InterfaceName) {
			continue
		}
		for _, protocol := range processes.Protocols {
			if conn, ok := protocol.Worker.(pinger); ok && (best == nil || sameNet(processes) && !sameNet(best)) {
				best, bestPinger = processes, conn
			}
		}
	}
	return bestPinger, best
}

// pingBeforeExpiration pings an address before it expires: its answer keeps it. The state logs the
// expiration.
func (w *Worker) pingBeforeExpiration(expired *Addr, remainingEvents AddrExpirationRemainingEvents) {
	if remainingEvents == 0 || !expired.Is6() {
		return
	}
	target := expired.WithZone("")
	fields := []any{
		zap.String("ipv6", target.String()),
		zap.String("mac", expired.Hw.String()),
		zap.Int("remainingEvents", int(remainingEvents)),
	}

	w.pcMutex.RLock()
	conn, processes := pingerFor(w.protocolConns, expired.Interfaces(), target)
	w.pcMutex.RUnlock()
	if conn == nil {
		w.logger.Debugw("host not seen for a while, no listener on its interfaces to ping it from", fields...)
		return
	}
	fields = append(fields, zap.String("iface", processes.InterfaceName))
	w.logger.Debugw("host not seen for a while, pinging", fields...)

	if err := conn.SendPing(&target); errors.Is(err, net.ErrClosed) {
		// The listener stopped meanwhile: the next event finds another, if there is.
		w.logger.Debugw("ping not sent, the listener stopped", append(fields, zap.Error(err))...)
	} else if err != nil {
		w.logger.Errorw("ping failed", append(fields, zap.Error(err))...)
	}
}

func (w *Worker) checkInterfaces(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		w.logger.Errorf("error getting interfaces: %s", err)
		return
	}

	// The addresses there now, each with its interface.
	found := make(map[workerKey]net.Interface)

	for _, iface := range ifaces {
		if err := isValidInterface(&iface); err != nil || !w.config.usesInterface(iface.Name) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			w.logger.Errorf("error getting IPv6 addresses for interface %s: %s", iface.Name, err)
			continue
		}

		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipNet.IP)
			addr = addr.Unmap()
			// An interface with a link-local address only is not listened on.
			if !ok || addr.Is4() || addr.IsLinkLocalUnicast() {
				continue
			}
			found[keyOf(&iface, addr)] = iface
		}
	}

	w.syncWorkers(ctx, found, w.StartInterfaceAddr)
}

// syncWorkers starts a worker, run, on each address found that has none, and stops the workers of
// the others: of the addresses that went, and of those now on another interface, on one made
// again, or on one whose MAC changed. Those stop before the others start. An address its interface
// no longer has with that MAC leaves the state at once, not after its lifetime: it is not this
// machine's there any more. When only the index changed, it stays for the worker that follows.
func (w *Worker) syncWorkers(ctx context.Context, found map[workerKey]net.Interface, run func(context.Context, net.Interface, netip.Addr)) {
	w.pcMutex.Lock()
	defer w.pcMutex.Unlock()

	start, stop := diffWorkers(w.workerCancels, found)
	for _, key := range stop {
		w.logger.Infof("stopping discovery on %s %s", key.name, key.addr)
		w.workerCancels[key]()
		delete(w.workerCancels, key)
		// With the lock registerSelf takes: the worker stopped doesn't register it again.
		if !slices.ContainsFunc(start, func(s workerKey) bool { return s.name == key.name && s.addr == key.addr && s.hw == key.hw }) {
			w.State.removeSelf(key.hw, key.addr, key.name)
		}
	}
	for _, key := range start {
		ctx, cancel := context.WithCancel(ctx)
		w.workerCancels[key] = cancel
		w.logger.Debugf("starting discovery on %s %s", key.name, key.addr)
		// Wait is safe with it: the goroutine that checks the interfaces is itself counted.
		w.running.Add(1)
		go func() {
			defer w.running.Done()
			run(ctx, found[key], key.addr)
			// It also ends on a failure to listen: let the next check try again. Stopped, its
			// entry is gone, or is of the worker that took its place.
			w.pcMutex.Lock()
			if ctx.Err() == nil {
				delete(w.workerCancels, key)
			}
			w.pcMutex.Unlock()
			cancel()
		}()
	}
}

// StartInterfaceAddr runs the IPv6 discovery on an address of an interface until ctx is done: the
// protocols of it that are enabled, each with its listener, and the address itself, registered
// as this machine's. NDP tells the MACs, and asks the MAC of whatever the others hear.
func (w *Worker) StartInterfaceAddr(ctx context.Context, iface net.Interface, addr netip.Addr) {
	var err error
	var ndpConn *ndp.Conn
	var pingConn *ping.Conn
	var ssdpConn *ssdp.Conn
	var wsdConn *wsd.Conn

	processNDP := func(receivedAddr netip.Addr, receivedNetHardwareAddr net.HardwareAddr, way string) bool {
		_, existing := w.registerFound(receivedNetHardwareAddr, receivedAddr, Record{Protocol: ProtocolNDP, Way: Way(way), On: iface.Name}, w.pingBeforeExpiration)
		return !existing
	}

	// The errors of a protocol, and the failure to listen for it, which ends the worker.
	onError := func(protocol string) func(error) {
		return func(err error) {
			w.logger.Errorw(protocol+" error",
				zap.String("interface", iface.Name),
				zap.String("address", addr.String()),
				zap.Error(err),
			)
		}
	}
	listenFailed := func(protocol string, err error) {
		w.logger.Errorw("error listening for "+protocol,
			zap.String("interface", iface.Name),
			zap.String("address", addr.String()),
			zap.Error(err),
		)
	}
	processes := &InterfaceProcesses{InterfaceName: iface.Name, Address: addr}
	running := func(name string, conn worker) {
		processes.Protocols = append(processes.Protocols, &DiscoveryProtocol{Name: name, Worker: conn})
	}

	if w.config.runs(ProtocolNDP) {
		ndpConn, err = ndp.ListenForNDP(&iface, addr, processNDP, onError("NDP"))
		if err != nil {
			listenFailed("NDP", err)
			return
		}
		defer ndpConn.Close()
		running(ProtocolNDP, ndpConn)
	}

	// The other protocols only tell an address: a neighbor solicitation asks its MAC. They are
	// not enabled without NDP.
	if w.config.runs(ProtocolPing) {
		pingConn, err = ping.ListenForICMP(&iface, addr, w.onFoundAddrFunc(ndpConn, &iface, w.logger, ProtocolPing, "ICMP echo response"), onError("ICMP"))
		if err != nil {
			listenFailed("ICMP", err)
			return
		}
		defer pingConn.Close()
		running(ProtocolPing, pingConn)
	}

	// With their names, the two that follow also fetch the name of each host that answers their
	// probe, from that host: without, nothing is fetched.
	if w.config.runs(ProtocolSSDP) {
		if w.config.fetchesNames(ProtocolSSDP) {
			wants, named := w.nameFetches(NameSSDP, iface.Name)
			ssdpConn, err = ssdp.ListenForSSDPNames(&iface, addr, w.onFoundAddrFunc(ndpConn, &iface, w.logger, ProtocolSSDP, "SSDP announcement"), ssdp.Names{Wants: wants, Named: named}, onError("SSDP"))
		} else {
			ssdpConn, err = ssdp.ListenForSSDP(&iface, addr, w.onFoundAddrFunc(ndpConn, &iface, w.logger, ProtocolSSDP, "SSDP announcement"), onError("SSDP"))
		}
		if err != nil {
			listenFailed("SSDP", err)
			return
		}
		defer ssdpConn.Close()
		running(ProtocolSSDP, ssdpConn)
	}

	if w.config.runs(ProtocolWSD) {
		if w.config.fetchesNames(ProtocolWSD) {
			wants, named := w.nameFetches(NameWSD, iface.Name)
			wsdConn, err = wsd.ListenForWSDNames(&iface, addr, w.onFoundAddrFunc(ndpConn, &iface, w.logger, ProtocolWSD, "WSD message"), wsd.Names{Wants: wants, Named: named}, onError("WSD"))
		} else {
			wsdConn, err = wsd.ListenForWSD(&iface, addr, w.onFoundAddrFunc(ndpConn, &iface, w.logger, ProtocolWSD, "WSD message"), onError("WSD"))
		}
		if err != nil {
			listenFailed("WSD", err)
			return
		}
		defer wsdConn.Close()
		running(ProtocolWSD, wsdConn)
	}

	key := keyOf(&iface, addr)
	w.pcMutex.Lock()
	w.protocolConns[key] = processes
	w.pcMutex.Unlock()
	defer func() {
		w.pcMutex.Lock()
		// Unless a new worker for the same address replaced it already.
		if w.protocolConns[key] == processes {
			delete(w.protocolConns, key)
		}
		w.pcMutex.Unlock()
	}()

	// Stopped while it started: nothing to register, nor to probe.
	if ctx.Err() != nil {
		return
	}

	// The address is this machine's for as long as the worker runs: it is registered again well
	// within its lifetime, whatever the interval of the probes, as nothing else refreshes it.
	// Not once stopped, which syncWorkers does with the lock, before it takes out of the state the
	// address that went.
	registerSelf := func() {
		w.pcMutex.RLock()
		defer w.pcMutex.RUnlock()
		if ctx.Err() != nil {
			return
		}
		w.State.RegisterSelf(iface.HardwareAddr, addr, iface.Name, temporaryAddrs()[addr], w.config.Lifetime, w.pingBeforeExpiration)
	}
	probe := func() {
		if !w.config.probesIPv6() || pingConn == nil && ssdpConn == nil && wsdConn == nil {
			return
		}

		w.logger.Infof("active discovery started on %s %s", iface.Name, addr.String())
		if pingConn != nil {
			startMulticast("PING", pingConn.DiscoverMulticast, pingConn.GetListenAddr().String(), w.logger)
		}
		if ssdpConn != nil {
			startMulticast("SSDP", ssdpConn.DiscoverMulticast, ssdpConn.GetListenAddrPort().String(), w.logger)
		}
		if wsdConn != nil {
			startMulticast("WSD", wsdConn.DiscoverMulticast, wsdConn.GetListenAddrPort().String(), w.logger)
		}
	}

	// Bootstrap discovery
	registerSelf()
	probe()

	// Periodic re-discovery
	ticker := time.NewTicker(w.config.Rediscover)
	defer ticker.Stop()
	selfTicker := time.NewTicker(w.config.selfRefresh())
	defer selfTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-selfTicker.C:
			registerSelf()
		case <-ticker.C:
			probe()
		}
	}
}

// isValidInterface tells whether the IPv6 discovery can run on the interface: up, multicast, not a
// loopback, and with a MAC. Without one, as PPP and the tunnels, NDP tells no MAC and a
// solicitation can't be sent, and the interface's own addresses would be of no host.
func isValidInterface(iface *net.Interface) error {
	if iface.Flags&net.FlagUp != 0 &&
		iface.Flags&net.FlagMulticast != 0 &&
		iface.Flags&net.FlagLoopback == 0 &&
		len(iface.HardwareAddr) > 0 {
		return nil
	}
	return &InvalidInterfaceError{iface}
}

// onFoundAddrFunc returns the callback for the addresses a protocol hears from, which answered its
// probe: it asks their MAC, as only NDP tells it, and ignores the interface's own addresses. The
// answer is a record of the protocol's, once the MAC is known.
func (w *Worker) onFoundAddrFunc(ndpConn *ndp.Conn, iface *net.Interface, logger *zap.SugaredLogger, protocol, logString string) func(remoteIP netip.Addr) bool {
	return func(remoteIP netip.Addr) bool {
		if addrs, err := iface.Addrs(); err == nil {
			for _, a := range addrs {
				if ipNet, ok := a.(*net.IPNet); ok {
					if addr, ok := netip.AddrFromSlice(ipNet.IP); ok && addr.Unmap() == remoteIP.WithZone("") {
						return false
					}
				}
			}
		}

		logger.Debugw(logString+" received",
			zap.String("remote", remoteIP.String()),
			zap.String("interface", iface.Name),
		)
		w.saw(iface.Name, remoteIP, protocol, Answered, nil)
		if err := ndpConn.SendNeighborSolicitation(&remoteIP); err != nil {
			logger.Debugw("neighbor solicitation failed",
				zap.String("remote", remoteIP.String()),
				zap.String("interface", iface.Name),
				zap.Error(err),
			)
		}
		return true
	}
}

// startMulticast runs a protocol's multicast discovery. A failure, as when the interface goes away,
// is only logged: the next run tries again.
func startMulticast(protocol string, discover func() error, listener string, logger *zap.SugaredLogger) {
	logger.Debugw(protocol+" discover multicast", zap.String("listener", listener))

	if err := discover(); err != nil {
		logger.Errorw(protocol+" discover multicast failed",
			zap.String("listener", listener),
			zap.Error(err),
		)
	}
}
