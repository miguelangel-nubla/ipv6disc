package ipv6disc

import (
	"cmp"
	"context"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/arp"
	"github.com/miguelangel-nubla/ipv6disc/pkg/mdns"
	"go.uber.org/zap"
)

// The naming layer learns the names of the hosts the discovery found. A protocol of it, on an
// interface, is a nameAsker: given a host's address, it asks its name. The answer comes when it
// comes, if it does, as a name registered in the State: the layer only decides whom to ask, and
// when. mDNS is the first; what follows, as NetBIOS, LLMNR or the reverse DNS, plugs in the same.
type nameAsker interface {
	// Asks tells whether the protocol can ask the host at addr, on its interface: its family, and
	// an address it reaches.
	Asks(addr netip.Addr) bool
	// AskName asks the host at addr its name, without waiting for the answer.
	AskName(addr netip.Addr) error
	Stats() map[string]any
}

// NameProtocol is a protocol of the naming layer running on an interface.
type NameProtocol struct {
	Name   string
	Worker nameAsker
}

// nameProcesses are the protocols of the naming layer on an interface.
type nameProcesses struct {
	InterfaceName string
	Protocols     []*NameProtocol
}

// nameKey is what the naming protocols of an interface run on: the interface, as a workerKey has
// it, and the families they listen over there. When any changes they stop, and start anew.
type nameKey struct {
	index      int
	name, hw   string
	ipv4, ipv6 bool
}

func (k nameKey) compare(other nameKey) int {
	return cmp.Or(cmp.Compare(k.index, other.index), cmp.Compare(k.name, other.name), cmp.Compare(k.hw, other.hw))
}

const (
	// nameSource is the source of the names mDNS tells.
	nameSource = "mdns"
	// namingRate bounds the hosts asked their name in a second, by all the protocols.
	namingRate = 10
	// How long what was heard waits for the discovery to tell the MAC of its address, and how
	// many of them wait at most.
	namingPatience = 30 * time.Second
	namingPending  = 256
	// How long an address the discovery was asked to find isn't asked for again.
	namingSolicitEvery = 5 * time.Second
	// How long the changes of the state are let come before they are looked at, together.
	namingSettle = 100 * time.Millisecond
)

// namer is the naming layer of a worker: whom to ask, and whose name is what was heard.
//
// A name is a host's, and a host is its MAC, which no name protocol tells: what is heard comes
// from an address. So a name goes to the MAC the State has that address at, which only the
// discovery put there: NDP, or the kernel's neighbor table. An address the State doesn't have
// yet is asked of the discovery, and what it said waits for it. A record is never taken as the
// address of whoever sent it.
type namer struct {
	state      *State
	logger     *zap.SugaredLogger
	lifetime   time.Duration
	rediscover time.Duration
	// The protocols running on an interface, and what has the discovery find the MAC of an
	// address heard on one: it tells whether it asked.
	askers   func(iface string) []nameAsker
	discover func(iface string, addr netip.Addr) bool
	now      func() time.Time

	mutex sync.Mutex
	// When each host, by MAC, was last asked its name, and at which address.
	asked map[string]asking
	// The names said that wait for the MAC of their addresses.
	claims []claim
	// The addresses heard of that the State doesn't have, and when the discovery was asked.
	wanted map[wantKey]want
	// The second the rate counts in, and how many were asked in it.
	second time.Time
	sent   int
}

type asking struct {
	at   time.Time
	addr netip.Addr
	// Whether it answered there: it is asked there again. A host doesn't answer at all its
	// addresses: over one family only, or not for a link-local address it doesn't publish.
	answered bool
}

// claim is what a host said: from, on iface, that name has addr.
type claim struct {
	iface string
	from  netip.Addr
	name  string
	addr  netip.Addr
	at    time.Time
}

type wantKey struct {
	iface string
	addr  netip.Addr
}

type want struct {
	// When it was first heard of, and when the discovery was last asked for it: zero if it
	// couldn't be.
	since, solicited time.Time
}

func newNamer(state *State, logger *zap.SugaredLogger, config Config) *namer {
	return &namer{
		state:      state,
		logger:     logger,
		lifetime:   config.Hostnames.Lifetime,
		rediscover: config.Rediscover,
		now:        time.Now,
		asked:      make(map[string]asking),
		wanted:     make(map[wantKey]want),
	}
}

// heard is for an address something was heard from, on iface: a host of the link. One the State
// doesn't have is asked of the discovery, which tells its MAC. It returns whether it is new.
func (n *namer) heard(iface string, from netip.Addr) bool {
	if _, known := n.state.macOf(from, iface); known {
		return false
	}
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.want(iface, from)
}

// want asks the discovery for an address the State doesn't have, unless it was asked a moment
// ago. It returns whether the address was not waited for already. With the mutex held.
func (n *namer) want(iface string, addr netip.Addr) bool {
	key := wantKey{iface, addr}
	now := n.now()
	w, waiting := n.wanted[key]
	if !waiting {
		if len(n.wanted) >= namingPending {
			return false
		}
		w.since = now
	}
	if w.solicited.IsZero() || now.Sub(w.solicited) >= namingSolicitEvery {
		if n.discover(iface, addr) {
			w.solicited = now
		}
	}
	n.wanted[key] = w
	return !waiting
}

// said is for a record of a response heard on iface: from says name has addr, which onLink tells
// to be of the link. The name is of the host that sent it only if addr is that host's own: the
// address it sent from, or another the State has at the same MAC. A response can carry the
// records of other hosts, as a proxy's, and those name nobody here: not their sender, whose
// addresses they aren't, nor the host of their address, which didn't say them.
//
// An address of the link the State doesn't have is asked of the discovery: if a host has it, it
// is registered at the MAC that answers for it, whatever the record said.
func (n *namer) said(iface string, from netip.Addr, name string, addr netip.Addr, onLink bool) {
	if _, ok := CleanName(name); !ok {
		return
	}
	c := claim{iface: iface, from: from, name: name, addr: addr, at: n.now()}
	if n.settle(c) {
		return
	}
	n.mutex.Lock()
	defer n.mutex.Unlock()
	if _, known := n.state.macOf(addr, iface); !known && onLink && addr != from {
		n.want(iface, addr)
	}
	if len(n.claims) >= namingPending || slices.ContainsFunc(n.claims, func(o claim) bool {
		return o.iface == c.iface && o.from == c.from && o.name == c.name && o.addr == c.addr
	}) {
		return
	}
	n.claims = append(n.claims, c)
}

// settle registers the name of a claim, if the State tells it is its sender's: it returns whether
// it is settled. One that isn't waits, as the addresses may be on their way to the State.
func (n *namer) settle(c claim) bool {
	sender, ok := n.state.macOf(c.from, c.iface)
	if !ok {
		return false
	}
	if c.addr != c.from {
		owner, ok := n.state.macOf(c.addr, c.iface)
		if !ok {
			return false
		}
		if owner.String() != sender.String() {
			// Another host's record: it names nobody.
			return true
		}
	}
	n.state.RegisterName(sender, c.name, nameSource, n.lifetime)
	return true
}

// answered is for the answer of the host asked at an address, on iface: its name, which goes to
// the MAC the State has that address at. The question went to that address alone, so whatever
// answered it has it.
func (n *namer) answered(iface string, asked netip.Addr, name string) {
	hw, ok := n.state.macOf(asked, iface)
	if !ok {
		return
	}
	if clean, _ := n.state.RegisterName(hw, name, nameSource, n.lifetime); clean == "" {
		return
	}
	n.mutex.Lock()
	defer n.mutex.Unlock()
	if last, ok := n.asked[hw.String()]; ok && last.addr == asked {
		last.answered = true
		n.asked[hw.String()] = last
	}
}

// resolve looks again at what waits for the discovery: the names said, now that the State may
// have their addresses, and the addresses the discovery couldn't be asked for, as before the
// listener of their interface started. What waited too long is dropped.
func (n *namer) resolve() {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	now := n.now()

	n.claims = slices.DeleteFunc(n.claims, func(c claim) bool {
		return n.settle(c) || now.Sub(c.at) > namingPatience
	})
	for key, w := range n.wanted {
		if _, known := n.state.macOf(key.addr, key.iface); known || now.Sub(w.since) > namingPatience {
			delete(n.wanted, key)
		} else if w.solicited.IsZero() {
			n.want(key.iface, key.addr)
		}
	}
}

// lookups asks the hosts that have no name their name, and those whose names are about to
// expire, as the addresses are pinged before they do: each once in a rediscovery interval at
// most, and namingRate of them in a second. A host whose name keeps being said, by itself or by
// a plugin, is never asked. It returns whether hosts are left to ask, for the second that
// follows.
func (n *namer) lookups() (backlog bool) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	now := n.now()

	hosts := n.state.GetAll()
	names := n.state.AllNames()
	for mac := range n.asked {
		if _, ok := hosts[mac]; !ok {
			delete(n.asked, mac)
		}
	}
	for _, mac := range slices.Sorted(maps.Keys(hosts)) {
		if n.named(names[mac], now) {
			continue
		}
		// Once in a rediscovery interval: a little less than one after the last time, so that the
		// look of each interval, which comes a moment sooner or later, finds it due.
		last := n.asked[mac]
		if !last.at.IsZero() && now.Sub(last.at) < n.rediscover-n.rediscover/10 {
			continue
		}
		candidates := n.candidates(hosts[mac])
		if len(candidates) == 0 {
			continue
		}
		if now.Sub(n.second) >= time.Second {
			n.second, n.sent = now, 0
		}
		if n.sent >= namingRate {
			return true
		}
		n.sent++
		// Where it answered the last time, or at the address after the one that it didn't at.
		i := slices.IndexFunc(candidates, func(c candidate) bool { return c.addr == last.addr })
		if i < 0 {
			i = 0
		} else if !last.answered {
			i = (i + 1) % len(candidates)
		}
		c := candidates[i]
		n.asked[mac] = asking{at: now, addr: c.addr}
		fields := []any{zap.String("ip", c.addr.String()), zap.String("mac", mac), zap.String("interface", c.iface)}
		if err := c.asker.AskName(c.addr); err != nil {
			n.logger.Debugw("host not asked its name", append(fields, zap.Error(err))...)
		} else {
			n.logger.Debugw("host asked its name", fields...)
		}
	}
	return false
}

// named tells whether a host has a name that stays for a while yet: longer than three
// rediscovery intervals, so that it is asked again in time, and again where it doesn't answer
// at once, or than half its lifetime when that is shorter.
func (n *namer) named(names []HostName, now time.Time) bool {
	for _, name := range names {
		if name.Expiration.Sub(now) > min(3*n.rediscover, name.Expiration.Sub(name.Seen)/2) {
			return true
		}
	}
	return false
}

// candidate is an address a host can be asked its name at, and what asks it.
type candidate struct {
	iface string
	addr  netip.Addr
	asker nameAsker
}

// candidates are the ways to ask a host its name: each of its addresses a local interface saw,
// by each protocol of that interface that asks it. The IPv4 ones first, which more devices
// answer mDNS over, and the link-local ones last, which a responder may not publish. None for
// this machine: it is no host to ask.
func (n *namer) candidates(collection *AddrCollection) []candidate {
	var result []candidate
	addrs := collection.Get()
	rank := func(a *Addr) int {
		switch {
		case a.Is4():
			return 0
		case !a.IsLinkLocalUnicast():
			return 1
		}
		return 2
	}
	slices.SortStableFunc(addrs, func(a, b *Addr) int { return cmp.Compare(rank(a), rank(b)) })
	for _, addr := range addrs {
		if addr.Self() {
			return nil
		}
		if !addr.Valid() {
			continue
		}
		ip := addr.WithZone("")
		for _, iface := range addr.Interfaces() {
			for _, asker := range n.askers(iface) {
				if asker.Asks(ip) {
					result = append(result, candidate{iface, ip, asker})
				}
			}
		}
	}
	return result
}

// run looks at what waits, and asks, after each change of the state, as a host found, at every
// rediscovery, and every second while hosts are left to ask, until ctx is done.
func (n *namer) run(ctx context.Context) {
	changes, cancel := n.state.Subscribe()
	defer cancel()
	ticker := time.NewTicker(n.rediscover)
	defer ticker.Stop()

	for {
		n.resolve()
		var again <-chan time.Time
		if n.lookups() {
			again = time.After(time.Second)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-again:
		case <-changes:
			select {
			case <-ctx.Done():
				return
			case <-time.After(namingSettle):
			}
		}
	}
}

// nameAskers returns the naming protocols running on the interface of that name.
func (w *Worker) nameAskers(iface string) []nameAsker {
	w.pcMutex.RLock()
	defer w.pcMutex.RUnlock()
	var askers []nameAsker
	for _, key := range slices.SortedFunc(maps.Keys(w.nameConns), nameKey.compare) {
		if key.name != iface {
			continue
		}
		for _, protocol := range w.nameConns[key].Protocols {
			askers = append(askers, protocol.Worker)
		}
	}
	return askers
}

// discoverAddr has the discovery find the MAC of an address heard on an interface, as it finds
// any: an IPv6 one by a neighbor solicitation of a listener of the interface; an IPv4 one by a
// packet to its discard port, as the sweep's, which has the kernel resolve it, and a reading of
// the neighbor table once it has. It returns whether it asked: not without a listener there yet.
func (w *Worker) discoverAddr(ctx context.Context, iface string, addr netip.Addr) bool {
	if addr.Is6() {
		if !w.config.listensIPv6() {
			return false
		}
		w.pcMutex.RLock()
		defer w.pcMutex.RUnlock()
		for _, key := range slices.SortedFunc(maps.Keys(w.protocolConns), workerKey.compare) {
			processes := w.protocolConns[key]
			if processes.InterfaceName != iface {
				continue
			}
			for _, protocol := range processes.Protocols {
				if conn, ok := protocol.Worker.(solicitor); ok && conn.SendNeighborSolicitation(&addr) == nil {
					return true
				}
			}
		}
		return false
	}

	if !w.config.listensIPv4() {
		return false
	}
	for _, local := range w.ipv4Interfaces()[iface].prefixes {
		if !local.Contains(addr) {
			continue
		}
		if err := arp.Sweep(ctx, local.Addr(), []netip.Addr{addr}); err != nil {
			return false
		}
		select {
		case w.ipv4Wake <- struct{}{}:
		default:
		}
		return true
	}
	return false
}

// ipv4WakeSettle is how long after an IPv4 address was heard of the neighbor table is read: the
// kernel has resolved it by then, if a host has it.
const ipv4WakeSettle = time.Second

// checkNameInterfaces starts the naming protocols on the interfaces the local discovery runs on,
// for the families it listens over on each, and stops those of the interfaces that went or
// changed: an interface as the IPv6 discovery takes it, with an address that isn't link-local,
// and as the IPv4 one does.
func (w *Worker) checkNameInterfaces(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		w.logger.Errorf("error getting interfaces: %s", err)
		return
	}
	var ipv4 map[string]ipv4Interface
	if w.config.listensIPv4() {
		ipv4 = w.ipv4Interfaces()
	}

	found := make(map[nameKey]net.Interface)
	for _, iface := range ifaces {
		if isValidInterface(&iface) != nil || !w.config.usesInterface(iface.Name) {
			continue
		}
		key := nameKey{index: iface.Index, name: iface.Name, hw: iface.HardwareAddr.String()}
		_, key.ipv4 = ipv4[iface.Name]
		if addrs, err := iface.Addrs(); err == nil && w.config.listensIPv6() {
			key.ipv6 = slices.ContainsFunc(addrs, func(a net.Addr) bool {
				ipNet, ok := a.(*net.IPNet)
				if !ok {
					return false
				}
				addr, ok := netip.AddrFromSlice(ipNet.IP)
				addr = addr.Unmap()
				return ok && addr.Is6() && !addr.IsLinkLocalUnicast()
			})
		}
		if key.ipv4 || key.ipv6 {
			found[key] = iface
		}
	}

	w.pcMutex.Lock()
	defer w.pcMutex.Unlock()
	for key, cancel := range w.nameCancels {
		if _, ok := found[key]; !ok {
			w.logger.Infof("stopping name discovery on %s", key.name)
			cancel()
			delete(w.nameCancels, key)
		}
	}
	for _, key := range slices.SortedFunc(maps.Keys(found), nameKey.compare) {
		if _, ok := w.nameCancels[key]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(ctx)
		w.nameCancels[key] = cancel
		w.running.Add(1)
		go func() {
			defer w.running.Done()
			w.startInterfaceNames(ctx, found[key], key)
			// As a discovery worker: one that failed to listen is tried again at the next check.
			w.pcMutex.Lock()
			if ctx.Err() == nil {
				delete(w.nameCancels, key)
			}
			w.pcMutex.Unlock()
			cancel()
		}()
	}
}

// startInterfaceNames runs the naming protocols on an interface until ctx is done: mDNS, which
// also probes, at every rediscovery, with the other probes.
func (w *Worker) startInterfaceNames(ctx context.Context, iface net.Interface, key nameKey) {
	fields := []any{zap.String("interface", iface.Name)}
	conn, err := mdns.Listen(&iface, mdns.Options{
		IPv4: key.ipv4, IPv6: key.ipv6,
		ActiveIPv4: w.config.probesIPv4(), ActiveIPv6: w.config.probesIPv6(),
	}, mdns.Handler{
		Heard: func(from netip.Addr) bool { return w.naming.heard(iface.Name, from) },
		Said: func(from netip.Addr, name string, addr netip.Addr, onLink bool) {
			w.naming.said(iface.Name, from, name, addr, onLink)
		},
		Answered: func(asked netip.Addr, name string) { w.naming.answered(iface.Name, asked, name) },
		Error: func(err error) {
			w.logger.Errorw("mDNS error", append(fields, zap.Error(err))...)
		},
	})
	if err != nil {
		w.logger.Errorw("error listening for mDNS", append(fields, zap.Error(err))...)
		return
	}
	defer conn.Close()

	processes := &nameProcesses{InterfaceName: iface.Name, Protocols: []*NameProtocol{{Name: "mdns", Worker: conn}}}
	w.pcMutex.Lock()
	w.nameConns[key] = processes
	w.pcMutex.Unlock()
	defer func() {
		w.pcMutex.Lock()
		if w.nameConns[key] == processes {
			delete(w.nameConns, key)
		}
		w.pcMutex.Unlock()
	}()

	probe := func() {
		if w.config.probesIPv4() && key.ipv4 || w.config.probesIPv6() && key.ipv6 {
			startMulticast("mDNS", conn.DiscoverMulticast, iface.Name, w.logger)
		}
	}
	probe()
	ticker := time.NewTicker(w.config.Rediscover)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probe()
		}
	}
}
