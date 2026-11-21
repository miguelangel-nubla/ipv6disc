package ipv6disc

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/arp"
	"github.com/miguelangel-nubla/ipv6disc/pkg/dhcp"
	"github.com/miguelangel-nubla/ipv6disc/pkg/lldp"
	"github.com/miguelangel-nubla/ipv6disc/pkg/llmnr"
	"github.com/miguelangel-nubla/ipv6disc/pkg/mdns"
	"github.com/miguelangel-nubla/ipv6disc/pkg/netbios"
	"github.com/miguelangel-nubla/ipv6disc/pkg/rdns"
	"go.uber.org/zap"
)

// The naming layer learns the names of the hosts the discovery found. A protocol of it that asks
// is a nameAsker: given a host's address, it asks its name. The answer comes when it comes, if it
// does, as a name registered in the State: the layer only decides whom to ask, by what, and when.
// mDNS, NetBIOS and LLMNR are of an interface; the reverse DNS, of the servers it was given, is
// of none.
type nameAsker interface {
	// Asks tells whether the protocol can ask the host at addr: its family, and an address it
	// reaches.
	Asks(addr netip.Addr) bool
	// AskName asks the host at addr its name, without waiting for the answer.
	AskName(addr netip.Addr) error
}

// NameProtocol is a protocol of the naming layer running: on an interface, or, as the reverse
// DNS, on none. One that asks is a nameAsker too; the others only hear, as DHCP and LLDP.
type NameProtocol struct {
	Name   string
	Worker worker
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

// The protocols of the names, as Hostnames.Protocols has them, and as the sources of the names
// they tell.
const (
	NameMDNS    = "mdns"
	NameDNS     = "dns"
	NameNetBIOS = "netbios"
	NameLLMNR   = "llmnr"
	NameWSD     = "wsd"
	NameSSDP    = "ssdp"
	NameDHCP    = "dhcp"
	NameLLDP    = "lldp"
)

// NameProtocols are the protocols the local discovery can learn names by: all run unless
// Hostnames.Protocols names some. The four first ask a host, in this order.
func NameProtocols() []string {
	return []string{NameMDNS, NameDNS, NameNetBIOS, NameLLMNR, NameWSD, NameSSDP, NameDHCP, NameLLDP}
}

// nameOrder is the order a host is asked in, by the protocols that can ask it: mDNS first, a
// question to the host alone, which most devices answer; then the reverse DNS, a question to a
// server, which disturbs nobody of the link; then NetBIOS, to the host alone again, which only
// Windows and Samba answer; and LLMNR last, whose question every host of the link hears, and
// whose answer anyone who heard it can forge.
var nameOrder = []string{NameMDNS, NameDNS, NameNetBIOS, NameLLMNR}

const (
	// nameSource is the source of the names mDNS tells.
	nameSource = NameMDNS
	// namingRate bounds the questions sent in a second, by all the protocols.
	namingRate = 10
	// namingStep is how long the answer of a protocol is waited for before the next one asks.
	namingStep = 2 * time.Second
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
// A name is a host's, and a host is its MAC, which few name protocols tell: what is heard comes
// from an address. So a name goes to the MAC the State has that address at, which only the
// discovery put there: NDP, or the kernel's neighbor table. An address the State doesn't have
// yet is asked of the discovery, and what it said waits for it. A record is never taken as the
// address of whoever sent it. And what does tell a MAC, as a DHCP client's message, names it
// only once the discovery found a host there: an address a packet tells is asked of the
// discovery too, never registered on its word.
type namer struct {
	state      *State
	logger     *zap.SugaredLogger
	lifetime   time.Duration
	rediscover time.Duration
	// The protocols running on an interface, or, for "", on none, and what has the discovery
	// find the MAC of an address heard on one: it tells whether it asked.
	askers   func(iface string) []*NameProtocol
	discover func(iface string, addr netip.Addr) bool
	now      func() time.Time

	mutex sync.Mutex
	// How each host, by MAC, was last asked its name.
	asked map[string]*hostAsking
	// The names said that wait for the MAC of their addresses, or for a host at their MAC.
	claims []claim
	// The addresses heard of that the State doesn't have, and when the discovery was asked.
	wanted map[wantKey]want
	// When the name of a host was last fetched, by a protocol that fetches it from the host
	// that answered its probe.
	fetched map[fetchKey]time.Time
	// The second the rate counts in, and how many were asked in it.
	second time.Time
	sent   int
}

// hostAsking is how a host was asked its name: in rounds, one in a rediscovery interval at most,
// where each protocol that can ask it does, once, one after another, until the host has a name.
type hostAsking struct {
	// When the last round started, and when its last question was sent.
	round, step time.Time
	// The protocols that are still to ask in it.
	left []string
	// Where each protocol last asked, and the protocol that last answered: it asks first.
	last       map[string]asking
	answeredBy string
}

type asking struct {
	addr netip.Addr
	// Whether it answered there: it is asked there again. A host doesn't answer at all its
	// addresses: over one family only, or not for a link-local address it doesn't publish.
	answered bool
}

// claim is what a host said, by source: from, on iface, that name has addr; or, of what tells a
// MAC, that name is the host's at hw, which may have addrs.
type claim struct {
	source string
	iface  string
	from   netip.Addr
	name   string
	addr   netip.Addr
	at     time.Time
	// Whether it is the answer to a question for the name of addr.
	answer bool

	hw    net.HardwareAddr
	addrs []netip.Addr
	// The MAC the frame it was said in came from, of what tells it: the name is the sender's
	// only if the State has from there.
	via net.HardwareAddr
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

type fetchKey struct {
	source, iface string
	addr          netip.Addr
}

func newNamer(state *State, logger *zap.SugaredLogger, config Config) *namer {
	return &namer{
		state:      state,
		logger:     logger,
		lifetime:   config.Hostnames.Lifetime,
		rediscover: config.Rediscover,
		now:        time.Now,
		asked:      make(map[string]*hostAsking),
		wanted:     make(map[wantKey]want),
		fetched:    make(map[fetchKey]time.Time),
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
		if n.discover != nil && n.discover(iface, addr) {
			w.solicited = now
		}
	}
	n.wanted[key] = w
	return !waiting
}

// said is for a record of an mDNS response heard on iface: saidBy, of mDNS.
func (n *namer) said(iface string, from netip.Addr, name string, addr netip.Addr, onLink bool) {
	n.saidBy(nameSource, iface, from, name, addr, onLink, false)
}

// saidBy is for what a host said, by the protocol source, on iface: from says name has addr,
// which onLink tells to be of the link. The name is of the host that sent it only if addr is that
// host's own: the address it sent from, or another the State has at the same MAC. A response can
// carry the records of other hosts, as a proxy's, and those name nobody here: not their sender,
// whose addresses they aren't, nor the host of their address, which didn't say them.
//
// An address of the link the State doesn't have is asked of the discovery: if a host has it, it
// is registered at the MAC that answers for it, whatever the record said. answer is for the
// answer to a question for the name of addr, that came from another address: it is the host's
// asked when both are at one MAC, and so remembered.
func (n *namer) saidBy(source, iface string, from netip.Addr, name string, addr netip.Addr, onLink, answer bool) {
	if _, ok := CleanName(name); !ok {
		return
	}
	n.say(claim{source: source, iface: iface, from: from, name: name, addr: addr, at: n.now(), answer: answer}, onLink)
}

// say settles a claim of saidBy, or has it wait for the discovery.
func (n *namer) say(c claim, onLink bool) {
	source, iface, from, addr := c.source, c.iface, c.from, c.addr
	settled, hw := n.settle(c)
	n.mutex.Lock()
	defer n.mutex.Unlock()
	if settled {
		n.remember(c, hw)
		return
	}
	for _, a := range []netip.Addr{from, addr} {
		if _, known := n.state.macOf(a, iface); !known && onLink && (a != from || source != nameSource) {
			n.want(iface, a)
		}
	}
	n.wait(c)
}

// wait keeps a claim for when the discovery tells whose it is, unless it waits already, or too
// many do. With the mutex held.
func (n *namer) wait(c claim) {
	if len(n.claims) >= namingPending || slices.ContainsFunc(n.claims, func(o claim) bool {
		return o.source == c.source && o.iface == c.iface && o.from == c.from && o.name == c.name && o.addr == c.addr && o.hw.String() == c.hw.String() && o.via.String() == c.via.String()
	}) {
		return
	}
	n.claims = append(n.claims, c)
}

// named is for the name a host gave of itself, by source, on iface, at the address addr of the
// link: its own word, of its own address, which is saidBy.
func (n *namer) named(source, iface string, addr netip.Addr, name string) {
	n.saidBy(source, iface, addr, name, addr, true, false)
}

// namedFrom is named, of what also tells the MAC the frame of the name came from, via, as a DHCPv6
// client's message heard on a packet socket: the name is the host's at addr only if that is the
// MAC the State has addr at. The address of a packet is whatever its sender wrote, and one who
// writes another's, from its own MAC, names nobody.
func (n *namer) namedFrom(source, iface string, addr netip.Addr, via net.HardwareAddr, name string) {
	if _, ok := CleanName(name); !ok || len(via) == 0 {
		return
	}
	n.say(claim{source: source, iface: iface, from: addr, name: name, addr: addr, at: n.now(), via: via}, true)
}

// claimed is for what tells a name with a MAC, by source, on iface: a DHCP client's message, or
// an LLDP neighbor's frame. The name is the host's at hw once the State has a host there, found
// by the discovery: until then it waits, and is dropped if none comes. The addresses it tells,
// addrs, are asked of the discovery, as any heard of, and are at whatever MAC answers for them.
// It returns whether the name is one a host can have.
func (n *namer) claimed(source, iface string, hw net.HardwareAddr, name string, addrs []netip.Addr) bool {
	_, clean := CleanName(name)
	c := claim{source: source, iface: iface, name: name, at: n.now(), hw: hw, addrs: addrs}
	settled := false
	if clean {
		settled, _ = n.settle(c)
	}
	n.mutex.Lock()
	defer n.mutex.Unlock()
	for _, addr := range addrs {
		if _, known := n.state.macOf(addr, iface); !known {
			n.want(iface, addr)
		}
	}
	if clean && !settled {
		n.wait(c)
	}
	return clean
}

// settle registers the name of a claim, if the State tells whose it is: it returns whether it
// is settled, and the MAC it named, if it did. One that isn't waits, as the addresses may be on
// their way to the State.
func (n *namer) settle(c claim) (bool, net.HardwareAddr) {
	if c.hw != nil {
		if !n.state.hasHost(c.hw) {
			return false, nil
		}
		n.state.RegisterName(c.hw, c.name, c.source, n.lifetime)
		return true, c.hw
	}
	sender, ok := n.state.macOf(c.from, c.iface)
	if !ok {
		return false, nil
	}
	if c.via != nil && c.via.String() != sender.String() {
		// Said from another MAC than the one that has the address: it names nobody.
		return true, nil
	}
	if c.addr != c.from {
		owner, ok := n.state.macOf(c.addr, c.iface)
		if !ok {
			return false, nil
		}
		if owner.String() != sender.String() {
			// Another host's record: it names nobody.
			return true, nil
		}
	}
	n.state.RegisterName(sender, c.name, c.source, n.lifetime)
	return true, sender
}

// remember marks a claim that answered a question, and named hw, as the answer of its protocol
// at the address asked. With the mutex held.
func (n *namer) remember(c claim, hw net.HardwareAddr) {
	if !c.answer || hw == nil {
		return
	}
	n.answeredAt(hw, c.source, c.addr)
}

// answeredAt marks the host at hw as having answered source at asked, if it was last asked
// there. With the mutex held.
func (n *namer) answeredAt(hw net.HardwareAddr, source string, asked netip.Addr) {
	h := n.asked[hw.String()]
	if h == nil {
		return
	}
	if last, ok := h.last[source]; ok && last.addr == asked {
		last.answered = true
		h.last[source] = last
		h.answeredBy = source
	}
}

// answered is for the answer of the host asked by mDNS at an address, on iface.
func (n *namer) answered(iface string, asked netip.Addr, name string) {
	n.answeredBy(nameSource, iface, asked, name)
}

// answeredBy is for the answer of the host asked at an address by the protocol source, on iface,
// or on none: its name, which goes to the MAC the State has that address at. The question was
// for that address alone, and the answer came from where it was sent, so whatever answered it
// has it, or, of a DNS server, knows who does.
func (n *namer) answeredBy(source, iface string, asked netip.Addr, name string) {
	hw, ok := n.state.macOf(asked, iface)
	if !ok {
		return
	}
	if clean, _ := n.state.RegisterName(hw, name, source, n.lifetime); clean == "" {
		return
	}
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.answeredAt(hw, source, asked)
}

// fetches tells whether the name of the host that answered a probe of source from addr, on
// iface, is to be fetched from it now: once in a rediscovery interval at most, and not while the
// host has a name that stays, as it isn't asked then either.
func (n *namer) fetches(source, iface string, addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	n.mutex.Lock()
	defer n.mutex.Unlock()
	now := n.now()
	key := fetchKey{source, iface, addr}
	if last, ok := n.fetched[key]; ok && now.Sub(last) < n.rediscover-n.rediscover/10 {
		return false
	}
	if hw, ok := n.state.macOf(addr, iface); ok && n.hasName(n.state.NamesOf(hw), now) {
		return false
	}
	if len(n.fetched) >= 4*namingPending {
		for k, at := range n.fetched {
			if now.Sub(at) >= n.rediscover {
				delete(n.fetched, k)
			}
		}
		if len(n.fetched) >= 4*namingPending {
			return false
		}
	}
	n.fetched[key] = now
	return true
}

// resolve looks again at what waits for the discovery: the names said, now that the State may
// have their addresses, and the addresses the discovery couldn't be asked for, as before the
// listener of their interface started. What waited too long is dropped. It returns whether a
// name still waits for a host at its MAC: its addresses are asked of the discovery again
// meanwhile, as a DHCP client that is given its address a moment after it asked for it.
func (n *namer) resolve() (waiting bool) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	now := n.now()

	n.claims = slices.DeleteFunc(n.claims, func(c claim) bool {
		settled, hw := n.settle(c)
		if settled {
			n.remember(c, hw)
		}
		return settled || now.Sub(c.at) > namingPatience
	})
	for key, w := range n.wanted {
		if _, known := n.state.macOf(key.addr, key.iface); known || now.Sub(w.since) > namingPatience {
			delete(n.wanted, key)
		} else if w.solicited.IsZero() {
			n.want(key.iface, key.addr)
		}
	}
	for _, c := range n.claims {
		if c.hw == nil {
			continue
		}
		waiting = true
		for _, addr := range c.addrs {
			if _, known := n.state.macOf(addr, c.iface); !known {
				n.want(c.iface, addr)
			}
		}
	}
	return waiting
}

// lookups asks the hosts that have no name their name, and those whose names are about to
// expire, as the addresses are pinged before they do: each in a round, once in a rediscovery
// interval at most, and namingRate questions in a second, of all. A host whose name keeps being
// said, by itself or by a plugin, is never asked.
//
// In a round each protocol that can ask the host does, once, at one of its addresses: one
// after another, namingStep apart, in nameOrder, but first the one that answered the last time,
// and only until the host has a name, which ends the round. So a host that answers the first is
// sent one question, and one that answers nothing one by each protocol, in a rediscovery
// interval. It returns whether hosts are left to ask, for the second that follows.
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
		h := n.asked[mac]
		if n.hasName(names[mac], now) {
			if h != nil {
				h.left = nil
			}
			continue
		}
		if h != nil {
			// A round once in a rediscovery interval: a little less than one after the last,
			// so that the look of each interval, which comes a moment sooner or later, finds
			// it due. And within one, a step after the last question.
			if len(h.left) == 0 && !h.round.IsZero() && now.Sub(h.round) < n.rediscover-n.rediscover/10 {
				continue
			}
			if len(h.left) > 0 && now.Sub(h.step) < namingStep {
				backlog = true
				continue
			}
		}
		candidates := n.candidates(hosts[mac])
		if len(candidates) == 0 {
			if h != nil {
				h.left = nil
			}
			continue
		}
		if h == nil {
			h = &hostAsking{last: make(map[string]asking)}
			n.asked[mac] = h
		}
		if len(h.left) == 0 {
			h.left, h.round, h.step = roundOrder(candidates, h.answeredBy), now, time.Time{}
		}
		for len(h.left) > 0 {
			protocol := h.left[0]
			var of []candidate
			for _, c := range candidates {
				if c.protocol == protocol {
					of = append(of, c)
				}
			}
			if len(of) == 0 {
				h.left = h.left[1:]
				continue
			}
			if now.Sub(n.second) >= time.Second {
				n.second, n.sent = now, 0
			}
			if n.sent >= namingRate {
				return true
			}
			n.sent++
			h.left, h.step = h.left[1:], now
			// Where it answered the last time, or at the address after the one that it didn't at.
			last := h.last[protocol]
			i := slices.IndexFunc(of, func(c candidate) bool { return c.addr == last.addr })
			if i < 0 {
				i = 0
			} else if !last.answered {
				i = (i + 1) % len(of)
			}
			c := of[i]
			h.last[protocol] = asking{addr: c.addr}
			fields := []any{zap.String("ip", c.addr.String()), zap.String("mac", mac), zap.String("protocol", protocol), zap.String("interface", c.iface)}
			if err := c.asker.AskName(c.addr); err != nil {
				n.logger.Debugw("host not asked its name", append(fields, zap.Error(err))...)
			} else {
				n.logger.Debugw("host asked its name", fields...)
			}
			break
		}
		if len(h.left) > 0 {
			backlog = true
		}
	}
	return backlog
}

// roundOrder is the order the protocols of the candidates ask in, in a round: first the one that
// answered the last time, then nameOrder, then any other.
func roundOrder(candidates []candidate, first string) []string {
	var order []string
	add := func(protocol string) {
		if !slices.Contains(order, protocol) && slices.ContainsFunc(candidates, func(c candidate) bool { return c.protocol == protocol }) {
			order = append(order, protocol)
		}
	}
	add(first)
	for _, protocol := range nameOrder {
		add(protocol)
	}
	for _, c := range candidates {
		add(c.protocol)
	}
	return order
}

// hasName tells whether a host has a name that stays for a while yet: longer than three
// rediscovery intervals, so that it is asked again in time, and again where it doesn't answer
// at once, or than half its lifetime when that is shorter.
func (n *namer) hasName(names []HostName, now time.Time) bool {
	for _, name := range names {
		if name.Expiration.Sub(now) > min(3*n.rediscover, name.Expiration.Sub(name.Seen)/2) {
			return true
		}
	}
	return false
}

// candidate is an address a host can be asked its name at, and what asks it.
type candidate struct {
	iface    string
	addr     netip.Addr
	protocol string
	asker    nameAsker
}

// candidates are the ways to ask a host its name: each of its addresses a local interface saw,
// by each protocol of that interface that asks it, and each of its addresses, whatever found
// it, by each protocol of no interface that does. The IPv4 ones first, which more devices answer
// over, and the link-local ones last, which a responder may not publish. None for this machine:
// it is no host to ask.
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
		// On no interface, the protocols of none.
		for _, iface := range slices.Concat(addr.Interfaces(), []string{""}) {
			for _, protocol := range n.askers(iface) {
				asker, ok := protocol.Worker.(nameAsker)
				if !ok || !asker.Asks(ip) || slices.ContainsFunc(result, func(c candidate) bool { return c.asker == asker && c.addr == ip }) {
					continue
				}
				result = append(result, candidate{iface, ip, protocol.Name, asker})
			}
		}
	}
	return result
}

// run looks at what waits, and asks, after each change of the state, as a host found, at every
// rediscovery, and every second while hosts are left to ask or a name waits for its host, until
// ctx is done.
func (n *namer) run(ctx context.Context) {
	changes, cancel := n.state.Subscribe()
	defer cancel()
	ticker := time.NewTicker(n.rediscover)
	defer ticker.Stop()

	for {
		waiting := n.resolve()
		var again <-chan time.Time
		if n.lookups() || waiting {
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

// nameProtocols returns the naming protocols running on the interface of that name, or, for
// "", those of no interface.
func (w *Worker) nameProtocols(iface string) []*NameProtocol {
	w.pcMutex.RLock()
	defer w.pcMutex.RUnlock()
	if iface == "" {
		return slices.Clone(w.nameGlobal)
	}
	var protocols []*NameProtocol
	for _, key := range slices.SortedFunc(maps.Keys(w.nameConns), nameKey.compare) {
		if key.name == iface {
			protocols = append(protocols, w.nameConns[key].Protocols...)
		}
	}
	return protocols
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

// startInterfaceNames runs the naming protocols on an interface until ctx is done: those of
// Hostnames.Protocols, each over the families it has and the interface listens over. mDNS also
// probes, at every rediscovery, with the other probes. DHCP and LLDP only hear, where the system
// lets them: a protocol that can't run is told, once, and the others run without it.
func (w *Worker) startInterfaceNames(ctx context.Context, iface net.Interface, key nameKey) {
	fields := []any{zap.String("interface", iface.Name)}
	onError := func(protocol string) func(error) {
		return func(err error) { w.logger.Errorw(protocol+" error", append(fields, zap.Error(err))...) }
	}
	processes := &nameProcesses{InterfaceName: iface.Name}
	running := func(name string, conn interface {
		worker
		Close() error
	}) {
		processes.Protocols = append(processes.Protocols, &NameProtocol{Name: name, Worker: conn})
	}
	defer func() {
		for _, protocol := range processes.Protocols {
			protocol.Worker.(interface{ Close() error }).Close()
		}
	}()

	var mdnsConn *mdns.Conn
	if w.config.names(NameMDNS) {
		conn, err := mdns.Listen(&iface, mdns.Options{
			IPv4: key.ipv4, IPv6: key.ipv6,
			ActiveIPv4: w.config.probesIPv4(), ActiveIPv6: w.config.probesIPv6(),
		}, mdns.Handler{
			Heard: func(from netip.Addr) bool { return w.naming.heard(iface.Name, from) },
			Said: func(from netip.Addr, name string, addr netip.Addr, onLink bool) {
				w.naming.said(iface.Name, from, name, addr, onLink)
			},
			Answered: func(asked netip.Addr, name string) { w.naming.answered(iface.Name, asked, name) },
			Error:    onError("mDNS"),
		})
		if err != nil {
			w.logger.Errorw("error listening for mDNS", append(fields, zap.Error(err))...)
			return
		}
		mdnsConn = conn
		running(NameMDNS, conn)
	}
	if w.config.names(NameNetBIOS) && key.ipv4 {
		conn, err := netbios.Listen(&iface, netbios.Handler{
			Answered: func(asked netip.Addr, name string) {
				w.naming.answeredBy(NameNetBIOS, iface.Name, asked, name)
			},
			Error: onError("NetBIOS"),
		})
		if err != nil {
			w.logger.Errorw("error listening for NetBIOS", append(fields, zap.Error(err))...)
			return
		}
		running(NameNetBIOS, conn)
	}
	if w.config.names(NameLLMNR) {
		conn, err := llmnr.Listen(&iface, llmnr.Options{IPv4: key.ipv4, IPv6: key.ipv6}, llmnr.Handler{
			Answered: func(asked, from netip.Addr, name string) {
				if from == asked {
					w.naming.answeredBy(NameLLMNR, iface.Name, asked, name)
					return
				}
				// From another address, as over IPv6 from its link-local one: the name is the
				// host's asked only if the state has both at one MAC.
				w.naming.saidBy(NameLLMNR, iface.Name, from, name, asked, true, true)
			},
			Error: onError("LLMNR"),
		})
		if err != nil {
			w.logger.Errorw("error listening for LLMNR", append(fields, zap.Error(err))...)
			return
		}
		running(NameLLMNR, conn)
	}
	if w.config.names(NameDHCP) {
		conn, err := dhcp.Listen(&iface, dhcp.Handler{
			Client4: func(m dhcp.Message4) bool {
				// The address it asks for, when the IPv4 discovery can look for it.
				var addrs []netip.Addr
				if m.Addr.IsValid() && key.ipv4 {
					addrs = append(addrs, m.Addr)
				}
				if m.Name == "" && len(addrs) == 0 {
					return false
				}
				return w.naming.claimed(NameDHCP, iface.Name, m.MAC, m.Name, addrs)
			},
			Client6: func(from netip.Addr, hw net.HardwareAddr, m dhcp.Message6) bool {
				if _, ok := CleanName(m.Name); !ok {
					return false
				}
				w.naming.namedFrom(NameDHCP, iface.Name, from, hw, m.Name)
				return true
			},
			Error: onError("DHCP"),
		})
		if err == nil {
			running(NameDHCP, conn)
		} else {
			w.cantHear("DHCP", err)
		}
	}
	if w.config.names(NameLLDP) {
		conn, err := lldp.Listen(&iface, func(neighbor lldp.Neighbor) bool {
			return w.naming.neighbor(iface.Name, neighbor.Source, neighbor.Chassis, neighbor.Name, neighbor.Addrs)
		}, onError("LLDP"))
		if err == nil {
			running(NameLLDP, conn)
		} else {
			w.cantHear("LLDP", err)
		}
	}
	if len(processes.Protocols) == 0 {
		// Nothing of an interface to run: until the interface changes.
		<-ctx.Done()
		return
	}

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
		if mdnsConn != nil && (w.config.probesIPv4() && key.ipv4 || w.config.probesIPv6() && key.ipv6) {
			startMulticast("mDNS", mdnsConn.DiscoverMulticast, iface.Name, w.logger)
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

// neighbor is for what an LLDP frame from the MAC source, heard on iface, says of its sender: its
// name, and the addresses it is managed at, which are claimed. The name is the chassis's: of the
// MAC the frame came from, and of the chassis's own when it tells one, as a switch whose ports
// each have theirs. That one is the frame's word alone, so it is taken only of a MAC of the maker
// of the one the frame came from, as the ports of a chassis are: a host can't name any other of
// the link by writing its MAC there. It returns whether the name is one a host can have.
func (n *namer) neighbor(iface string, source, chassis net.HardwareAddr, name string, addrs []netip.Addr) bool {
	named := n.claimed(NameLLDP, iface, source, name, addrs)
	if chassis != nil && chassis.String() != source.String() && sameMaker(chassis, source) {
		n.claimed(NameLLDP, iface, chassis, name, nil)
	}
	return named
}

// sameMaker tells whether two MACs are of one maker's block: their first three bytes, the OUI.
func sameMaker(a, b net.HardwareAddr) bool {
	return len(a) == 6 && len(b) == 6 && bytes.Equal(a[:3], b[:3])
}

// cantHear tells, once for each protocol, that it can't be heard: without Linux's packet
// sockets it is no news, and without the privilege for them it is said. The rest runs without.
func (w *Worker) cantHear(protocol string, err error) {
	if _, told := w.unheard.LoadOrStore(protocol, true); told {
		return
	}
	switch {
	case errors.Is(err, errors.ErrUnsupported):
		w.logger.Debugf("not listening for %s: %s", protocol, err)
	case errors.Is(err, os.ErrPermission):
		w.logger.Warnf("not listening for %s, which needs CAP_NET_RAW: %s", protocol, err)
	default:
		w.logger.Errorf("not listening for %s: %s", protocol, err)
	}
}

// startNameServers opens what asks the DNS servers of the configuration the names of the
// addresses, until ctx is done: a protocol of the naming layer of no interface.
func (w *Worker) startNameServers(ctx context.Context) {
	if !w.config.names(NameDNS) || len(w.config.Hostnames.DNS) == 0 {
		return
	}
	conn, err := rdns.Dial(w.config.Hostnames.DNS, rdns.Handler{
		Answered: func(asked netip.Addr, name string) { w.naming.answeredBy(NameDNS, "", asked, name) },
		Error:    func(err error) { w.logger.Errorw("DNS error", zap.Error(err)) },
	})
	if err != nil {
		w.logger.Errorw("error listening for DNS", zap.Error(err))
		return
	}
	protocol := &NameProtocol{Name: NameDNS, Worker: conn}
	w.pcMutex.Lock()
	w.nameGlobal = append(w.nameGlobal, protocol)
	w.pcMutex.Unlock()
	w.running.Add(1)
	go func() {
		defer w.running.Done()
		<-ctx.Done()
		w.pcMutex.Lock()
		w.nameGlobal = slices.DeleteFunc(w.nameGlobal, func(p *NameProtocol) bool { return p == protocol })
		w.pcMutex.Unlock()
		conn.Close()
	}()
}

// nameFetches is what a discovery protocol that fetches the names of the hosts that answer its
// probe needs of the naming layer, for an interface: whether to fetch one's, and its name.
func (w *Worker) nameFetches(source, iface string) (wants func(netip.Addr) bool, named func(netip.Addr, string)) {
	return func(from netip.Addr) bool { return w.naming.fetches(source, iface, from) },
		func(from netip.Addr, name string) { w.naming.named(source, iface, from.Unmap().WithZone(""), name) }
}
