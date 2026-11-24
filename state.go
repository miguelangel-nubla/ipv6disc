package ipv6disc

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// State is the addresses discovered, by MAC, and the names of the hosts, by MAC too.
//
// Its locks are taken in this order, never the other way: macsMutex, then an AddrCollection's
// addressesMutex, then an Addr's mutex; and macsMutex, then namesMutex. subscribersMutex and
// movesMutex are taken alone. An address seen again as
// it expires is safe for it: seen and remove both hold macsMutex, and remove only takes out the very
// address that expired, if it is still not valid.
type State struct {
	macs      map[string]*AddrCollection
	macsMutex sync.RWMutex
	logger    *zap.SugaredLogger
	// The families it takes: IPv6 only by default.
	noIPv6 atomic.Bool
	ipv4   atomic.Bool
	// The families' lifetimes, in nanoseconds, when they have their own.
	lifetimeIPv6, lifetimeIPv4 atomic.Int64

	// The names of the hosts, by MAC and by name, when it takes them: not by default. They have
	// one timer among them all, for the first to expire, and their lifetime, in nanoseconds, when
	// they have their own.
	takesNames    atomic.Bool
	lifetimeNames atomic.Int64
	names         map[string]map[string]*HostName
	namesMutex    sync.Mutex
	namesTimer    *time.Timer
	// When the timer fires, zero when it doesn't; and whether Close stopped it.
	namesTimerAt time.Time
	namesStopped bool

	// The channels Subscribe gave, which hear of every change.
	subscribers      map[chan struct{}]struct{}
	subscribersMutex sync.Mutex

	// The last move of each address, by where it moved, to tell one that goes back and forth.
	moves      map[moveKey]move
	movesMutex sync.Mutex
}

// SetLifetimes gives each family the lifetime of its addresses: Register uses it in place of the
// one it is given. Zero keeps the one given.
func (s *State) SetLifetimes(ipv6, ipv4 time.Duration) {
	s.lifetimeIPv6.Store(int64(ipv6))
	s.lifetimeIPv4.Store(int64(ipv4))
}

// Subscribe returns a channel that receives a value after the addresses change: one is added, one
// expires, or one is seen by a new source; and after the names of a host do: one is added, expires,
// goes with its host, or is said by a new source. Changes coming faster than they are received
// are told once. cancel stops it, and doesn't close the channel: a reader that waits on it waits
// on what ends itself too, as its context.
func (s *State) Subscribe() (changes <-chan struct{}, cancel func()) {
	ch := make(chan struct{}, 1)
	s.subscribersMutex.Lock()
	if s.subscribers == nil {
		s.subscribers = make(map[chan struct{}]struct{})
	}
	s.subscribers[ch] = struct{}{}
	s.subscribersMutex.Unlock()
	return ch, func() {
		s.subscribersMutex.Lock()
		delete(s.subscribers, ch)
		s.subscribersMutex.Unlock()
	}
}

func (s *State) changed() {
	s.subscribersMutex.Lock()
	defer s.subscribersMutex.Unlock()
	for ch := range s.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// SetFamilies sets the families whose addresses the state takes, and the plugins read: Register
// leaves the others out.
func (s *State) SetFamilies(ipv6, ipv4 bool) {
	s.noIPv6.Store(!ipv6)
	s.ipv4.Store(ipv4)
}

// IPv6 tells whether the state takes IPv6 addresses, for the plugins to read them.
func (s *State) IPv6() bool {
	return !s.noIPv6.Load()
}

// IPv4 tells whether the state takes IPv4 addresses, for the plugins to read them.
func (s *State) IPv4() bool {
	return s.ipv4.Load()
}

func (s *State) SetLogger(l *zap.SugaredLogger) {
	s.logger = l
}

// Register adds a discovered address to the state, or refreshes the one already there. An address
// of a family the state doesn't take is left out: it returns nil and true, as if known. One that is
// invalid, unspecified or multicast, or has no MAC, is left out the same way: a host is its MAC.
// The family's lifetime, if SetLifetimes gave it one, replaces lifetime.
// onExpiration, which can be nil, is called on each expiration event of the address: the first one
// given stays, also when the address was first registered without. When the address expires it is
// logged and taken out of the state, unless it was seen again meanwhile.
func (s *State) Register(hw net.HardwareAddr, ip netip.Addr, source string, lifetime time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) (*Addr, bool) {
	return s.register(hw, ip, Record{By: source}, kind{}, lifetime, onExpiration)
}

// Report is Register for what a plugin, or another source, reports from one of its tables: by is
// its name, typ its type, and from the table, as FromNeighbors.
func (s *State) Report(hw net.HardwareAddr, ip netip.Addr, by, typ, from string, lifetime time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) (*Addr, bool) {
	return s.register(hw, ip, Record{By: by, Type: typ, From: from}, kind{}, lifetime, onExpiration)
}

// Attach adds a report to the address of that MAC the state has, if it has it: by, of type typ,
// from its table from. The report says how the address was seen for its lifetime, refreshed by the
// next, and keeps the address no longer than the others do: a table that lists an address whether
// its host is there or not, as a DHCP server's leases, finds nobody, and names one that is. It
// tells whether there was the address.
func (s *State) Attach(hw net.HardwareAddr, ip netip.Addr, by, typ, from string, lifetime time.Duration) bool {
	ip = ip.Unmap().WithZone("")
	s.macsMutex.RLock()
	c := s.macs[hw.String()]
	s.macsMutex.RUnlock()
	if c == nil {
		return false
	}
	c.addressesMutex.RLock()
	addr := c.addresses[ip.String()]
	c.addressesMutex.RUnlock()
	if addr == nil || !addr.Valid() {
		return false
	}
	now := time.Now()
	addr.mutex.Lock()
	added := addr.addRecord(Record{By: by, Type: typ, From: from, FirstSeen: now, LastSeen: now, Lifetime: lifetime, attached: true})
	addr.mutex.Unlock()
	if added {
		s.changed()
	}
	return true
}

// registerLocal is Register for the local discovery: r says how, and on which interface.
func (s *State) registerLocal(hw net.HardwareAddr, ip netip.Addr, r Record, lifetime time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) (*Addr, bool) {
	return s.register(hw, ip, r, kind{}, lifetime, onExpiration)
}

// registerLocalSeen is registerLocal, of an address seen at seen, past: it stays its lifetime from
// then. One already there that stays longer is left as it is, and one whose lifetime from then is
// over isn't registered.
func (s *State) registerLocalSeen(hw net.HardwareAddr, ip netip.Addr, r Record, lifetime time.Duration, seen time.Time) (*Addr, bool) {
	return s.register(hw, ip, r, kind{seen: seen}, lifetime, nil)
}

// RegisterSelf is Register for an address of this machine's own, on the local interface iface:
// Addr.Self says so, and Addr.Temporary whether temporary is. The local discovery registers those of
// the interfaces it runs on; a program can register others, as found otherwise.
func (s *State) RegisterSelf(hw net.HardwareAddr, ip netip.Addr, iface string, temporary bool, lifetime time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) (*Addr, bool) {
	r := Record{By: ReportedByKernel, From: FromInterfaces, On: iface}
	return s.register(hw, ip, r, kind{self: true, temporary: temporary}, lifetime, onExpiration)
}

// kind is what a registration says of the address, besides its record; and when it was seen, if
// past.
type kind struct {
	self, temporary bool
	seen            time.Time
}

func (s *State) register(hw net.HardwareAddr, ip netip.Addr, record Record, k kind, lifetime time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) (*Addr, bool) {
	source := record.source()
	ip = ip.Unmap()
	if ip.Is4() && !s.IPv4() || ip.Is6() && !s.IPv6() {
		return nil, true
	}
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || len(hw) == 0 {
		return nil, true
	}
	familyLifetime := &s.lifetimeIPv6
	if ip.Is4() {
		familyLifetime = &s.lifetimeIPv4
	}
	if l := time.Duration(familyLifetime.Load()); l > 0 {
		lifetime = l
	}
	if !k.seen.IsZero() && !k.seen.Add(lifetime).After(time.Now()) {
		// Seen too long ago to be there: nothing to register, nor to extend.
		return nil, true
	}

	// The callback is the address's, not this registration's: a later one can have given it.
	expire := func(expiredAddr *Addr, remainingEvents AddrExpirationRemainingEvents) {
		expiredAddr.mutex.RLock()
		notify := expiredAddr.notify
		expiredAddr.mutex.RUnlock()
		if notify != nil {
			notify(expiredAddr, remainingEvents)
		}
		if remainingEvents != 0 || !s.remove(expiredAddr) {
			return
		}
		s.changed()
		if s.logger != nil {
			s.logger.Infow("host expired",
				zap.String("ip", expiredAddr.WithZone("").String()),
				zap.String("mac", expiredAddr.Hw.String()),
				zap.String("source", source),
			)
		}
	}

	scope, scoped := scopeOf(record)
	scoped = scoped && !k.self
	if scoped && !k.seen.IsZero() && s.outdated(hw.String(), ip, scope, k.seen) {
		// Another MAC showed the address there since: a neighbor table read later than it
		// changed, as the kernel's whose entry still has the MAC the address left.
		return nil, true
	}

	newAddr := NewAddr(hw, ip, source, lifetime, expire)
	// Now, as the address it makes has it: its expiration is the record's, to the nanosecond.
	seen := k.seen
	if seen.IsZero() {
		seen = newAddr.expirationTime.Add(-lifetime)
	}
	record.FirstSeen, record.LastSeen, record.Lifetime = seen, seen, lifetime
	record.order = 1
	newAddr.records = map[recordKey]*Record{record.key(): &record}
	newAddr.self, newAddr.temporary = k.self, k.temporary
	newAddr.notify = onExpiration
	newAddr.removedBy = s
	addr, existing, newSource := s.seen(newAddr, source)
	if !existing || newSource {
		defer s.changed()
	}
	if scoped {
		s.moveOff(hw, ip, scope, seen)
	}

	if !existing {
		addr.Watch()
		if !k.seen.IsZero() {
			// Its lifetime from when it was seen, not from now.
			addr.resetTimersFrom(k.seen, true)
		}
		if s.logger != nil {
			s.logger.Infow("host identified",
				zap.String("ip", ip.WithZone("").String()),
				zap.String("mac", hw.String()),
				zap.String("source", source),
				zap.Stringer("record", record),
			)
		}
	} else {
		// After Close, which stopped its events.
		addr.watch(true)
		if s.logger != nil {
			s.logger.Debugw("ttl refreshed",
				zap.String("ip", ip.String()),
				zap.String("mac", hw.String()),
				zap.String("source", source),
			)
		}
	}

	return addr, existing
}

// Seen adds the address to the collection of its MAC, or marks the one there as seen.
// The address is taken as it is: unlike Register, Seen applies neither SetFamilies nor
// SetLifetimes, and logs nothing. One it adds is seen now, valid for its lifetime from then on,
// whenever it was made, and also if it had expired: it is watched, its onExpiration called on each
// event, and it leaves the state when it expires. The onExpiration of one given for an address
// already there is not called.
func (s *State) Seen(addr *Addr, source ...string) (*Addr, bool) {
	addr, existing, newSource := s.seen(addr, source...)
	if !existing {
		addr.mutex.Lock()
		// Once: an address that expired and is given again has it already.
		if addr.removedBy != s {
			given := addr.onExpiration
			addr.onExpiration = func(expired *Addr, remaining AddrExpirationRemainingEvents) {
				if given != nil {
					given(expired, remaining)
				}
				if remaining == 0 && s.remove(expired) {
					s.changed()
				}
			}
			addr.removedBy = s
		}
		addr.mutex.Unlock()
		addr.Watch()
		// Its expiration time with its timers: Watch leaves it as it was, already past for one
		// that expired.
		addr.resetTimers(true)
	} else {
		addr.watch(true)
	}
	if !existing || newSource {
		s.changed()
	}
	return addr, existing
}

// seen is Seen, telling also whether source is new to an address already there.
func (s *State) seen(addr *Addr, source ...string) (*Addr, bool, bool) {
	s.macsMutex.Lock()
	defer s.macsMutex.Unlock()

	mac := addr.Hw.String()
	collection, exists := s.macs[mac]
	if !exists {
		collection = NewAddrCollection()
		s.macs[mac] = collection
	}

	return collection.seen(addr, source...)
}

// moveOff takes the address ip, in scope, off every other MAC than hw that was last seen with it
// there before seen: hw showed it since, and an address is at one MAC of a link, and of a
// neighbor table, at a time. So the host it left loses it at once, not a lifetime later, and its
// names no longer give the address of another: as when a device takes the place of another, a
// container is made again with a new MAC, or a virtual address goes to the other machine of a
// pair. One that it was the last address of is gone, and its names with it. A host that showed it
// as late keeps it too: it is nobody's, until one of them shows it again.
//
// Seen at two MACs by turns, as by two devices given the same address, the address moves each
// time, and the log warns of it.
func (s *State) moveOff(hw net.HardwareAddr, ip netip.Addr, scope moveScope, seen time.Time) {
	mac := hw.String()
	if !s.elsewhere(mac, ip) {
		return
	}
	var from []string
	s.macsMutex.Lock()
	for other, collection := range s.macs {
		if other == mac {
			continue
		}
		addr, _, empty := collection.moveOff(ip, scope, seen)
		if addr == nil {
			continue
		}
		from = append(from, other)
		if empty {
			delete(s.macs, other)
			// A host is its addresses: without any, it is gone, and its names with it.
			s.dropNames(other)
		}
	}
	s.macsMutex.Unlock()
	if len(from) == 0 {
		return
	}
	s.changed()
	slices.Sort(from)
	for _, other := range from {
		back := s.noteMove(moveKey{scope, ip}, other, mac, seen)
		if s.logger == nil {
			continue
		}
		fields := []any{zap.String("ip", ip.WithZone("").String()), zap.String("from", other), zap.String("to", mac), zap.String("on", scope.String())}
		if back {
			s.logger.Warnw("address moves back and forth between two MACs: two devices with the same address?", fields...)
		} else {
			s.logger.Infow("address moved", fields...)
		}
	}
}

// elsewhere tells whether a MAC other than mac has the address ip: what moveOff looks at first, as
// it runs at every sighting, with the read lock alone.
func (s *State) elsewhere(mac string, ip netip.Addr) bool {
	key := ip.Unmap().WithZone("").String()
	s.macsMutex.RLock()
	defer s.macsMutex.RUnlock()
	for other, collection := range s.macs {
		if other == mac {
			continue
		}
		collection.addressesMutex.RLock()
		_, ok := collection.addresses[key]
		collection.addressesMutex.RUnlock()
		if ok {
			return true
		}
	}
	return false
}

// outdated tells whether a MAC other than mac was seen with the address ip in scope later than
// seen: a sighting of mac then is of an address that moved since, which isn't mac's any more.
func (s *State) outdated(mac string, ip netip.Addr, scope moveScope, seen time.Time) bool {
	key := ip.Unmap().WithZone("").String()
	s.macsMutex.RLock()
	defer s.macsMutex.RUnlock()
	for other, collection := range s.macs {
		if other == mac {
			continue
		}
		collection.addressesMutex.RLock()
		addr, ok := collection.addresses[key]
		collection.addressesMutex.RUnlock()
		if ok && addr.lastIn(scope).After(seen) {
			return true
		}
	}
	return false
}

// moveKey is an address, where it moves.
type moveKey struct {
	scope moveScope
	ip    netip.Addr
}

// move is the last move of an address: from which MAC to which, and when; and when the log last
// warned that it goes back and forth.
type move struct {
	from, to string
	at       time.Time
	warned   time.Time
}

// moveFlapping is how soon after a move one back counts as the address going back and forth, and
// how often the log warns of it: once in that time, of each address.
const moveFlapping = 10 * time.Minute

// noteMove keeps the move of an address from one MAC to another, at, and tells whether the log is
// to warn of it: it went back to where it came from, within moveFlapping of the move before, and
// the log didn't warn of it in that time. The moves older than that are forgotten.
func (s *State) noteMove(key moveKey, from, to string, at time.Time) (warn bool) {
	s.movesMutex.Lock()
	defer s.movesMutex.Unlock()
	if s.moves == nil {
		s.moves = make(map[moveKey]move)
	}
	for k, m := range s.moves {
		if at.Sub(m.at) > moveFlapping && at.Sub(m.warned) > moveFlapping {
			delete(s.moves, k)
		}
	}
	last, ok := s.moves[key]
	next := move{from: from, to: to, at: at, warned: last.warned}
	if ok && last.from == to && last.to == from && at.Sub(last.at) <= moveFlapping && at.Sub(last.warned) > moveFlapping {
		warn = true
		next.warned = at
	}
	s.moves[key] = next
	return warn
}

// remove takes an expired address out of the state, unless it was seen again since. It returns
// whether it did.
func (s *State) remove(addr *Addr) bool {
	s.macsMutex.Lock()
	defer s.macsMutex.Unlock()

	mac := addr.Hw.String()
	collection, ok := s.macs[mac]
	if !ok {
		return false
	}
	removed, empty := collection.removeExpired(addr)
	if empty {
		delete(s.macs, mac)
		// A host is its addresses: without any, it is gone, and its names with it.
		s.dropNames(mac)
	}
	return removed
}

// removeSelf takes out of the state an address of this machine's that the interface iface no longer
// has, valid as it is: the worker knows it gone, which no neighbor's address ever is. One that
// another interface has too stays, without iface among its interfaces and sources. It returns
// whether the address was this machine's on iface: a neighbor's with the same MAC and IP is left.
func (s *State) removeSelf(mac string, ip netip.Addr, iface string) bool {
	s.macsMutex.Lock()
	collection, ok := s.macs[mac]
	if !ok {
		s.macsMutex.Unlock()
		return false
	}
	addr, removed, empty := collection.removeSelf(ip, iface)
	if empty {
		delete(s.macs, mac)
		s.dropNames(mac)
	}
	s.macsMutex.Unlock()
	if addr == nil {
		return false
	}

	s.changed()
	if removed && s.logger != nil {
		s.logger.Infow("host removed",
			zap.String("ip", addr.WithZone("").String()),
			zap.String("mac", mac),
			zap.String("source", iface),
		)
	}
	return true
}

// Close stops the expiration events of every address, each with its goroutine and timers: none
// is removed nor logged after it, but one whose event is under way, and Valid still tells by time. It is for a state whose worker
// stopped, after Worker.Wait, and can be called more than once. An address registered after it is
// watched again. The names' one timer stops too, and none is taken out after it: NamesOf still
// leaves out those whose lifetime passed, and a name registered after it starts the timer again.
func (s *State) Close() {
	s.stopNames()

	s.macsMutex.RLock()
	defer s.macsMutex.RUnlock()

	for _, collection := range s.macs {
		for _, addr := range collection.Get() {
			addr.Unwatch()
		}
	}
}

// GetAll returns the addresses of each MAC.
func (s *State) GetAll() map[string]*AddrCollection {
	s.macsMutex.RLock()
	defer s.macsMutex.RUnlock()

	return maps.Clone(s.macs)
}

func (s *State) FilterMACs(hws []net.HardwareAddr) *AddrCollection {
	results := NewAddrCollection()

	s.macsMutex.RLock()
	defer s.macsMutex.RUnlock()

	for _, hw := range hws {
		if collection, exists := s.macs[hw.String()]; exists {
			results.Join(collection)
		}
	}

	return results
}

// PrettyPrint is the page of the discovery: a summary, and each host by its MAC, with its names
// and their sources, and its addresses and their records, each with how long it has left and how
// long it has been seen, lined up. hideSensible is there for symmetry with the other PrettyPrint
// methods: nothing here is sensible.
func (s *State) PrettyPrint(prefix string, hideSensible bool) string {
	return s.Page(prefix).String()
}

// Page is PrettyPrint with the roles: the names as names, and the times, what said each thing
// and the groups as details.
func (s *State) Page(prefix string) pretty.Page {
	s.macsMutex.RLock()
	defer s.macsMutex.RUnlock()

	names := s.AllNames()
	addresses, named := 0, 0
	for mac, c := range s.macs {
		addresses += len(c.Get())
		if len(names[mac]) > 0 {
			named++
		}
	}
	var t pretty.Table
	t.Spans(pretty.As(pretty.Heading, "Discovery:"), pretty.Span{Text: fmt.Sprintf(" %s, %d named, %s", counted(len(s.macs), "host", "hosts"), named, counted(addresses, "address", "addresses"))})
	now := time.Now()
	for _, mac := range slices.Sorted(maps.Keys(s.macs)) {
		t.Line("    " + mac)
		if hostNames := names[mac]; len(hostNames) > 0 {
			t.Spans(pretty.As(pretty.Detail, "        names:"))
			for _, n := range hostNames {
				t.Row("            "+n.Name, n.Expiration.Sub(now), now.Sub(n.FirstSeen), "").Label(pretty.Name)
				for _, said := range n.Said {
					t.Row("                "+said.String(), said.Expiration().Sub(now), now.Sub(said.FirstSeen), "").Label(pretty.Detail)
				}
			}
		}
		t.Spans(pretty.As(pretty.Detail, "        addresses:"))
		s.macs[mac].rows(&t, "            ", now)
	}
	return t.Page(prefix)
}

func NewState() *State {
	return &State{
		macs: make(map[string]*AddrCollection),
	}
}

// counted is n with the word for one, or for any other number: 1 host, 2 hosts, 0 hosts.
func counted(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
