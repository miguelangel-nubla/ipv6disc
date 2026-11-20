package ipv6disc

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// State is the addresses discovered, by MAC.
//
// Its locks are taken in this order, never the other way: macsMutex, then an AddrCollection's
// addressesMutex, then an Addr's mutex. subscribersMutex is taken alone. An address seen again as
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

	// The channels Subscribe gave, which hear of every change.
	subscribers      map[chan struct{}]struct{}
	subscribersMutex sync.Mutex
}

// SetLifetimes gives each family the lifetime of its addresses: Register uses it in place of the
// one it is given. Zero keeps the one given.
func (s *State) SetLifetimes(ipv6, ipv4 time.Duration) {
	s.lifetimeIPv6.Store(int64(ipv6))
	s.lifetimeIPv4.Store(int64(ipv4))
}

// Subscribe returns a channel that receives a value after the addresses change: one is added, one
// expires, or one is seen by a new source. Changes coming faster than they are received are told
// once. cancel stops it, and doesn't close the channel: a reader that waits on it waits on what
// ends itself too, as its context.
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
	return s.register(hw, ip, source, kind{}, lifetime, onExpiration)
}

// registerLocal is Register for the local discovery: source is the interface that saw it.
func (s *State) registerLocal(hw net.HardwareAddr, ip netip.Addr, iface string, lifetime time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) (*Addr, bool) {
	return s.register(hw, ip, iface, kind{local: true}, lifetime, onExpiration)
}

// registerLocalSeen is registerLocal, of an address seen at seen, past: it stays its lifetime from
// then. One already there that stays longer is left as it is, and one whose lifetime from then is
// over isn't registered.
func (s *State) registerLocalSeen(hw net.HardwareAddr, ip netip.Addr, iface string, lifetime time.Duration, seen time.Time) (*Addr, bool) {
	return s.register(hw, ip, iface, kind{local: true, seen: seen}, lifetime, nil)
}

// RegisterSelf is Register for an address of this machine's own, on the local interface iface:
// Addr.Self says so, and Addr.Temporary whether temporary is. The local discovery registers those of
// the interfaces it runs on; a program can register others, as found otherwise.
func (s *State) RegisterSelf(hw net.HardwareAddr, ip netip.Addr, iface string, temporary bool, lifetime time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) (*Addr, bool) {
	return s.register(hw, ip, iface, kind{local: true, self: true, temporary: temporary}, lifetime, onExpiration)
}

// kind is what a registration says of the address, besides its source; and when it was seen, if
// past.
type kind struct {
	local, self, temporary bool
	seen                   time.Time
}

func (s *State) register(hw net.HardwareAddr, ip netip.Addr, source string, k kind, lifetime time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) (*Addr, bool) {
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

	newAddr := NewAddr(hw, ip, source, lifetime, expire)
	if k.local {
		newAddr.interfaces = []string{source}
	}
	newAddr.self, newAddr.temporary = k.self, k.temporary
	newAddr.seenAt = k.seen
	newAddr.notify = onExpiration
	newAddr.removedBy = s
	addr, existing, newSource := s.seen(newAddr, source)
	if !existing || newSource {
		defer s.changed()
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
// watched again.
func (s *State) Close() {
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

// PrettyPrint lists the addresses of each MAC. hideSensible is there for symmetry with the other
// PrettyPrint methods: nothing here is sensible.
func (s *State) PrettyPrint(prefix string, hideSensible bool) string {
	var result strings.Builder

	s.macsMutex.RLock()
	defer s.macsMutex.RUnlock()

	fmt.Fprintf(&result, "%sDiscovery:\n", prefix)

	for _, mac := range slices.Sorted(maps.Keys(s.macs)) {
		fmt.Fprintf(&result, "%s    %s\n", prefix, mac)
		fmt.Fprint(&result, s.macs[mac].PrettyPrint(prefix+"        "))
	}

	return result.String()
}

func NewState() *State {
	return &State{
		macs: make(map[string]*AddrCollection),
	}
}
