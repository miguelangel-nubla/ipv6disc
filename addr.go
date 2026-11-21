package ipv6disc

import (
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

type Addr struct {
	netip.Addr
	Hw net.HardwareAddr

	lifetime     time.Duration
	onExpiration func(*Addr, AddrExpirationRemainingEvents)
	// What State.Register was given to call on the expiration events, read when one fires: a later
	// registration gives it to an address that has none.
	notify func(*Addr, AddrExpirationRemainingEvents)
	// The state whose onExpiration this one has, which takes it out when it expires: State.Seen
	// wraps it once, however many times the address is given.
	removedBy *State

	expiration3    *time.Timer
	expiration2    *time.Timer
	expiration1    *time.Timer
	expiration     *time.Timer
	expirationTime time.Time
	// How it was seen: by each protocol and way, or reported by each, each with its own times. The
	// address expires with the last of them; lifetime is that one's.
	records      map[recordKey]*Record
	recordsAdded uint64
	// An address of this machine, rather than of a neighbor; and, of those, one the kernel says is
	// temporary, a privacy address of IPv6.
	self, temporary bool

	// Closed by Unwatch; a Watch after it makes a new one.
	unwatch   chan struct{}
	unwatched bool

	mutex sync.RWMutex
}

// AddrExpirationRemainingEvents counts the warnings left before the address expires: 3, 2 and 1
// come at 2/3, 3/4 and 4/5 of its lifetime, and 0 is the expiration itself.
type AddrExpirationRemainingEvents int

func (a *Addr) resetTimers(resetExpirationTime bool) {
	a.resetTimersFrom(time.Now(), resetExpirationTime)
}

// resetTimersFrom is resetTimers, of an address seen at from, which can be past: the events come
// that much sooner, at once those already due.
func (a *Addr) resetTimersFrom(from time.Time, resetExpirationTime bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Before the timers: the expiration timer can't fire before the address is invalid.
	elapsed := time.Since(from)
	a.expiration3.Reset(a.lifetime/3*2 - elapsed)
	a.expiration2.Reset(a.lifetime/4*3 - elapsed)
	a.expiration1.Reset(a.lifetime/5*4 - elapsed)
	a.expiration.Reset(a.lifetime - elapsed)

	if resetExpirationTime {
		a.expirationTime = from.Add(a.lifetime)
	}
}

func (a *Addr) Valid() bool {
	return a.GetExpiration().After(time.Now())
}

func (a *Addr) GetExpiration() time.Time {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	return a.expirationTime
}

// Sources returns the names of what has seen the address, of its records that count: the local
// interfaces, and the plugins and others that reported it.
func (a *Addr) Sources() []string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	var sources []string
	for _, r := range a.liveRecords(time.Now()) {
		if s := r.source(); s != "" && !slices.Contains(sources, s) {
			sources = append(sources, s)
		}
	}
	return sources
}

// Interfaces returns the local interfaces that have seen the address: of its records, those of the
// worker's own local discovery, not plugins nor other callers of State.Register.
func (a *Addr) Interfaces() []string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	var interfaces []string
	for _, r := range a.liveRecords(time.Now()) {
		if r.On != "" && !slices.Contains(interfaces, r.On) {
			interfaces = append(interfaces, r.On)
		}
	}
	return interfaces
}

// Self tells whether the address is one of this machine's own, rather than a neighbor's.
func (a *Addr) Self() bool {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.self
}

// Temporary tells whether the address is one of this machine's that the kernel says is temporary:
// an IPv6 privacy address, which changes every day or so. It is known on Linux, and of this
// machine's own addresses only: a neighbor's is never said temporary.
func (a *Addr) Temporary() bool {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.temporary
}

// Seen extends the address's lifetime: that of the record it has that lasts longest, seen again
// now; with a source, a record of it, reported.
func (a *Addr) Seen(source ...string) {
	by := &Addr{}
	if len(source) > 0 {
		a.mutex.RLock()
		lifetime := a.lifetime
		a.mutex.RUnlock()
		by.records = map[recordKey]*Record{}
		r := Record{By: source[0], LastSeen: time.Now(), Lifetime: lifetime}
		by.records[r.key()] = &r
	}
	a.seenBy(by)
}

// seenBy is Seen, by a registration of the same address, telling whether it gave the address a
// source it didn't have: its records are merged into the address's, each seen again or added, and
// the address then expires with the one that lasts longest, however long the others. A record of a
// sighting past counts from then: an older sighting never shortens what another gave. It says too
// whether the address is this machine's, and temporary. Without records, the one that lasts
// longest is seen again now.
func (a *Addr) seenBy(by *Addr) bool {
	now := time.Now()
	a.mutex.Lock()
	before := len(a.sourcesLocked(now))
	if len(by.records) == 0 {
		if r := a.lasting(now); r != nil {
			r.LastSeen = now
		}
	}
	for _, r := range by.records {
		a.addRecord(*r)
	}
	if by.self {
		a.self, a.temporary = true, by.temporary
	}
	if a.notify == nil {
		a.notify = by.notify
	}
	newSource := len(a.sourcesLocked(now)) > before
	lasting := a.lasting(now)
	from, changed := time.Time{}, false
	if lasting != nil && !lasting.Expiration().Equal(a.expirationTime) {
		a.lifetime, from, changed = lasting.Lifetime, lasting.LastSeen, true
	}
	a.mutex.Unlock()
	if changed {
		a.resetTimersFrom(from, true)
	}
	return newSource
}

// sourcesLocked is the sources of the records that count at now, with the mutex held.
func (a *Addr) sourcesLocked(now time.Time) []string {
	var sources []string
	for _, r := range a.liveRecords(now) {
		if s := r.source(); s != "" && !slices.Contains(sources, s) {
			sources = append(sources, s)
		}
	}
	return sources
}

// Watch calls onExpiration on each of the expiration events, until Unwatch is called. An address
// seen again after it expired has its events again.
// It reads the timers' channels after they are reset, which needs the timers of Go 1.23: a reset
// timer has no stale value left in its channel.
func (a *Addr) Watch() {
	a.watch(false)
}

// watch is Watch. With again, of an address Unwatch stopped only: a state watches again the one
// registered after its Close, and no address twice.
func (a *Addr) watch(again bool) {
	a.mutex.Lock()
	if again && !a.unwatched {
		a.mutex.Unlock()
		return
	}
	if a.unwatched {
		a.unwatch, a.unwatched = make(chan struct{}), false
	}
	unwatch, onExpiration := a.unwatch, a.onExpiration
	a.mutex.Unlock()

	go func() {
		for {
			select {
			case <-a.expiration3.C:
				onExpiration(a, 3)
			case <-a.expiration2.C:
				onExpiration(a, 2)
			case <-a.expiration1.C:
				onExpiration(a, 1)
			case <-a.expiration.C:
				onExpiration(a, 0)
			case <-unwatch:
				return
			}
		}
	}()

	a.resetTimers(false)
}

// leaves is for an address of this machine's that iface no longer has: it is no longer among its
// interfaces, nor its sources. It tells whether the address was one of this machine's on iface,
// and whether no interface has it now.
func (a *Addr) leaves(iface string) (was, last bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if !a.self {
		return false, false
	}
	for k, r := range a.records {
		if r.On == iface {
			delete(a.records, k)
			was = true
		}
	}
	if !was {
		return false, false
	}
	for _, r := range a.records {
		if r.On != "" {
			return true, false
		}
	}
	return true, true
}

// Unwatch stops the expiration events. It can be called more than once.
func (a *Addr) Unwatch() {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.unwatched {
		return
	}
	a.expiration3.Stop()
	a.expiration2.Stop()
	a.expiration1.Stop()
	a.expiration.Stop()
	close(a.unwatch)
	a.unwatched = true
}

// NewAddr makes an address that expires after lifetime: Watch tells its expiration events.
// Its timers run from now on, watched or not. State.Register makes one for every registration and
// drops it, unstopped, when the address is already there: that leaks nothing since Go 1.23, which
// collects a timer nothing refers to.
func NewAddr(hw net.HardwareAddr, addr netip.Addr, source string, lifetime time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) *Addr {
	if onExpiration == nil {
		onExpiration = func(*Addr, AddrExpirationRemainingEvents) {}
	}
	now := time.Now()
	r := Record{By: source, FirstSeen: now, LastSeen: now, Lifetime: lifetime, order: 1}
	return &Addr{
		Addr:           addr,
		Hw:             hw,
		records:        map[recordKey]*Record{r.key(): &r},
		recordsAdded:   1,
		lifetime:       lifetime,
		onExpiration:   onExpiration,
		expiration3:    time.NewTimer(lifetime / 3 * 2),
		expiration2:    time.NewTimer(lifetime / 4 * 3),
		expiration1:    time.NewTimer(lifetime / 5 * 4),
		expiration:     time.NewTimer(lifetime),
		expirationTime: now.Add(lifetime),
		unwatch:        make(chan struct{}),
	}
}
