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
	sources        []string
	// The local interfaces that saw it: sources too, but a plugin can have an interface's name.
	interfaces []string
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
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Before the timers: the expiration timer can't fire before the address is invalid.
	now := time.Now()
	a.expiration3.Reset(a.lifetime / 3 * 2)
	a.expiration2.Reset(a.lifetime / 4 * 3)
	a.expiration1.Reset(a.lifetime / 5 * 4)
	a.expiration.Reset(a.lifetime)

	if resetExpirationTime {
		a.expirationTime = now.Add(a.lifetime)
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

// Sources returns the names of what has seen the address: interfaces and plugins.
func (a *Addr) Sources() []string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	return slices.Clone(a.sources)
}

// Interfaces returns the local interfaces that have seen the address: of its sources, those of
// the worker's own local discovery, not plugins nor other callers of State.Register.
func (a *Addr) Interfaces() []string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	return slices.Clone(a.interfaces)
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

// Seen extends the address lifetime, and records the source if one is given.
func (a *Addr) Seen(source ...string) {
	a.seenBy(&Addr{}, source...)
}

// seenBy is Seen, by a registration of the same address, telling whether the source is new: its
// lifetime, when not zero, replaces the address's from now on, as the latest registration says how
// long it stays; it says whether the source is a local interface, and whether the address is this
// machine's, and temporary.
func (a *Addr) seenBy(by *Addr, source ...string) bool {
	local := len(by.interfaces) > 0
	a.mutex.Lock()
	if by.lifetime > 0 {
		a.lifetime = by.lifetime
	}
	if by.self {
		a.self, a.temporary = true, by.temporary
	}
	if a.notify == nil {
		a.notify = by.notify
	}
	a.mutex.Unlock()
	a.resetTimers(true)
	if len(source) == 0 {
		return false
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if local && !slices.Contains(a.interfaces, source[0]) {
		a.interfaces = append(a.interfaces, source[0])
	}
	if slices.Contains(a.sources, source[0]) {
		return false
	}
	a.sources = append(a.sources, source[0])
	return true
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
	if !a.self || !slices.Contains(a.interfaces, iface) {
		return false, false
	}
	differs := func(name string) bool { return name != iface }
	a.interfaces = filterStrings(a.interfaces, differs)
	a.sources = filterStrings(a.sources, differs)
	return true, len(a.interfaces) == 0
}

// filterStrings returns a new slice of those keep accepts: Sources and Interfaces give copies, but
// nothing is written in place of what a reader may hold.
func filterStrings(values []string, keep func(string) bool) []string {
	var result []string
	for _, v := range values {
		if keep(v) {
			result = append(result, v)
		}
	}
	return result
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
	return &Addr{
		Addr:           addr,
		Hw:             hw,
		sources:        []string{source},
		lifetime:       lifetime,
		onExpiration:   onExpiration,
		expiration3:    time.NewTimer(lifetime / 3 * 2),
		expiration2:    time.NewTimer(lifetime / 4 * 3),
		expiration1:    time.NewTimer(lifetime / 5 * 4),
		expiration:     time.NewTimer(lifetime),
		expirationTime: time.Now().Add(lifetime),
		unwatch:        make(chan struct{}),
	}
}
