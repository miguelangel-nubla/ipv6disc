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

	expiration3    *time.Timer
	expiration2    *time.Timer
	expiration1    *time.Timer
	expiration     *time.Timer
	expirationTime time.Time
	sources        []string
	// The local interfaces that saw it: sources too, but a plugin can have an interface's name.
	interfaces []string

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

// Seen extends the address lifetime, and records the source if one is given.
func (a *Addr) Seen(source ...string) {
	a.seenBy(0, false, source...)
}

// seenBy is Seen, telling whether the source is new. A lifetime, when not zero, replaces the
// address's from now on: the latest registration says how long it stays. local says the source is
// a local interface.
func (a *Addr) seenBy(lifetime time.Duration, local bool, source ...string) bool {
	if lifetime > 0 {
		a.mutex.Lock()
		a.lifetime = lifetime
		a.mutex.Unlock()
	}
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
func (a *Addr) Watch() {
	a.mutex.Lock()
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
