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

	unwatch     chan struct{}
	unwatchOnce sync.Once

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

// Seen extends the address lifetime, and records the source if one is given.
func (a *Addr) Seen(source ...string) {
	a.resetTimers(true)
	if len(source) > 0 {
		a.mutex.Lock()
		if !slices.Contains(a.sources, source[0]) {
			a.sources = append(a.sources, source[0])
		}
		a.mutex.Unlock()
	}
}

// Watch calls onExpiration on each of the expiration events, until Unwatch is called. An address
// seen again after it expired has its events again.
func (a *Addr) Watch() {
	go func() {
		for {
			select {
			case <-a.expiration3.C:
				a.onExpiration(a, 3)
			case <-a.expiration2.C:
				a.onExpiration(a, 2)
			case <-a.expiration1.C:
				a.onExpiration(a, 1)
			case <-a.expiration.C:
				a.onExpiration(a, 0)
			case <-a.unwatch:
				return
			}
		}
	}()

	a.resetTimers(false)
}

// Unwatch stops the expiration events. It can be called more than once.
func (a *Addr) Unwatch() {
	a.unwatchOnce.Do(func() {
		a.mutex.Lock()
		defer a.mutex.Unlock()

		a.expiration3.Stop()
		a.expiration2.Stop()
		a.expiration1.Stop()
		a.expiration.Stop()

		close(a.unwatch)
	})
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
