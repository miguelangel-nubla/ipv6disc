package ipv6disc

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

type Addr struct {
	netip.Addr
	Hw      net.HardwareAddr
	Sources []string

	lifetime     time.Duration
	onExpiration func(*Addr, AddrExpirationRemainingEvents)

	expiration3    *time.Timer
	expiration2    *time.Timer
	expiration1    *time.Timer
	expiration     *time.Timer
	expirationTime time.Time

	unwatch chan bool

	mutex sync.RWMutex
}

type AddrExpirationRemainingEvents int

func (a *Addr) resetTimers(resetExpirationTime bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.expiration3.Reset(a.lifetime / 3 * 2)
	a.expiration2.Reset(a.lifetime / 4 * 3)
	a.expiration1.Reset(a.lifetime / 5 * 4)
	a.expiration.Reset(a.lifetime)

	if resetExpirationTime {
		a.expirationTime = time.Now().Add(a.lifetime)
	}
}

func (a *Addr) Valid() bool {
	return a.expirationTime.After(time.Now())
}

func (a *Addr) GetExpiration() time.Time {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	return a.expirationTime
}

func (a *Addr) Seen(source ...string) {
	a.resetTimers(true)
	if len(source) > 0 {
		a.mutex.Lock()
		// Check if source already exists in the slice
		found := false
		for _, s := range a.Sources {
			if s == source[0] {
				found = true
				break
			}
		}
		if !found {
			a.Sources = append(a.Sources, source[0])
		}
		a.mutex.Unlock()
	}
}

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
				return
			case <-a.unwatch:
				return
			}
		}
	}()

	a.resetTimers(false)
}

func (a *Addr) Unwatch() {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.expiration3.Stop()
	a.expiration2.Stop()
	a.expiration1.Stop()
	a.expiration.Stop()

	close(a.unwatch)
}

func NewAddr(hw net.HardwareAddr, addr netip.Addr, source string, lifetime time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) *Addr {
	return &Addr{
		Addr:           addr,
		Hw:             hw,
		Sources:        []string{source},
		lifetime:       lifetime,
		onExpiration:   onExpiration,
		expiration3:    time.NewTimer(lifetime / 3 * 2),
		expiration2:    time.NewTimer(lifetime / 4 * 3),
		expiration1:    time.NewTimer(lifetime / 5 * 4),
		expiration:     time.NewTimer(lifetime),
		expirationTime: time.Now().Add(lifetime),
		unwatch:        make(chan bool),
	}
}
