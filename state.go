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

type State struct {
	macs      map[string]*AddrCollection
	macsMutex sync.RWMutex
	logger    *zap.SugaredLogger
	// The families it takes: IPv6 only by default.
	noIPv6 atomic.Bool
	ipv4   atomic.Bool
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
// of a family the state doesn't take is left out: it returns nil and true, as if known.
// onExpiration, which can be nil, is called on each expiration event of a new address. When the
// address expires it is logged and taken out of the state, unless it was seen again meanwhile.
func (s *State) Register(hw net.HardwareAddr, ip netip.Addr, source string, lifetime time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) (*Addr, bool) {
	ip = ip.Unmap()
	if ip.Is4() && !s.IPv4() || ip.Is6() && !s.IPv6() {
		return nil, true
	}

	expire := func(expiredAddr *Addr, remainingEvents AddrExpirationRemainingEvents) {
		if onExpiration != nil {
			onExpiration(expiredAddr, remainingEvents)
		}
		if remainingEvents != 0 || !s.remove(expiredAddr) {
			return
		}
		if s.logger != nil {
			s.logger.Infow("host expired",
				zap.String("ip", expiredAddr.WithZone("").String()),
				zap.String("mac", expiredAddr.Hw.String()),
				zap.String("source", source),
			)
		}
	}

	addr, existing := s.Seen(NewAddr(hw, ip, source, lifetime, expire), source)

	if !existing {
		addr.Watch()
		if s.logger != nil {
			s.logger.Infow("host identified",
				zap.String("ip", ip.WithZone("").String()),
				zap.String("mac", hw.String()),
				zap.String("source", source),
			)
		}
	} else if s.logger != nil {
		s.logger.Debugw("ttl refreshed",
			zap.String("ip", ip.String()),
			zap.String("mac", hw.String()),
			zap.String("source", source),
		)
	}

	return addr, existing
}

// Seen adds the address to the collection of its MAC, or marks the one there as seen.
func (s *State) Seen(addr *Addr, source ...string) (*Addr, bool) {
	s.macsMutex.Lock()
	defer s.macsMutex.Unlock()

	mac := addr.Hw.String()
	collection, exists := s.macs[mac]
	if !exists {
		collection = NewAddrCollection()
		s.macs[mac] = collection
	}

	return collection.Seen(addr, source...)
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
