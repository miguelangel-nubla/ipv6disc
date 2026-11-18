package ipv6disc

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

type State struct {
	macs      map[string]*AddrCollection
	macsMutex sync.RWMutex
	logger    *zap.SugaredLogger
}

func (s *State) SetLogger(l *zap.SugaredLogger) {
	s.logger = l
}

// Register adds a discovered address to the state, or refreshes the one already there.
// onExpiration, which can be nil, is called on each expiration event of a new address. When the
// address expires it is logged and taken out of the state, unless it was seen again meanwhile.
func (s *State) Register(hw net.HardwareAddr, ip netip.Addr, source string, lifetime time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) (*Addr, bool) {
	expire := func(expiredAddr *Addr, remainingEvents AddrExpirationRemainingEvents) {
		if onExpiration != nil {
			onExpiration(expiredAddr, remainingEvents)
		}
		if remainingEvents != 0 || !s.remove(expiredAddr) {
			return
		}
		if s.logger != nil {
			s.logger.Infow("host expired",
				zap.String("ipv6", expiredAddr.WithZone("").String()),
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
				zap.String("ipv6", ip.WithZone("").String()),
				zap.String("mac", hw.String()),
				zap.String("source", source),
			)
		}
	} else if s.logger != nil {
		s.logger.Debugw("ttl refreshed",
			zap.String("ipv6", ip.String()),
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
