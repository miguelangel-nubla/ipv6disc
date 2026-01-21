package ipv6disc

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
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

// Register adds a discovered address to the state.
// It handles creation of new Addr objects, calling Seen, and logging "host identified" events.
// If onExpiration is nil, a default handler is used which logs "host expired".
func (s *State) Register(hw net.HardwareAddr, ip netip.Addr, source string, lifetime time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) (*Addr, bool) {
	if onExpiration == nil {
		onExpiration = func(expiredAddr *Addr, remainingEvents AddrExpirationRemainingEvents) {
			if remainingEvents == 0 && s.logger != nil {
				s.logger.Infow("host expired",
					zap.String("ipv6", netip.AddrFrom16(expiredAddr.As16()).String()),
					zap.String("mac", expiredAddr.Hw.String()),
					zap.String("source", source),
				)
			}
		}
	}

	newAddr := NewAddr(hw, ip, source, lifetime, onExpiration)
	addr, existing := s.Seen(newAddr, source)

	if !existing {
		addr.Watch()
		if s.logger != nil {
			s.logger.Infow("host identified",
				zap.String("ipv6", netip.AddrFrom16(ip.As16()).String()),
				zap.String("mac", hw.String()),
				zap.String("source", source),
			)
		}
	} else {
		if s.logger != nil {
			s.logger.Debugw("ttl refreshed",
				zap.String("ipv6", ip.String()),
				zap.String("mac", hw.String()),
				zap.String("source", source),
			)
		}
	}

	return addr, existing
}

// accepts default TTL and onExpiration function
func (s *State) Seen(addr *Addr, source ...string) (*Addr, bool) {
	s.macsMutex.Lock()
	defer s.macsMutex.Unlock()

	mac := addr.Hw.String()
	_, exists := s.macs[mac]
	if !exists {
		s.macs[mac] = NewAddrCollection()
	}

	return s.macs[mac].Seen(addr, source...)
}

func (s *State) FilterMACs(hws []net.HardwareAddr) *AddrCollection {
	results := NewAddrCollection()

	s.macsMutex.Lock()
	defer s.macsMutex.Unlock()

	for _, hw := range hws {
		collection, exists := s.macs[hw.String()]
		if exists {
			results.Join(collection)
		}
	}

	return results
}

func (s *State) PrettyPrint(prefix string, hideSensible bool) string {
	var result strings.Builder

	s.macsMutex.Lock()
	defer s.macsMutex.Unlock()

	fmt.Fprintf(&result, "%sDiscovery:\n", prefix)

	// Get the keys from the map
	keys := make([]string, 0, len(s.macs))
	for k := range s.macs {
		keys = append(keys, k)
	}

	// Sort the keys
	sort.Strings(keys)

	// Iterate ordered
	for _, key := range keys {
		fmt.Fprintf(&result, "%s    %s\n", prefix, key)
		fmt.Fprint(&result, s.macs[key].PrettyPrint(prefix+"        "))
	}

	return result.String()
}

func NewState() *State {
	return &State{
		macs: make(map[string]*AddrCollection),
	}
}
