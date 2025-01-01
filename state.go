package ipv6disc

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

type State struct {
	macs                    map[string]*AddrCollection
	macsMutex               sync.RWMutex
	addrDefaultLifetime     time.Duration
	addrDefaultOnExpiration func(*Addr, AddrExpirationRemainingEvents)
}

// accepts default TTL and onExpiration function
func (s *State) Enlist(hw net.HardwareAddr, netipAddr netip.Addr, ttl time.Duration, onExpiration func(*Addr, AddrExpirationRemainingEvents)) (*Addr, bool) {
	s.macsMutex.Lock()
	defer s.macsMutex.Unlock()

	mac := hw.String()
	_, exists := s.macs[mac]
	if !exists {
		s.macs[mac] = NewAddrCollection()
	}

	if ttl == 0 {
		ttl = s.addrDefaultLifetime
	}

	if onExpiration == nil {
		onExpiration = s.addrDefaultOnExpiration
	}

	newAddr := NewAddr(hw, netipAddr, ttl, onExpiration)

	return s.macs[mac].Enlist(newAddr)
}

func (s *State) Filter(hws []net.HardwareAddr, prefixes []netip.Prefix) *AddrCollection {
	results := NewAddrCollection()

	s.macsMutex.Lock()
	defer s.macsMutex.Unlock()

	for _, prefix := range prefixes {
		for _, hw := range hws {
			collection, exists := s.macs[hw.String()]
			if exists {
				results.Join(collection.FilterPrefix(prefix))
			}
		}
	}

	return results
}

func (s *State) PrettyPrint(prefix string) string {
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

func NewState(lifetime time.Duration) *State {
	return &State{
		macs:                    make(map[string]*AddrCollection),
		addrDefaultLifetime:     lifetime,
		addrDefaultOnExpiration: func(addr *Addr, remainingEvents AddrExpirationRemainingEvents) {},
	}
}
