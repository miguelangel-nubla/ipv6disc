package ipv6disc

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

type State struct {
	macs      map[string]*AddrCollection
	macsMutex sync.RWMutex
}

// accepts default TTL and onExpiration function
func (s *State) Seen(addr *Addr) (*Addr, bool) {
	s.macsMutex.Lock()
	defer s.macsMutex.Unlock()

	mac := addr.Hw.String()
	_, exists := s.macs[mac]
	if !exists {
		s.macs[mac] = NewAddrCollection()
	}

	return s.macs[mac].Seen(addr)
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
