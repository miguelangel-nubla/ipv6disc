package ipv6disc

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

type AddrCollection struct {
	// string in key avoids looping over Addr.String() in the map
	addresses      map[string]*Addr
	addressesMutex sync.RWMutex
}

func (c *AddrCollection) Add(addr *Addr) (*Addr, bool) {
	c.addressesMutex.Lock()
	defer c.addressesMutex.Unlock()

	// Normalize address by removing zone for map key
	addString := addr.WithZone("").String()

	existing := false
	if c.Contains(addr) {
		existing = true
	} else {
		c.addresses[addString] = addr
	}

	return c.addresses[addString], existing
}

func (c *AddrCollection) Seen(addr *Addr, source ...string) (*Addr, bool) {
	addr, existing := c.Add(addr)
	if existing {
		addr.Seen(source...)
	}

	return addr, existing
}

func (c *AddrCollection) Remove(addr *Addr) {
	c.addressesMutex.Lock()
	defer c.addressesMutex.Unlock()

	if c.Contains(addr) {
		// Normalize address by removing zone for map key
		key := addr.WithZone("").String()
		c.addresses[key].Unwatch()
		delete(c.addresses, key)
	}
}

func (c *AddrCollection) Join(addrCollection *AddrCollection) {
	c.addressesMutex.Lock()
	defer c.addressesMutex.Unlock()

	addrCollection.addressesMutex.RLock()
	defer addrCollection.addressesMutex.RUnlock()

	for key, addr := range addrCollection.addresses {
		c.addresses[key] = addr
	}
}

func (c *AddrCollection) Contains(addr *Addr) bool {
	// Normalize address by removing zone for map key
	_, ok := c.addresses[addr.WithZone("").String()]
	return ok
}

func (c *AddrCollection) Equal(addrCollection *AddrCollection) bool {
	c.addressesMutex.RLock()
	defer c.addressesMutex.RUnlock()
	addrCollection.addressesMutex.RLock()
	defer addrCollection.addressesMutex.RUnlock()

	if len(c.addresses) != len(addrCollection.addresses) {
		return false
	}

	for addrKey := range c.addresses {
		if _, ok := addrCollection.addresses[addrKey]; !ok {
			return false
		}
	}

	return true
}

func (c *AddrCollection) Copy() *AddrCollection {
	c.addressesMutex.RLock()
	defer c.addressesMutex.RUnlock()

	result := NewAddrCollection()
	for _, addr := range c.addresses {
		result.Add(addr)
	}
	return result
}

func (c *AddrCollection) FilterSubnets(subnets []netip.Prefix) *AddrCollection {
	c.addressesMutex.RLock()
	defer c.addressesMutex.RUnlock()

	result := NewAddrCollection()

	for _, addr := range c.addresses {
		ip := addr.Addr.WithZone("")
		for _, sub := range subnets {
			if sub.Contains(ip) {
				result.Add(addr)
			}
		}
	}

	return result
}

func (c *AddrCollection) Filter6() *AddrCollection {
	c.addressesMutex.RLock()
	defer c.addressesMutex.RUnlock()

	result := NewAddrCollection()
	for _, addr := range c.addresses {
		if addr.Addr.Is6() {
			result.Add(addr)
		}
	}
	return result
}

func (c *AddrCollection) Filter4() *AddrCollection {
	c.addressesMutex.RLock()
	defer c.addressesMutex.RUnlock()

	result := NewAddrCollection()
	for _, addr := range c.addresses {
		if addr.Addr.Is4() {
			result.Add(addr)
		}
	}
	return result
}

func (c *AddrCollection) FilterValid() *AddrCollection {
	c.addressesMutex.RLock()
	defer c.addressesMutex.RUnlock()

	result := NewAddrCollection()
	for _, addr := range c.addresses {
		if addr.Valid() {
			result.Add(addr)
		}
	}
	return result
}

func (c *AddrCollection) Get() []*Addr {
	c.addressesMutex.RLock()
	defer c.addressesMutex.RUnlock()

	keys := make([]string, 0, len(c.addresses))
	for key := range c.addresses {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	addresses := make([]*Addr, 0, len(c.addresses))
	for _, key := range keys {
		addresses = append(addresses, c.addresses[key])
	}

	return addresses
}

func (c *AddrCollection) Strings() []string {
	c.addressesMutex.RLock()
	defer c.addressesMutex.RUnlock()

	addressesMap := make(map[string]bool)
	for _, addr := range c.addresses {
		ip := addr.WithZone("").String()
		addressesMap[ip] = true
	}

	return slices.Collect(maps.Keys(addressesMap))
}

func (c *AddrCollection) PrettyPrint(prefix string) string {
	c.addressesMutex.RLock()
	defer c.addressesMutex.RUnlock()

	var result strings.Builder

	// Get the keys from the map
	keys := make([]netip.Addr, 0, len(c.addresses))
	for _, addr := range c.addresses {
		keys = append(keys, addr.Addr)
	}

	// Sort the keys
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Less(keys[j])
	})

	// Iterate ordered
	for _, key := range keys {
		// Normalize address by removing zone for map key
		ipAddressInfo := c.addresses[key.WithZone("").String()]
		fmt.Fprintf(&result, prefix+"%s %s %s\n", ipAddressInfo.Addr.WithZone("").String(), time.Until(ipAddressInfo.GetExpiration()).Round(time.Second), strings.Join(ipAddressInfo.Sources, ","))
	}

	return result.String()
}

func NewAddrCollection() *AddrCollection {
	return &AddrCollection{addresses: make(map[string]*Addr)}
}
