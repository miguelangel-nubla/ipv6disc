package ipv6disc

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// AddrCollection is a set of addresses, keyed by the address without its zone.
type AddrCollection struct {
	addresses      map[string]*Addr
	addressesMutex sync.RWMutex
}

func addrKey(addr *Addr) string {
	return addr.WithZone("").String()
}

// Add puts the address in the collection unless it already has one with the same IP. It returns the
// one the collection holds, and whether it was there already.
func (c *AddrCollection) Add(addr *Addr) (*Addr, bool) {
	c.addressesMutex.Lock()
	defer c.addressesMutex.Unlock()

	key := addrKey(addr)
	if existing, ok := c.addresses[key]; ok {
		return existing, true
	}
	c.addresses[key] = addr
	return addr, false
}

// Seen adds the address, or marks the one already there as seen by source.
func (c *AddrCollection) Seen(addr *Addr, source ...string) (*Addr, bool) {
	addr, existing, _ := c.seen(addr, source...)
	return addr, existing
}

// seen is Seen, telling also whether source is new to an address already there.
func (c *AddrCollection) seen(newAddr *Addr, source ...string) (*Addr, bool, bool) {
	addr, existing := c.Add(newAddr)
	newSource := false
	if existing {
		newSource = addr.seenBy(newAddr.lifetime, len(newAddr.interfaces) > 0, source...)
	}
	return addr, existing, newSource
}

// Remove takes the address out of the collection, and stops its expiration events.
func (c *AddrCollection) Remove(addr *Addr) {
	c.addressesMutex.Lock()
	defer c.addressesMutex.Unlock()

	key := addrKey(addr)
	if existing, ok := c.addresses[key]; ok {
		existing.Unwatch()
		delete(c.addresses, key)
	}
}

// removeExpired removes addr if the collection still holds this very address and it was not seen
// again since it expired. It returns whether it did, and whether the collection is left empty.
func (c *AddrCollection) removeExpired(addr *Addr) (removed bool, empty bool) {
	c.addressesMutex.Lock()
	defer c.addressesMutex.Unlock()

	key := addrKey(addr)
	if existing, ok := c.addresses[key]; ok && existing == addr && !addr.Valid() {
		addr.Unwatch()
		delete(c.addresses, key)
		removed = true
	}
	return removed, len(c.addresses) == 0
}

func (c *AddrCollection) Join(addrCollection *AddrCollection) {
	if c == addrCollection {
		return
	}

	c.addressesMutex.Lock()
	defer c.addressesMutex.Unlock()

	addrCollection.addressesMutex.RLock()
	defer addrCollection.addressesMutex.RUnlock()

	maps.Copy(c.addresses, addrCollection.addresses)
}

func (c *AddrCollection) Contains(addr *Addr) bool {
	c.addressesMutex.RLock()
	defer c.addressesMutex.RUnlock()

	_, ok := c.addresses[addrKey(addr)]
	return ok
}

// Equal tells whether both collections hold the same IPs.
func (c *AddrCollection) Equal(addrCollection *AddrCollection) bool {
	if c == addrCollection {
		return true
	}

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

// filter returns a new collection with the addresses keep accepts.
func (c *AddrCollection) filter(keep func(*Addr) bool) *AddrCollection {
	c.addressesMutex.RLock()
	defer c.addressesMutex.RUnlock()

	result := NewAddrCollection()
	for key, addr := range c.addresses {
		if keep(addr) {
			result.addresses[key] = addr
		}
	}
	return result
}

func (c *AddrCollection) Copy() *AddrCollection {
	return c.filter(func(*Addr) bool { return true })
}

func (c *AddrCollection) FilterSubnets(subnets []netip.Prefix) *AddrCollection {
	return c.filter(func(addr *Addr) bool {
		ip := addr.WithZone("")
		return slices.ContainsFunc(subnets, func(sub netip.Prefix) bool { return sub.Contains(ip) })
	})
}

func (c *AddrCollection) Filter6() *AddrCollection {
	return c.filter(func(addr *Addr) bool { return addr.Is6() })
}

func (c *AddrCollection) Filter4() *AddrCollection {
	return c.filter(func(addr *Addr) bool { return addr.Is4() })
}

func (c *AddrCollection) FilterValid() *AddrCollection {
	return c.filter((*Addr).Valid)
}

// Get returns the addresses, sorted by IP.
func (c *AddrCollection) Get() []*Addr {
	c.addressesMutex.RLock()
	defer c.addressesMutex.RUnlock()

	addresses := slices.Collect(maps.Values(c.addresses))
	slices.SortFunc(addresses, func(a, b *Addr) int {
		return a.WithZone("").Compare(b.WithZone(""))
	})
	return addresses
}

// Strings returns the IPs, without zones, sorted.
func (c *AddrCollection) Strings() []string {
	addresses := c.Get()
	result := make([]string, len(addresses))
	for i, addr := range addresses {
		result[i] = addrKey(addr)
	}
	return result
}

func (c *AddrCollection) PrettyPrint(prefix string) string {
	var result strings.Builder
	for _, addr := range c.Get() {
		fmt.Fprintf(&result, "%s%s %s %s\n", prefix, addrKey(addr), time.Until(addr.GetExpiration()).Round(time.Second), strings.Join(addr.Sources(), ","))
	}
	return result.String()
}

func NewAddrCollection() *AddrCollection {
	return &AddrCollection{addresses: make(map[string]*Addr)}
}
