package ipv6disc

import (
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
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

// seen is Seen, telling also whether source is new to an address already there. A source given is
// a record of newAddr's, reported by it, when newAddr has none of it.
func (c *AddrCollection) seen(newAddr *Addr, source ...string) (*Addr, bool, bool) {
	if len(source) > 0 && source[0] != "" {
		newAddr.mutex.Lock()
		has := false
		for _, r := range newAddr.records {
			if r.source() == source[0] {
				has = true
			}
		}
		if !has {
			now := time.Now()
			newAddr.addRecord(Record{By: source[0], FirstSeen: now, LastSeen: now, Lifetime: newAddr.lifetime})
		}
		newAddr.mutex.Unlock()
	}
	addr, existing := c.Add(newAddr)
	newSource := false
	if existing {
		newSource = addr.seenBy(newAddr)
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

// removeSelf is State.removeSelf, of the collection of the MAC. It returns the address if iface
// had it as this machine's, whether it was taken out, and whether the collection is left empty.
func (c *AddrCollection) removeSelf(ip netip.Addr, iface string) (addr *Addr, removed bool, empty bool) {
	c.addressesMutex.Lock()
	defer c.addressesMutex.Unlock()

	key := ip.Unmap().WithZone("").String()
	if existing, ok := c.addresses[key]; ok {
		if was, last := existing.leaves(iface); was {
			addr = existing
			if last {
				existing.Unwatch()
				delete(c.addresses, key)
				removed = true
			}
		}
	}
	return addr, removed, len(c.addresses) == 0
}

// Join adds the addresses of addrCollection to c. It locks c, then addrCollection, as Equal does:
// two collections must not be joined, or compared, both ways at once.
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
	var t pretty.Table
	c.rows(&t, "", time.Now())
	return t.Render(prefix)
}

// rows adds the addresses to t, each with how long it has left, how long it has been seen and
// whether it is this host's; and under it its records, as it was seen, each with its own times:
// one attached, as a lease, keeps the address no longer than the others, and has a note in place
// of its time.
func (c *AddrCollection) rows(t *pretty.Table, indent string, now time.Time) {
	for _, addr := range c.Get() {
		var notes string
		switch {
		case addr.Temporary():
			notes = "(this host, temporary)"
		case addr.Self():
			notes = "(this host)"
		}
		records := addr.Records()
		t.Row(indent+addrKey(addr), addr.GetExpiration().Sub(now), now.Sub(firstSeen(records)), notes)
		for _, r := range records {
			if r.Attached() {
				t.RowNote(indent+"    "+r.String(), "(lease)", now.Sub(r.FirstSeen), "")
				continue
			}
			t.Row(indent+"    "+r.String(), r.Expiration().Sub(now), now.Sub(r.FirstSeen), "")
		}
	}
}

// firstSeen is the first time of records, as an address was first seen.
func firstSeen(records []Record) time.Time {
	var first time.Time
	for _, r := range records {
		if first.IsZero() || r.FirstSeen.Before(first) {
			first = r.FirstSeen
		}
	}
	return first
}

func NewAddrCollection() *AddrCollection {
	return &AddrCollection{addresses: make(map[string]*Addr)}
}
