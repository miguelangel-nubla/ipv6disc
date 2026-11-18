package ipv6disc

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func collectionOf(ips ...string) *AddrCollection {
	c := NewAddrCollection()
	for _, ip := range ips {
		c.Add(NewAddr(nil, netip.MustParseAddr(ip), "test", time.Hour, nil))
	}
	return c
}

func TestAddrCollectionAdd(t *testing.T) {
	c := NewAddrCollection()
	first, existing := c.Add(NewAddr(nil, netip.MustParseAddr("fe80::1%eth0"), "a", time.Hour, nil))
	assert.False(t, existing)
	// The same IP in another zone is the same address.
	again, existing := c.Add(NewAddr(nil, netip.MustParseAddr("fe80::1%eth1"), "b", time.Hour, nil))
	assert.True(t, existing)
	assert.Same(t, first, again)
	assert.True(t, c.Contains(NewAddr(nil, netip.MustParseAddr("fe80::1"), "c", time.Hour, nil)))
}

func TestAddrCollectionGetIsSorted(t *testing.T) {
	c := collectionOf("2001:db8::10", "192.0.2.1", "2001:db8::9", "fe80::1%eth0")
	assert.Equal(t, []string{"192.0.2.1", "2001:db8::9", "2001:db8::10", "fe80::1"}, c.Strings())
}

func TestAddrCollectionFilters(t *testing.T) {
	c := collectionOf("192.0.2.1", "2001:db8::1", "fd00::1")
	assert.Equal(t, []string{"192.0.2.1"}, c.Filter4().Strings())
	assert.Equal(t, []string{"2001:db8::1", "fd00::1"}, c.Filter6().Strings())
	assert.Equal(t, []string{"fd00::1"}, c.FilterSubnets([]netip.Prefix{netip.MustParsePrefix("fc00::/7")}).Strings())
	assert.Equal(t, c.Strings(), c.Copy().Strings())

	expired := NewAddr(nil, netip.MustParseAddr("2001:db8::2"), "test", -time.Second, nil)
	c.Add(expired)
	assert.NotContains(t, c.FilterValid().Strings(), "2001:db8::2")
}

func TestAddrCollectionEqualAndJoin(t *testing.T) {
	a, b := collectionOf("2001:db8::1"), collectionOf("2001:db8::1")
	assert.True(t, a.Equal(b))
	assert.True(t, a.Equal(a))
	b.Join(collectionOf("2001:db8::2"))
	assert.False(t, a.Equal(b))
	b.Join(b) // no deadlock
	assert.Equal(t, []string{"2001:db8::1", "2001:db8::2"}, b.Strings())
}

func TestAddrCollectionRemove(t *testing.T) {
	c := collectionOf("2001:db8::1")
	addr := c.Get()[0]
	c.Remove(addr)
	assert.Empty(t, c.Get())
	addr.Unwatch() // already unwatched by Remove: no panic
}
