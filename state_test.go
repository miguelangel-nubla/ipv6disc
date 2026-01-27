package ipv6disc

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetAll(t *testing.T) {
	state := NewState()

	// 1. Register a dummy host
	ip, _ := netip.ParseAddr("fe80::1")
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:08")
	state.Register(mac, ip, "test", time.Hour, nil)

	// 2. Call GetAll
	entries := state.GetAll()

	// 3. Verify
	assert.Len(t, entries, 1)
	assert.Contains(t, entries, "00:1a:2b:3c:4d:08")

	collection := entries["00:1a:2b:3c:4d:08"]
	addrs := collection.Get()
	assert.Len(t, addrs, 1)
	assert.Equal(t, mac.String(), addrs[0].Hw.String())
}
