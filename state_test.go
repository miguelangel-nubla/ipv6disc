package ipv6disc

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
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

func TestWorkerPrefixesAndSolicitWithoutListeners(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), time.Minute, time.Minute, false, false)
	w.protocolConns["2001:db8:1::5"] = &InterfaceProcesses{InterfaceName: "eth0", Address: netip.MustParseAddr("2001:db8:1::5")}
	w.protocolConns["2001:db8:1::6"] = &InterfaceProcesses{InterfaceName: "eth0", Address: netip.MustParseAddr("2001:db8:1::6")}
	w.protocolConns["fd00:2::7"] = &InterfaceProcesses{InterfaceName: "eth1", Address: netip.MustParseAddr("fd00:2::7")}

	if got := len(w.Prefixes()); got != 2 {
		t.Errorf("Prefixes: got %d, want 2 (one per /64)", got)
	}
	// No NDP connection, no prefix: nothing to send on, and no error.
	if sent, err := w.Solicit(netip.MustParseAddr("2001:db8:9::1")); sent != 0 || err != nil {
		t.Errorf("Solicit on another prefix: %d, %v", sent, err)
	}
}
