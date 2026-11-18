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
	w := NewWorker(zap.NewNop().Sugar(), Config{Lifetime: time.Minute, Rediscover: time.Minute, IPv6: Family{Enabled: true}})
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

func TestExpiredAddressesLeaveTheState(t *testing.T) {
	state := NewState()
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:08")
	expired := make(chan AddrExpirationRemainingEvents, 4)
	state.Register(mac, netip.MustParseAddr("2001:db8::1"), "test", 50*time.Millisecond, func(_ *Addr, remaining AddrExpirationRemainingEvents) {
		expired <- remaining
	})
	kept, _ := state.Register(mac, netip.MustParseAddr("2001:db8::2"), "test", time.Hour, nil)

	for remaining := range expired {
		if remaining == 0 {
			break
		}
	}
	// The expiration callback runs before the removal.
	assert.Eventually(t, func() bool {
		return len(state.GetAll()[mac.String()].Get()) == 1
	}, time.Second, 5*time.Millisecond)
	assert.Equal(t, []*Addr{kept}, state.GetAll()[mac.String()].Get())

	state.remove(kept)
	assert.Len(t, state.GetAll(), 1, "an address still valid stays")
	kept.Unwatch()
}

func TestMACWithoutAddressesLeavesTheState(t *testing.T) {
	state := NewState()
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:08")
	state.Register(mac, netip.MustParseAddr("2001:db8::1"), "test", 20*time.Millisecond, nil)
	assert.Eventually(t, func() bool { return len(state.GetAll()) == 0 }, time.Second, 5*time.Millisecond)
}

func TestSeenAddsSources(t *testing.T) {
	state := NewState()
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:08")
	addr, _ := state.Register(mac, netip.MustParseAddr("2001:db8::1"), "eth0", time.Hour, nil)
	defer addr.Unwatch()

	done := make(chan bool)
	go func() {
		for range 100 {
			addr.Sources()
		}
		done <- true
	}()
	state.Register(mac, netip.MustParseAddr("2001:db8::1"), "router", time.Hour, nil)
	state.Register(mac, netip.MustParseAddr("2001:db8::1"), "eth0", time.Hour, nil)
	<-done
	assert.Equal(t, []string{"eth0", "router"}, addr.Sources())
}

// An address seen again around its expiration keeps its events, and expires once left alone.
func TestAddressSeenAtExpirationStillExpires(t *testing.T) {
	for range 50 {
		state := NewState()
		mac, _ := net.ParseMAC("00:1a:2b:3c:4d:08")
		ip := netip.MustParseAddr("2001:db8::1")
		lifetime := 2 * time.Millisecond
		deadline := time.Now().Add(20 * lifetime)
		for time.Now().Before(deadline) {
			state.Register(mac, ip, "test", lifetime, nil)
			time.Sleep(lifetime * 3 / 4)
		}
		assert.Eventually(t, func() bool { return len(state.GetAll()) == 0 }, time.Second, time.Millisecond)
	}
}

func TestStateFamilies(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:08")
	for _, tt := range []struct{ ipv6, ipv4, want6, want4 bool }{
		{true, false, true, false}, // the default
		{true, true, true, true},
		{false, true, false, true},
	} {
		state := NewState()
		if tt.ipv6 != true || tt.ipv4 {
			state.SetFamilies(tt.ipv6, tt.ipv4)
		}
		a6, _ := state.Register(mac, netip.MustParseAddr("2001:db8::1"), "test", time.Hour, nil)
		a4, _ := state.Register(mac, netip.MustParseAddr("192.0.2.1"), "test", time.Hour, nil)
		if (a6 != nil) != tt.want6 || (a4 != nil) != tt.want4 || state.IPv6() != tt.ipv6 || state.IPv4() != tt.ipv4 {
			t.Errorf("families %v/%v: registered IPv6 %v, IPv4 %v", tt.ipv6, tt.ipv4, a6 != nil, a4 != nil)
		}
		for _, a := range []*Addr{a6, a4} {
			if a != nil {
				a.Unwatch()
			}
		}
	}
}

func TestConfigValidate(t *testing.T) {
	if err := DefaultConfig().validate(); err != nil {
		t.Errorf("the default: %v", err)
	}
	// Active without listening probes nothing: not an error, as with listening turned off alone.
	quiet := DefaultConfig()
	quiet.IPv4 = Family{Enabled: true, Active: true}
	if err := quiet.validate(); err != nil || quiet.probesIPv4() {
		t.Errorf("IPv4 active without listening: %v, probing %v", err, quiet.probesIPv4())
	}
	bad := DefaultConfig()
	bad.Lifetime = 0
	if err := bad.validate(); err == nil {
		t.Error("no lifetime: want an error")
	}
	// Active without listening, on a family off: nothing runs, nothing to refuse.
	off := DefaultConfig()
	off.IPv4 = Family{Active: true}
	if err := off.validate(); err != nil {
		t.Errorf("a family off: %v", err)
	}
}
