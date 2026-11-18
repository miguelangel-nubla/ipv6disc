package ipv6disc

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestConfigInterfaces(t *testing.T) {
	for _, tt := range []struct {
		include, exclude []string
		used, unused     []string
	}{
		{nil, nil, []string{"eth0", "docker0", "veth12ab"}, nil},
		{[]string{"eth0"}, nil, []string{"eth0"}, []string{"eth1", "docker0"}},
		{[]string{"eth*", "br-lan"}, nil, []string{"eth0", "eth1", "br-lan"}, []string{"docker0", "br-1234"}},
		{nil, []string{"docker*", "veth*"}, []string{"eth0", "br-lan"}, []string{"docker0", "veth12ab"}},
		{[]string{"eth*"}, []string{"eth1"}, []string{"eth0"}, []string{"eth1", "wlan0"}},
	} {
		c := Config{Interfaces: tt.include, ExcludeInterfaces: tt.exclude}
		for _, name := range tt.used {
			if !c.usesInterface(name) {
				t.Errorf("%v, excluding %v: %s left out", tt.include, tt.exclude, name)
			}
		}
		for _, name := range tt.unused {
			if c.usesInterface(name) {
				t.Errorf("%v, excluding %v: %s used", tt.include, tt.exclude, name)
			}
		}
	}

	bad := DefaultConfig()
	bad.ExcludeInterfaces = []string{"docker["}
	if err := bad.validate(); err == nil {
		t.Error("a bad pattern: want an error")
	}
	bad = DefaultConfig()
	bad.IPv4.Lifetime = -time.Second
	if err := bad.validate(); err == nil {
		t.Error("a negative family lifetime: want an error")
	}
}

// The family's lifetime is what an address gets, whatever lifetime Register is given: the plugins
// give the global one.
func TestStateFamilyLifetimes(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:09")
	state := NewState()
	state.SetFamilies(true, true)
	state.SetLifetimes(0, 50*time.Millisecond)
	a4, _ := state.Register(mac, netip.MustParseAddr("192.0.2.1"), "test", time.Hour, nil)
	a6, _ := state.Register(mac, netip.MustParseAddr("2001:db8::1"), "test", time.Hour, nil)
	defer a6.Unwatch()
	if until := time.Until(a4.GetExpiration()); until > time.Second {
		t.Errorf("IPv4 expires in %s, want its family's 50ms", until)
	}
	if until := time.Until(a6.GetExpiration()); until < 59*time.Minute {
		t.Errorf("IPv6 expires in %s, want the hour given", until)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(state.FilterMACs([]net.HardwareAddr{mac}).Filter4().Get()) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("the IPv4 address didn't expire")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStateSubscribe(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:0a")
	state := NewState()
	changes, cancel := state.Subscribe()
	other, cancelOther := state.Subscribe()
	defer cancelOther()

	expectChange := func(what string, want bool) {
		t.Helper()
		select {
		case <-changes:
			if !want {
				t.Errorf("%s: a change told", what)
			}
		case <-time.After(200 * time.Millisecond):
			if want {
				t.Errorf("%s: no change told", what)
			}
		}
	}

	addr, _ := state.Register(mac, netip.MustParseAddr("2001:db8::1"), "eth0", 300*time.Millisecond, nil)
	expectChange("a new address", true)
	state.Register(mac, netip.MustParseAddr("2001:db8::1"), "eth0", 300*time.Millisecond, nil)
	expectChange("seen again", false)
	state.Register(mac, netip.MustParseAddr("2001:db8::1"), "router", 300*time.Millisecond, nil)
	expectChange("a new source", true)
	select {
	case <-changes:
	case <-time.After(2 * time.Second):
		t.Error("the expiration: no change told")
	}
	if addr.Valid() {
		t.Error("the address is still valid")
	}

	// Changes not received are told once; every subscriber hears.
	<-other
	for i := range 3 {
		a, _ := state.Register(mac, netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(10 + i)}), "eth0", time.Hour, nil)
		defer a.Unwatch()
	}
	expectChange("three new addresses", true)
	expectChange("three new addresses, again", false)
	select {
	case <-other:
	default:
		t.Error("the other subscriber heard nothing")
	}

	cancel()
	a, _ := state.Register(mac, netip.MustParseAddr("2001:db8::99"), "eth0", time.Hour, nil)
	defer a.Unwatch()
	expectChange("after cancel", false)
}
