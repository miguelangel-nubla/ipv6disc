package ipv6disc

import (
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"go.uber.org/zap"
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

func TestConfigDefaults(t *testing.T) {
	probing := Family{Enabled: true, Listen: true, Active: true}
	ipv4 := probing
	ipv4.Lifetime = 3 * time.Minute
	c := Config{Lifetime: time.Hour, IPv6: probing, IPv4: ipv4}.withDefaults()
	if c.IPv6.Lifetime != time.Hour || c.IPv4.Lifetime != 3*time.Minute {
		t.Errorf("family lifetimes: %s, %s", c.IPv6.Lifetime, c.IPv4.Lifetime)
	}
	// A third of the shortest lifetime of the families on: a quiet host is probed before it expires.
	if c.Rediscover != time.Minute {
		t.Errorf("rediscover: %s", c.Rediscover)
	}
	// Of the families that don't probe, off or listening only, none counts.
	for _, ipv4 := range []Family{{Lifetime: time.Minute}, {Enabled: true, Listen: true, Lifetime: time.Minute}} {
		c = Config{Lifetime: time.Hour, IPv6: probing, IPv4: ipv4}.withDefaults()
		if c.Rediscover != 20*time.Minute {
			t.Errorf("rediscover, IPv4 %+v: %s", ipv4, c.Rediscover)
		}
	}
	// Given, it stays.
	if c := (Config{Lifetime: time.Hour, Rediscover: time.Second}).withDefaults(); c.Rediscover != time.Second {
		t.Errorf("rediscover given: %s", c.Rediscover)
	}
}

// The latest registration says how long an address stays.
func TestAddressTakesTheLatestLifetime(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:0b")
	state := NewState()
	a, _ := state.Register(mac, netip.MustParseAddr("2001:db8::1"), "router", time.Hour, nil)
	defer a.Unwatch()
	state.Register(mac, netip.MustParseAddr("2001:db8::1"), "eth0", time.Minute, nil)
	if until := time.Until(a.GetExpiration()); until > 2*time.Minute {
		t.Errorf("expires in %s, want a minute", until)
	}
}

// A plugin named as a local interface doesn't make its hosts seen on that interface.
func TestInterfacesOfAMACAreLocalOnly(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Lifetime: time.Hour, IPv4: Family{Enabled: true}})
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:0c")
	other, _ := net.ParseMAC("00:1a:2b:3c:4d:0d")
	interfaces := map[string]ipv4Interface{"eth0": {}, "eth1": {}}

	a, _ := w.State.Register(mac, netip.MustParseAddr("192.0.2.1"), "eth0", time.Hour, nil) // a plugin named eth0
	defer a.Unwatch()
	if got := w.interfacesOf(mac, interfaces); !slices.Equal(got, []string{"eth0", "eth1"}) {
		t.Errorf("seen by a plugin only: %v, want every interface", got)
	}
	b, _ := w.State.registerLocal(mac, netip.MustParseAddr("192.0.2.1"), "eth1", time.Hour, nil)
	if b != a || !slices.Equal(a.Interfaces(), []string{"eth1"}) || !slices.Equal(a.Sources(), []string{"eth0", "eth1"}) {
		t.Errorf("interfaces %v, sources %v", a.Interfaces(), a.Sources())
	}
	if got := w.interfacesOf(mac, interfaces); !slices.Equal(got, []string{"eth1"}) {
		t.Errorf("seen on eth1: %v", got)
	}
	if got := w.interfacesOf(other, interfaces); len(got) != 2 {
		t.Errorf("never seen: %v, want every interface", got)
	}
}

// An address State.Seen adds expires, and leaves the state, as one Register adds.
func TestSeenAddressesExpire(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:0e")
	state := NewState()
	changes, cancel := state.Subscribe()
	defer cancel()
	events := make(chan AddrExpirationRemainingEvents, 4)
	state.Seen(NewAddr(mac, netip.MustParseAddr("2001:db8::e"), "test", 100*time.Millisecond, func(_ *Addr, n AddrExpirationRemainingEvents) { events <- n }), "test")
	<-changes
	select {
	case <-changes:
	case <-time.After(3 * time.Second):
		t.Fatal("no change told at the expiration")
	}
	if len(state.GetAll()) != 0 {
		t.Error("still in the state")
	}
	if len(events) != 4 {
		t.Errorf("%d expiration events, want 4", len(events))
	}
}
