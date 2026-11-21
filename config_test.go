package ipv6disc

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/arp"
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

	// A bad pattern is refused wherever its fault is, also past what could match no name.
	for _, pattern := range []string{"docker[", "*[", "eth*[", `eth\`, "[]", "[a-]"} {
		bad := DefaultConfig().withDefaults()
		bad.ExcludeInterfaces = []string{pattern}
		if err := bad.validate(); err == nil {
			t.Errorf("the bad pattern %q excluded: want an error", pattern)
		}
		bad.Interfaces, bad.ExcludeInterfaces = bad.ExcludeInterfaces, nil
		if err := bad.validate(); err == nil {
			t.Errorf("the bad pattern %q: want an error", pattern)
		}
	}
	// An empty pattern is valid, and matches no interface: alone, the local discovery runs on none.
	empty := DefaultConfig().withDefaults()
	empty.Interfaces = []string{""}
	if err := empty.validate(); err != nil || empty.usesInterface("eth0") {
		t.Errorf("an empty pattern: %v, eth0 used %v", err, empty.usesInterface("eth0"))
	}
	bad := DefaultConfig().withDefaults()
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
	c := Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: probing, IPv4: ipv4}.withDefaults()
	if c.IPv6.Lifetime != time.Hour || c.IPv4.Lifetime != 3*time.Minute {
		t.Errorf("family lifetimes: %s, %s", c.IPv6.Lifetime, c.IPv4.Lifetime)
	}
	// A third of the shortest lifetime of the families on: a quiet host is probed before it expires.
	if c.Rediscover != time.Minute {
		t.Errorf("rediscover: %s", c.Rediscover)
	}
	// Of the families that don't probe, off or listening only, none counts.
	for _, ipv4 := range []Family{{Lifetime: time.Minute}, {Enabled: true, Listen: true, Lifetime: time.Minute}} {
		c = Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: probing, IPv4: ipv4}.withDefaults()
		if c.Rediscover != 20*time.Minute {
			t.Errorf("rediscover, IPv4 %+v: %s", ipv4, c.Rediscover)
		}
	}
	// Given, it stays.
	if c := (Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, Rediscover: time.Second}).withDefaults(); c.Rediscover != time.Second {
		t.Errorf("rediscover given: %s", c.Rediscover)
	}
}

// The default rediscovery interval follows a lifetime changed after DefaultConfig.
func TestDefaultConfigRediscoverFollowsTheLifetime(t *testing.T) {
	if c := DefaultConfig().withDefaults(); c.Rediscover != 80*time.Minute {
		t.Errorf("the default: %s, want 1h20m", c.Rediscover)
	}
	c := DefaultConfig()
	c.Lifetime = time.Hour
	c = c.withDefaults()
	if c.Rediscover != 20*time.Minute || len(c.warnings()) != 0 {
		t.Errorf("a lifetime of an hour: rediscover %s, warnings %q", c.Rediscover, c.warnings())
	}
}

// This machine's own IPv6 addresses are registered again within their lifetime, whatever the
// interval of the probes: nothing else refreshes them.
func TestSelfRefreshIsWithinTheLifetime(t *testing.T) {
	for _, tt := range []struct {
		what string
		c    Config
		want time.Duration
	}{
		{"the default", DefaultConfig(), 80 * time.Minute},
		// Listening only, the rediscovery interval comes from the global lifetime.
		{"a short IPv6 lifetime, listening only", Config{Protocols: DefaultProtocols(), Lifetime: 4 * time.Hour, IPv6: Family{Enabled: true, Listen: true, Lifetime: 10 * time.Minute}}, 10 * time.Minute / 3},
		{"a rediscovery interval longer than the lifetime", Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, Rediscover: 80 * time.Minute, IPv6: Family{Enabled: true, Listen: true, Active: true}}, 20 * time.Minute},
		{"a short rediscovery interval", Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, Rediscover: time.Minute, IPv6: Family{Enabled: true, Listen: true, Active: true}}, time.Minute},
		{"a lifetime of a second", Config{Protocols: DefaultProtocols(), Lifetime: time.Second, IPv6: Family{Enabled: true, Listen: true}}, time.Second},
	} {
		c := tt.c.withDefaults()
		if err := c.validate(); err != nil {
			t.Errorf("%s: %v", tt.what, err)
		}
		if got := c.selfRefresh(); got != tt.want {
			t.Errorf("%s: every %s, want %s", tt.what, got, tt.want)
		}
	}
}

// A configuration that loses hosts that are there is valid, and warned of.
func TestConfigWarnings(t *testing.T) {
	probing := Family{Enabled: true, Listen: true, Active: true}
	for _, tt := range []struct {
		what string
		c    Config
		want int
	}{
		{"the default", DefaultConfig(), 0},
		{"rediscovering less often than the lifetime", Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, Rediscover: 80 * time.Minute, IPv6: probing}, 1},
		{"the same, of both families", Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, Rediscover: time.Hour, IPv6: probing, IPv4: probing}, 2},
		{"the same, listening only: nothing is probed", Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, Rediscover: 80 * time.Minute, IPv6: Family{Enabled: true, Listen: true}}, 0},
		{"an IPv4 lifetime of the interval of the table", Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: probing, IPv4: Family{Enabled: true, Listen: true, Lifetime: time.Minute}}, 1},
		{"the same, IPv4 not listening", Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: probing, IPv4: Family{Enabled: true, Lifetime: time.Minute}}, 0},
		{"an IPv4 lifetime of two minutes", Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: probing, IPv4: Family{Enabled: true, Listen: true, Lifetime: 2 * time.Minute}}, 0},
	} {
		c := tt.c.withDefaults()
		if err := c.validate(); err != nil {
			t.Errorf("%s: %v", tt.what, err)
		}
		if got := c.warnings(); len(got) != tt.want {
			t.Errorf("%s: %d warnings, want %d: %q", tt.what, len(got), tt.want, got)
		}
	}
}

// Where the system has no neighbor table, as on Windows, the interfaces' own IPv4 addresses are
// still registered, and refreshed: they don't expire while the family listens.
func TestIPv4SelfAddressesWithoutANeighborTable(t *testing.T) {
	table := arpTable
	defer func() { arpTable = table }()
	arpTable = func() ([]arp.Neighbor, error) {
		return nil, fmt.Errorf("reading the neighbor table: %w", errors.ErrUnsupported)
	}

	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv4: Family{Enabled: true, Listen: true, Active: true}})
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:13")
	interfaces := map[string]ipv4Interface{"eth0": {
		iface:    net.Interface{Index: 2, Name: "eth0", HardwareAddr: mac},
		prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.5/24")},
	}}

	err := w.readIPv4Table(interfaces, time.Time{})
	if !errors.Is(err, errors.ErrUnsupported) || !w.tableUnsupported(err) {
		t.Errorf("reading the table: %v, want unsupported", err)
	}
	if w.tableUnsupported(errors.New("another")) || w.tableUnsupported(nil) {
		t.Error("another error, or none, taken as unsupported")
	}

	w.registerSelfIPv4(interfaces)
	own := w.State.FilterMACs([]net.HardwareAddr{mac}).Get()
	if len(own) != 1 || own[0].Addr != netip.MustParseAddr("192.0.2.5") || !own[0].Self() {
		t.Fatalf("this machine's addresses: %v", own)
	}
	defer own[0].Unwatch()
	before := own[0].GetExpiration()
	time.Sleep(5 * time.Millisecond)
	w.registerSelfIPv4(interfaces)
	if again := w.State.FilterMACs([]net.HardwareAddr{mac}).Get(); len(again) != 1 || again[0] != own[0] || !again[0].GetExpiration().After(before) {
		t.Errorf("registered again: %v, expiring %s after", again, again[0].GetExpiration().Sub(before))
	}
}

// An IPv4 address an interface no longer has leaves the state when the interfaces are next read,
// not a lifetime later: unless they couldn't all be read, when what is missing isn't known gone.
func TestIPv4SelfAddressesGone(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv4: Family{Enabled: true, Listen: true}})
	defer w.State.Close()
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:1f")
	eth0 := func(prefixes ...string) map[string]ipv4Interface {
		i := ipv4Interface{iface: net.Interface{Index: 2, Name: "eth0", HardwareAddr: mac}}
		for _, p := range prefixes {
			i.prefixes = append(i.prefixes, netip.MustParsePrefix(p))
		}
		return map[string]ipv4Interface{"eth0": i}
	}
	addrs := func() []string { return w.State.FilterMACs([]net.HardwareAddr{mac}).Strings() }

	own := w.syncSelfIPv4(nil, eth0("192.0.2.5/24", "198.51.100.5/24"), true)
	if len(own) != 2 || len(addrs()) != 2 {
		t.Fatalf("registered %v, in the state %v", own, addrs())
	}
	own = w.syncSelfIPv4(own, map[string]ipv4Interface{}, false)
	if len(own) != 2 || len(addrs()) != 2 {
		t.Errorf("the interfaces not all read: registered %v, in the state %v, want both kept", own, addrs())
	}
	own = w.syncSelfIPv4(own, eth0("192.0.2.5/24"), true)
	if got := addrs(); len(own) != 1 || !slices.Equal(got, []string{"192.0.2.5"}) {
		t.Errorf("an address gone: registered %v, in the state %v", own, got)
	}
	own = w.syncSelfIPv4(own, map[string]ipv4Interface{}, true)
	if got := addrs(); len(own) != 0 || len(got) != 0 {
		t.Errorf("the interface gone: registered %v, in the state %v", own, got)
	}
}

// The latest registration says how long an address stays.
// Each record has its lifetime: a later registration of the same one gives it its own, and the
// address stays while the record that lasts longest does, whatever the others.
func TestAddressTakesTheLatestLifetime(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:0b")
	state := NewState()
	ip := netip.MustParseAddr("2001:db8::1")
	a, _ := state.Register(mac, ip, "router", time.Hour, nil)
	defer a.Unwatch()
	// Another, shorter: the router's hour stays.
	state.Register(mac, ip, "eth0", time.Minute, nil)
	if until := time.Until(a.GetExpiration()); until < 59*time.Minute {
		t.Errorf("expires in %s, want the router's hour", until)
	}
	// The router's again, of a minute: the latest says how long it stays, and the address goes
	// with the longest left, a minute.
	state.Register(mac, ip, "router", time.Minute, nil)
	if until := time.Until(a.GetExpiration()); until > 2*time.Minute {
		t.Errorf("expires in %s, want a minute", until)
	}
}

// A plugin named as a local interface doesn't make its hosts seen on that interface.
func TestInterfacesOfAMACAreLocalOnly(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv4: Family{Enabled: true}})
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:0c")
	other, _ := net.ParseMAC("00:1a:2b:3c:4d:0d")
	interfaces := map[string]ipv4Interface{"eth0": {}, "eth1": {}}

	a, _ := w.State.Register(mac, netip.MustParseAddr("192.0.2.1"), "eth0", time.Hour, nil) // a plugin named eth0
	defer a.Unwatch()
	if got := w.interfacesOf(mac, interfaces); !slices.Equal(got, []string{"eth0", "eth1"}) {
		t.Errorf("seen by a plugin only: %v, want every interface", got)
	}
	b, _ := w.State.registerLocal(mac, netip.MustParseAddr("192.0.2.1"), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth1"}, time.Hour, nil)
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
	// Timers due together fire in any order, and the expiration stops the others: the last is told.
	var last AddrExpirationRemainingEvents = -1
	for len(events) > 0 {
		last = <-events
	}
	if last != 0 {
		t.Errorf("the last event %d, want the expiration, 0", last)
	}
}

// Seen of an address already there changes nothing of it, nor races with its watch; one that
// expired, given again, is seen then, valid for its lifetime again, watched again, and expires
// again.
func TestSeenAgain(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:0f")
	state := NewState()
	lifetime := 300 * time.Millisecond
	a, _ := state.Register(mac, netip.MustParseAddr("2001:db8::f"), "test", lifetime, nil)
	for range 20 {
		state.Seen(a, "test")
		time.Sleep(2 * time.Millisecond)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(state.GetAll()) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("never expired")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Expired and unwatched: given again, it is there, valid, not with its expiration time past.
	if a.Valid() {
		t.Fatal("out of the state, and valid")
	}
	state.Seen(a, "test")
	if got := state.FilterMACs([]net.HardwareAddr{mac}).FilterValid().Get(); !a.Valid() || len(got) != 1 || got[0] != a {
		t.Errorf("seen again after it expired: valid %v, the valid addresses of the state %v", a.Valid(), got)
	}
	if until := time.Until(a.GetExpiration()); until > lifetime || until < lifetime/2 {
		t.Errorf("seen again after it expired: expires in %s, want its lifetime, %s", until, lifetime)
	}
	// And it goes again, once.
	for len(state.GetAll()) > 0 {
		if time.Now().After(deadline.Add(3 * time.Second)) {
			t.Fatal("seen again after it expired, it stays")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An address of this machine says so, and whether it is temporary, as its latest registration as
// this machine's does; a neighbor's registration of it changes neither.
func TestSelfAddresses(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:10")
	state := NewState()
	ip := netip.MustParseAddr("2001:db8::10")

	a, _ := state.Register(mac, ip, "router", time.Hour, nil)
	defer a.Unwatch()
	if a.Self() || a.Temporary() {
		t.Errorf("a plugin's: self %v, temporary %v", a.Self(), a.Temporary())
	}
	state.RegisterSelf(mac, ip, "eth0", true, time.Hour, nil)
	if !a.Self() || !a.Temporary() {
		t.Errorf("this machine's, temporary: self %v, temporary %v", a.Self(), a.Temporary())
	}
	state.Register(mac, ip, "router", time.Hour, nil)
	if !a.Self() || !a.Temporary() {
		t.Error("a plugin's registration changed it")
	}
	state.RegisterSelf(mac, ip, "eth0", false, time.Hour, nil)
	if a.Temporary() {
		t.Error("no longer temporary, still said so")
	}
	if got := state.GetAll()[mac.String()].PrettyPrint(""); !strings.Contains(got, "(this host)") {
		t.Errorf("the report: %q", got)
	}
}

// A target's probes: with prefixes, on the interfaces whose subnets they cover, wherever its MAC
// was seen, as a host heard over IPv6 on one interface and with its IPv4 address on another, two
// networks of one wire; without, only where it was seen.
func TestIPv4ProbesFollowThePrefixes(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: Family{Enabled: true}, IPv4: Family{Enabled: true}})
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:0f")
	interfaces := map[string]ipv4Interface{
		"eth0": {prefixes: []netip.Prefix{netip.MustParsePrefix("10.2.3.75/24")}},  // lan-ipv4
		"eth1": {prefixes: []netip.Prefix{netip.MustParsePrefix("172.16.2.2/24")}}, // lan-ipv6, the IPv6 heard here
		"eth2": {prefixes: []netip.Prefix{netip.MustParsePrefix("172.20.53.11/29")}},
	}
	a, _ := w.State.registerLocal(mac, netip.MustParseAddr("fd00::1"), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth1"}, time.Hour, nil)
	if a == nil {
		t.Fatal("the IPv6 address not taken")
	}
	defer a.Unwatch()
	probed := func(target IPv4Target) []string {
		var got []string
		for _, p := range w.ipv4Probes(target, interfaces) {
			got = append(got, fmt.Sprintf("%s %s %d", p.name, p.local.Masked(), len(p.asked)))
		}
		return got
	}

	if got := probed(IPv4Target{MAC: mac, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.2.3.0/24")}}); !slices.Equal(got, []string{"eth0 10.2.3.0/24 253"}) {
		t.Errorf("10.2.3.0/24, the MAC seen on eth1: %q, want eth0's subnet", got)
	}
	if got := probed(IPv4Target{MAC: mac, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.2.3.200/30")}}); !slices.Equal(got, []string{"eth0 10.2.3.0/24 4"}) {
		t.Errorf("a part of a subnet: %q", got)
	}
	if got := probed(IPv4Target{MAC: mac, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}); len(got) != 0 {
		t.Errorf("a prefix of no interface: %q", got)
	}
	if got := probed(IPv4Target{MAC: mac}); !slices.Equal(got, []string{"eth1 172.16.2.0/24 253"}) {
		t.Errorf("without prefixes, the MAC seen on eth1: %q, want eth1 only", got)
	}
	other, _ := net.ParseMAC("00:1a:2b:3c:4d:10")
	if got := probed(IPv4Target{MAC: other}); len(got) != 3 {
		t.Errorf("without prefixes, a MAC never seen: %q, want every interface", got)
	}
}

// A reading of the table after a sweep: what the kernel confirmed since the sweep began is there
// now, whatever the lifetime, as one shorter than the wait for the kernel's checks; what it last
// confirmed before counts from then, and a reading without a sweep counts every entry so.
func TestReadIPv4TableConfirmed(t *testing.T) {
	table := arpTable
	defer func() { arpTable = table }()
	mac := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
	swept := time.Now().Add(-9 * time.Second)
	neighbors := []arp.Neighbor{
		{IP: netip.MustParseAddr("192.0.2.10"), MAC: mac("00:1a:2b:3c:4d:21"), Interface: "eth0", Confirmed: swept.Add(time.Second)},
		{IP: netip.MustParseAddr("192.0.2.11"), MAC: mac("00:1a:2b:3c:4d:22"), Interface: "eth0", Confirmed: swept.Add(-20 * time.Second)},
		{IP: netip.MustParseAddr("192.0.2.12"), MAC: mac("00:1a:2b:3c:4d:23"), Interface: "eth0"},
	}
	arpTable = func() ([]arp.Neighbor, error) { return neighbors, nil }
	interfaces := map[string]ipv4Interface{"eth0": {iface: net.Interface{Index: 2, Name: "eth0"}}}
	expiry := func(w *Worker, n arp.Neighbor) time.Time {
		for _, a := range w.State.FilterMACs([]net.HardwareAddr{n.MAC}).Get() {
			return a.GetExpiration()
		}
		return time.Time{}
	}
	near := func(t *testing.T, what string, got, want time.Time) {
		t.Helper()
		if d := got.Sub(want); d < -100*time.Millisecond || d > 100*time.Millisecond {
			t.Errorf("%s: expires %s from now, want %s", what, time.Until(got).Round(time.Millisecond), time.Until(want).Round(time.Millisecond))
		}
	}

	for _, lifetime := range []time.Duration{6 * time.Second, time.Hour} {
		w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: lifetime, IPv4: Family{Enabled: true, Listen: true, Active: true}})
		if err := w.readIPv4Table(interfaces, swept); err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		near(t, fmt.Sprintf("%s, confirmed since the sweep, lifetime %s", neighbors[0].IP, lifetime), expiry(w, neighbors[0]), now.Add(lifetime))
		near(t, fmt.Sprintf("%s, with no time", neighbors[2].IP), expiry(w, neighbors[2]), now.Add(lifetime))
		old := expiry(w, neighbors[1])
		if lifetime < 29*time.Second {
			if !old.IsZero() {
				t.Errorf("%s, confirmed %s before the sweep with a lifetime of %s: registered", neighbors[1].IP, 20*time.Second, lifetime)
			}
		} else {
			near(t, fmt.Sprintf("%s, confirmed before the sweep", neighbors[1].IP), old, neighbors[1].Confirmed.Add(lifetime))
		}
	}

	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv4: Family{Enabled: true, Listen: true}})
	if err := w.readIPv4Table(interfaces, time.Time{}); err != nil {
		t.Fatal(err)
	}
	near(t, "without a sweep, confirmed after the last", expiry(w, neighbors[0]), neighbors[0].Confirmed.Add(time.Hour))
}
