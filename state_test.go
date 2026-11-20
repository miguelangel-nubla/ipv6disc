package ipv6disc

import (
	"errors"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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
	listen(w, 2, "eth0", "2001:db8:1::5")
	listen(w, 2, "eth0", "2001:db8:1::6")
	listen(w, 3, "eth1", "fd00:2::7")

	if got := len(w.Prefixes()); got != 2 {
		t.Errorf("Prefixes: got %d, want 2 (one per /64)", got)
	}
	// No NDP connection, no prefix: nothing to send on, and no error.
	if sent, err := w.Solicit(netip.MustParseAddr("2001:db8:9::1")); sent != 0 || err != nil {
		t.Errorf("Solicit on another prefix: %d, %v", sent, err)
	}
}

// listen makes the worker listen on an address of an interface, as StartInterfaceAddr does, with
// the given protocols in place of the connections.
func listen(w *Worker, index int, name, addr string, protocols ...*DiscoveryProtocol) {
	a := netip.MustParseAddr(addr)
	w.protocolConns[workerKey{index, name, a, ""}] = &InterfaceProcesses{InterfaceName: name, Address: a, Protocols: protocols}
}

// fakeConn stands for an NDP or ping connection: it counts what it sends, or fails.
type fakeConn struct {
	sent int
	err  error
}

func (c *fakeConn) Stats() map[string]any { return nil }
func (c *fakeConn) send() error {
	if c.err != nil {
		return c.err
	}
	c.sent++
	return nil
}
func (c *fakeConn) SendNeighborSolicitation(*netip.Addr) error { return c.send() }
func (c *fakeConn) SendPing(*netip.Addr) error                 { return c.send() }

// One solicitation per link, whatever addresses of the interface share the /64, as its stable and
// its temporary one; a listener that fails leaves it to another of the interface.
func TestWorkerSolicitOncePerInterface(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Lifetime: time.Minute, IPv6: Family{Enabled: true}})
	stable, temporary, other, elsewhere := &fakeConn{}, &fakeConn{}, &fakeConn{}, &fakeConn{}
	listen(w, 2, "eth0", "2001:db8:1::5", &DiscoveryProtocol{Name: "ndp", Worker: stable})
	listen(w, 2, "eth0", "2001:db8:1::6", &DiscoveryProtocol{Name: "ndp", Worker: temporary})
	listen(w, 3, "eth1", "2001:db8:1::7", &DiscoveryProtocol{Name: "ndp", Worker: other})
	listen(w, 4, "eth2", "fd00:2::7", &DiscoveryProtocol{Name: "ndp", Worker: elsewhere})

	sent, err := w.Solicit(netip.MustParseAddr("2001:db8:1::99"))
	if sent != 2 || err != nil || stable.sent+temporary.sent != 1 || other.sent != 1 || elsewhere.sent != 0 {
		t.Errorf("sent on %d links, %v: eth0 %d, eth1 %d, eth2 %d", sent, err, stable.sent+temporary.sent, other.sent, elsewhere.sent)
	}

	// The map's order says which is tried first: the error is told only when the failing one was.
	stable.err = errors.New("no route")
	temporary.sent, other.sent = 0, 0
	sent, err = w.Solicit(netip.MustParseAddr("2001:db8:1::99"))
	if sent != 2 || temporary.sent != 1 || other.sent != 1 {
		t.Errorf("a listener failing: sent on %d links, %v: eth0 %d, eth1 %d", sent, err, temporary.sent, other.sent)
	}
	temporary.err = stable.err
	if sent, err = w.Solicit(netip.MustParseAddr("2001:db8:1::99")); sent != 1 || err == nil {
		t.Errorf("every listener of eth0 failing: sent on %d links, %v", sent, err)
	}
}

// What is no address of a host is left out, as a family the state doesn't take: nil and true.
func TestRegisterLeavesOutWhatIsNoHostAddress(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:11")
	state := NewState()
	state.SetFamilies(true, true)
	changes, cancel := state.Subscribe()
	defer cancel()
	for _, tt := range []struct {
		what string
		hw   net.HardwareAddr
		ip   netip.Addr
	}{
		{"an invalid address", mac, netip.Addr{}},
		{"the unspecified address", mac, netip.MustParseAddr("::")},
		{"the unspecified IPv4 address", mac, netip.MustParseAddr("0.0.0.0")},
		{"a multicast address", mac, netip.MustParseAddr("ff02::1")},
		{"an IPv4 multicast address", mac, netip.MustParseAddr("224.0.0.1")},
		{"no MAC", nil, netip.MustParseAddr("2001:db8::1")},
		{"an empty MAC", net.HardwareAddr{}, netip.MustParseAddr("2001:db8::1")},
	} {
		if a, existing := state.Register(tt.hw, tt.ip, "test", time.Hour, nil); a != nil || !existing {
			t.Errorf("%s: %v, existing %v, want nil and true", tt.what, a, existing)
		}
		// As the interface of a PPP link or a tunnel would have its own registered.
		if a, existing := state.RegisterSelf(tt.hw, tt.ip, "ppp0", false, time.Hour, nil); a != nil || !existing {
			t.Errorf("%s, as this machine's: %v, existing %v, want nil and true", tt.what, a, existing)
		}
	}
	if all := state.GetAll(); len(all) != 0 {
		t.Errorf("in the state: %v", all)
	}
	select {
	case <-changes:
		t.Error("a change told")
	default:
	}
}

// The expiration events of an address go to the first callback a registration gives, also when
// the address was registered without before, as by a plugin: the local discovery, which hears it
// later, still pings it before it expires.
func TestExpirationCallbackOfALaterRegistration(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:12")
	ip := netip.MustParseAddr("2001:db8::12")
	lifetime := 300 * time.Millisecond
	// The events until the expiration, 0: timers due together fire in any order.
	expiration := func(events chan AddrExpirationRemainingEvents) (warnings int) {
		t.Helper()
		for {
			select {
			case remaining := <-events:
				if remaining == 0 {
					return warnings
				}
				warnings++
			case <-time.After(5 * time.Second):
				t.Fatal("no expiration event")
			}
		}
	}

	state := NewState()
	events := make(chan AddrExpirationRemainingEvents, 8)
	callback := func(_ *Addr, remaining AddrExpirationRemainingEvents) { events <- remaining }
	state.Register(mac, ip, "router", lifetime, nil)
	a, existing := state.registerLocal(mac, ip, "eth0", lifetime, callback)
	if !existing {
		t.Fatal("the second registration made a new address")
	}
	if warnings := expiration(events); warnings == 0 {
		t.Error("a plugin first, then the local discovery: no event before the expiration")
	}
	assert.Eventually(t, func() bool { return len(state.GetAll()) == 0 }, time.Second, 5*time.Millisecond)
	a.Unwatch()

	// The first given stays: a registration without, or with another, changes nothing.
	state = NewState()
	later := make(chan AddrExpirationRemainingEvents, 8)
	state.registerLocal(mac, ip, "eth0", lifetime, callback)
	state.Register(mac, ip, "router", lifetime, nil)
	state.registerLocal(mac, ip, "eth1", lifetime, func(_ *Addr, remaining AddrExpirationRemainingEvents) { later <- remaining })
	if warnings := expiration(events); warnings == 0 {
		t.Error("the local discovery first, then a plugin: no event before the expiration")
	}
	if len(later) != 0 {
		t.Error("a later callback took the place of the first")
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
	if err := DefaultConfig().withDefaults().validate(); err != nil {
		t.Errorf("the default: %v", err)
	}
	// Active without listening probes nothing: not an error, as with listening turned off alone.
	quiet := DefaultConfig().withDefaults()
	quiet.IPv4 = Family{Enabled: true, Active: true}
	if err := quiet.validate(); err != nil || quiet.probesIPv4() {
		t.Errorf("IPv4 active without listening: %v, probing %v", err, quiet.probesIPv4())
	}
	bad := DefaultConfig().withDefaults()
	bad.Lifetime = 0
	if err := bad.validate(); err == nil {
		t.Error("no lifetime: want an error")
	}
	// Active without listening, on a family off: nothing runs, nothing to refuse.
	off := DefaultConfig().withDefaults()
	off.IPv4 = Family{Active: true}
	if err := off.validate(); err != nil {
		t.Errorf("a family off: %v", err)
	}
}

// The log's events are what the README says, and its jq example reads: "host identified" and
// "host expired", each with the ip, mac and source, and the refreshes at debug only.
func TestLogEvents(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	state := NewState()
	state.SetLogger(zap.New(core).Sugar())
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:5e")
	ip := netip.MustParseAddr("2001:db8::5e")

	state.Register(mac, ip, "router", 100*time.Millisecond, nil)
	state.Register(mac, ip, "router", 100*time.Millisecond, nil)
	deadline := time.Now().Add(5 * time.Second)
	for logs.FilterMessage("host expired").Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the address didn't expire")
		}
		time.Sleep(10 * time.Millisecond)
	}

	for _, tt := range []struct {
		msg   string
		level zapcore.Level
	}{
		{"host identified", zap.InfoLevel},
		{"ttl refreshed", zap.DebugLevel},
		{"host expired", zap.InfoLevel},
	} {
		entries := logs.FilterMessage(tt.msg).All()
		if len(entries) != 1 {
			t.Errorf("%q: %d entries, want 1", tt.msg, len(entries))
			continue
		}
		fields := entries[0].ContextMap()
		if entries[0].Level != tt.level || fields["ip"] != "2001:db8::5e" || fields["mac"] != "00:1a:2b:3c:4d:5e" || fields["source"] != "router" {
			t.Errorf("%q: level %s, fields %v", tt.msg, entries[0].Level, fields)
		}
	}
}

// An address of this machine's that its interface no longer has leaves the state, with a change
// told; one that another interface has too stays, without the first; and a neighbor's, even with
// the MAC and IP asked, or an address on another interface, is left alone.
func TestRemoveSelf(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:1a")
	ip, neighbor := netip.MustParseAddr("2001:db8::1a"), netip.MustParseAddr("2001:db8::1b")
	state := NewState()
	state.SetFamilies(true, true)
	state.RegisterSelf(mac, ip, "eth0", false, time.Hour, nil)
	n, _ := state.registerLocal(mac, neighbor, "eth0", time.Hour, nil)
	defer n.Unwatch()
	changes, cancel := state.Subscribe()
	defer cancel()
	told := func() bool {
		select {
		case <-changes:
			return true
		default:
			return false
		}
	}
	addrs := func() []string { return state.FilterMACs([]net.HardwareAddr{mac}).Strings() }

	if state.removeSelf(mac.String(), neighbor, "eth0") || state.removeSelf(mac.String(), ip, "eth1") || state.removeSelf("00:1a:2b:3c:4d:ff", ip, "eth0") || told() {
		t.Error("removed, or told of, what is not this machine's address on the interface")
	}
	if got := addrs(); len(got) != 2 {
		t.Fatalf("addresses: %v", got)
	}

	// On two interfaces, as a bridge and its port: it stays while one has it.
	a, _ := state.RegisterSelf(mac, ip, "br0", false, time.Hour, nil)
	told()
	if !state.removeSelf(mac.String(), ip, "eth0") || !told() {
		t.Error("an address one of its two interfaces lost: not removed from it, or no change told")
	}
	if !slices.Equal(a.Interfaces(), []string{"br0"}) || !slices.Equal(a.Sources(), []string{"br0"}) || len(addrs()) != 2 {
		t.Errorf("interfaces %v, sources %v, addresses %v", a.Interfaces(), a.Sources(), addrs())
	}
	if !state.removeSelf(mac.String(), ip, "br0") || !told() {
		t.Error("an address its last interface lost: not removed, or no change told")
	}
	if got := addrs(); !slices.Equal(got, []string{neighbor.String()}) || !a.Valid() {
		t.Errorf("addresses %v, want the neighbor's only", got)
	}

	// The last address of a MAC takes the MAC with it, an IPv4 one as an IPv6 one.
	other, _ := net.ParseMAC("00:1a:2b:3c:4d:1c")
	state.RegisterSelf(other, netip.MustParseAddr("192.0.2.28"), "eth0", false, time.Hour, nil)
	state.removeSelf(other.String(), netip.MustParseAddr("192.0.2.28"), "eth0")
	if _, ok := state.GetAll()[other.String()]; ok {
		t.Error("a MAC without addresses left in the state")
	}
}

// Close stops the events of every address, with their goroutines: none expires out of the state
// after it, nor has its callback called, and Valid tells by time. One registered again is watched
// again, and expires.
func TestStateClose(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:1d")
	before := runtime.NumGoroutine()
	state := NewState()
	var events sync.WaitGroup
	lifetime := 50 * time.Millisecond
	ip := func(i int) netip.Addr { return netip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, 15: byte(i + 1)}) }
	called := make(chan struct{}, 64)
	for i := range 10 {
		state.Register(mac, ip(i), "test", lifetime, func(*Addr, AddrExpirationRemainingEvents) {
			events.Add(1)
			defer events.Done()
			called <- struct{}{}
		})
	}
	state.Close()
	// An event under way when it closed is the last.
	events.Wait()
	for len(called) > 0 {
		<-called
	}
	for deadline := time.Now().Add(5 * time.Second); runtime.NumGoroutine() > before; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines after Close, %d before", runtime.NumGoroutine(), before)
		}
	}

	time.Sleep(2 * lifetime)
	all := state.FilterMACs([]net.HardwareAddr{mac})
	if len(all.Get()) != 10 || len(all.FilterValid().Get()) != 0 || len(called) != 0 {
		t.Errorf("after Close and a lifetime: %d addresses, %d valid, %d events; want all 10 kept, none valid, no event", len(all.Get()), len(all.FilterValid().Get()), len(called))
	}

	// Registered again, by Register or by Seen: watched again, each once.
	a, existing := state.Register(mac, ip(0), "test", lifetime, nil)
	state.Register(mac, ip(0), "test", lifetime, nil)
	state.Seen(all.Get()[1], "test")
	if !existing || !a.Valid() {
		t.Errorf("registered after Close: existing %v, valid %v", existing, a.Valid())
	}
	if got := runtime.NumGoroutine(); got > before+2 {
		t.Errorf("%d goroutines for 2 addresses watched again, %d before", got, before)
	}
	assert.Eventually(t, func() bool { return len(state.FilterMACs([]net.HardwareAddr{mac}).Get()) == 8 }, 5*time.Second, 5*time.Millisecond, "the addresses registered after Close did not expire")
	state.Close()
}

// An address refreshed between the firing of its expiration timer and its removal stays: the
// removal takes only an address still not valid, and tells no expiration of the other.
func TestAddressRefreshedAtExpirationStays(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:1e")
	ip := netip.MustParseAddr("2001:db8::1e")
	state := NewState()
	// Not watched: the test is the expiration event, with the refresh before its removal.
	a, _, _ := state.seen(NewAddr(mac, ip, "test", time.Millisecond, nil), "test")
	time.Sleep(5 * time.Millisecond)
	if a.Valid() {
		t.Fatal("still valid after its lifetime")
	}
	changes, cancel := state.Subscribe()
	defer cancel()
	if got, existing := state.Register(mac, ip, "test", time.Hour, nil); got != a || !existing {
		t.Fatal("the refresh made another address")
	}
	if state.remove(a) {
		t.Error("removed an address seen again since it expired")
	}
	if got := state.FilterMACs([]net.HardwareAddr{mac}).FilterValid().Get(); len(got) != 1 || got[0] != a {
		t.Errorf("valid addresses: %v", got)
	}
	select {
	case <-changes:
		t.Error("a change told: nothing expired, and the source is the same")
	default:
	}

	// Another address with the same MAC and IP, as registered after the first left: not it.
	stale := NewAddr(mac, ip, "test", time.Millisecond, nil)
	time.Sleep(5 * time.Millisecond)
	if state.remove(stale) || len(state.GetAll()) != 1 {
		t.Error("the expiration of an address took another out, of the same MAC and IP")
	}
}

// Registrations, expirations, removals and readers at once: for the race detector, and for the
// order of the locks, macsMutex, then a collection's, then an address's. The callbacks of the
// expirations, which read the state, run with none held.
func TestStateConcurrently(t *testing.T) {
	state := NewState()
	state.SetFamilies(true, true)
	changes, cancel := state.Subscribe()
	defer cancel()
	macs := make([]net.HardwareAddr, 4)
	for i := range macs {
		macs[i] = net.HardwareAddr{0, 0x1a, 0x2b, 0x3c, 0x4d, byte(0x20 + i)}
	}
	ip := func(i int) netip.Addr { return netip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, 15: byte(i%8 + 1)}) }
	onExpiration := func(a *Addr, _ AddrExpirationRemainingEvents) {
		state.FilterMACs(macs).FilterValid().Strings()
		a.Interfaces()
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	loop := func(f func(i int)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
					f(i)
				}
			}
		}()
	}
	for worker := range 4 {
		loop(func(i int) {
			mac := macs[(i+worker)%len(macs)]
			switch i % 4 {
			case 0:
				state.Register(mac, ip(i), "router", 2*time.Millisecond, onExpiration)
			case 1:
				state.registerLocal(mac, ip(i), "eth0", 3*time.Millisecond, onExpiration)
			case 2:
				state.RegisterSelf(mac, ip(i), "eth1", false, 2*time.Millisecond, nil)
			case 3:
				state.removeSelf(mac.String(), ip(i), "eth1")
			}
			if i%64 == 0 {
				time.Sleep(time.Millisecond)
			}
		})
	}
	loop(func(int) {
		for _, collection := range state.GetAll() {
			for _, a := range collection.FilterValid().Get() {
				a.Sources()
				a.Self()
			}
		}
		state.PrettyPrint("", false)
	})
	loop(func(int) {
		select {
		case <-changes:
		case <-time.After(time.Millisecond):
		}
	})
	loop(func(i int) {
		joined := NewAddrCollection()
		for _, collection := range state.GetAll() {
			joined.Join(collection)
			joined.Equal(collection)
		}
		if i%16 == 0 {
			state.Close()
		}
		time.Sleep(100 * time.Microsecond)
	})

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	// Left alone, everything expires. A Close can have stopped the events of some: registered
	// again, they are watched.
	for _, mac := range macs {
		for i := range 8 {
			state.Register(mac, ip(i), "router", 2*time.Millisecond, nil)
		}
	}
	assert.Eventually(t, func() bool { return len(state.GetAll()) == 0 }, 5*time.Second, 5*time.Millisecond)
}
