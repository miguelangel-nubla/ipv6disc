package ipv6disc

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/internal/fetch"
	"github.com/miguelangel-nubla/ipv6disc/internal/questions"
	"github.com/miguelangel-nubla/ipv6disc/pkg/arp"
	"github.com/miguelangel-nubla/ipv6disc/pkg/llmnr"
	"github.com/miguelangel-nubla/ipv6disc/pkg/mdns"
	"github.com/miguelangel-nubla/ipv6disc/pkg/netbios"
	"go.uber.org/zap"
)

// fakeAsker stands for a naming protocol on an interface: it records the addresses asked, and
// asks those it is given a prefix of.
type fakeAsker struct {
	mutex sync.Mutex
	nets  []netip.Prefix
	asked []netip.Addr
}

func (a *fakeAsker) Stats() map[string]any { return nil }

func (a *fakeAsker) Asks(addr netip.Addr) bool {
	return slices.ContainsFunc(a.nets, func(p netip.Prefix) bool { return p.Contains(addr) })
}

func (a *fakeAsker) AskName(addr netip.Addr) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.asked = append(a.asked, addr)
	return nil
}

// take returns the addresses asked since the last time.
func (a *fakeAsker) take() []netip.Addr {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	asked := a.asked
	a.asked = nil
	return asked
}

// testNamer is a naming layer over a state that takes both families and names, with a clock the
// test moves, an asker on eth0, and a discovery that records what it is asked to find.
type testNamer struct {
	*namer
	clock      time.Time
	asker      *fakeAsker
	discovered []string
	// Whether the discovery can ask: not before its listener started.
	listening bool
}

func newTestNamer(t *testing.T) *testNamer {
	state := NewState()
	t.Cleanup(state.Close)
	state.SetFamilies(true, true)
	state.SetNames(true, 0)
	config := Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, Rediscover: 10 * time.Minute, Hostnames: Hostnames{Enabled: true}}.withDefaults()
	n := &testNamer{namer: newNamer(state, zap.NewNop().Sugar(), config), clock: time.Now(), listening: true,
		asker: &fakeAsker{nets: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("2001:db8::/64"), netip.MustParsePrefix("fe80::/10")}}}
	n.now = func() time.Time { return n.clock }
	n.askers = func(iface string) []*NameProtocol {
		if iface != "eth0" {
			return nil
		}
		return []*NameProtocol{{Name: NameMDNS, Worker: n.asker}}
	}
	n.discover = func(iface string, addr netip.Addr) bool {
		if n.listening {
			n.discovered = append(n.discovered, iface+" "+addr.String())
		}
		return n.listening
	}
	return n
}

func hostMAC(i int) net.HardwareAddr {
	return net.HardwareAddr{0x02, 0, 0, 0, byte(i >> 8), byte(i)}
}

func hostIPv4(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{192, 168, 1, byte(i)})
}

// A host without a name is asked its name: once in a rediscovery interval, and not this machine,
// nor a host no local interface saw, nor one at an address no protocol asks.
func TestNamingAsksTheHostsWithoutAName(t *testing.T) {
	n := newTestNamer(t)
	n.state.registerLocal(hostMAC(1), hostIPv4(1), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	n.state.Register(hostMAC(2), hostIPv4(2), "router", time.Hour, nil)                                                                           // a plugin's
	n.state.registerLocal(hostMAC(3), netip.MustParseAddr("10.0.0.3"), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)     // off the asker's link
	n.state.registerLocal(hostMAC(4), hostIPv4(4), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth1"}, time.Hour, nil)                         // an interface with no protocol
	n.state.RegisterSelf(hostMAC(5), hostIPv4(5), "eth0", false, time.Hour, nil)                                                                  // this machine
	n.state.registerLocal(hostMAC(5), netip.MustParseAddr("192.168.1.55"), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil) // another address of it
	n.state.registerLocal(hostMAC(6), hostIPv4(6), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)                         // named already
	n.state.RegisterName(hostMAC(6), "named", "router", time.Hour)
	n.state.RegisterName(hostMAC(2), "elsewhere", "router", time.Hour)

	if backlog := n.lookups(); backlog {
		t.Error("hosts left to ask")
	}
	if got := n.asker.take(); !slices.Equal(got, []netip.Addr{hostIPv4(1)}) {
		t.Errorf("asked %v, want the one host without a name that can be", got)
	}

	// Not again before a rediscovery interval passed, however many times it looks.
	for range 4 {
		n.clock = n.clock.Add(n.rediscover / 5)
		n.lookups()
	}
	if got := n.asker.take(); len(got) != 0 {
		t.Errorf("asked again within the rediscovery interval: %v", got)
	}
	// The look of the next interval, which comes a moment before a whole one passed.
	n.clock = n.clock.Add(n.rediscover/5 - 10*time.Millisecond)
	n.lookups()
	if got := n.asker.take(); !slices.Equal(got, []netip.Addr{hostIPv4(1)}) {
		t.Errorf("after a rediscovery interval, asked %v", got)
	}

	// It answers: it is never asked while its name is said.
	n.answered("eth0", hostIPv4(1), "Printer.local.")
	if got := namesOf(n.state, hostMAC(1)); !slices.Equal(got, []string{"printer (mdns)"}) {
		t.Errorf("the name answered: %v", got)
	}
	for range 30 {
		n.clock = n.clock.Add(n.rediscover)
		// Said again, by itself or by a plugin, well within its lifetime.
		n.sayAgain(hostMAC(1), time.Hour, time.Hour)
		n.sayAgain(hostMAC(6), time.Hour, time.Hour)
		n.lookups()
	}
	if got := n.asker.take(); len(got) != 0 {
		t.Errorf("a host whose name keeps being said was asked: %v", got)
	}
	// The hosts gone are forgotten.
	n.asked["02:00:00:00:00:63"] = &hostAsking{round: n.clock}
	n.lookups()
	if len(n.asked) != 1 {
		t.Errorf("remembers asking %d hosts, want the one there that was", len(n.asked))
	}
}

// sayAgain has the names of a host said lifetime ago, by the test's clock, and left to stay: the
// state's own clock is the machine's.
func (n *testNamer) sayAgain(hw net.HardwareAddr, lifetime, left time.Duration) {
	n.state.namesMutex.Lock()
	defer n.state.namesMutex.Unlock()
	for _, name := range n.state.names[hw.String()] {
		name.Expiration = n.clock.Add(left)
		name.Seen = name.Expiration.Add(-lifetime)
	}
}

// A host whose name is about to expire is asked again before it does, as an address is pinged:
// when it has less than three rediscovery intervals left, and then once in each.
func TestNamingAsksBeforeANameExpires(t *testing.T) {
	n := newTestNamer(t)
	n.state.registerLocal(hostMAC(1), hostIPv4(1), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, 24*time.Hour, nil)
	// The state's clock is the machine's: the namer's follows it.
	n.state.RegisterName(hostMAC(1), "printer", "mdns", 2*time.Hour)
	expiration := n.state.NamesOf(hostMAC(1))[0].Expiration

	// A look in each rediscovery interval, a moment sooner or later, as a ticker's.
	var askedAt []time.Duration
	jitter := 20 * time.Millisecond
	for at := expiration.Add(-65 * time.Minute); at.Before(expiration); at = at.Add(n.rediscover) {
		n.clock, jitter = at.Add(jitter), -jitter
		n.lookups()
		if len(n.asker.take()) > 0 {
			askedAt = append(askedAt, expiration.Sub(n.clock).Round(time.Minute))
		}
	}
	// Within three rediscovery intervals of 10 minutes of the end, once in each.
	if want := []time.Duration{25 * time.Minute, 15 * time.Minute, 5 * time.Minute}; !slices.Equal(askedAt, want) {
		t.Errorf("asked with %v left, want with %v", askedAt, want)
	}

	// A name with a lifetime shorter than that: from half of it.
	short := newTestNamer(t)
	short.state.registerLocal(hostMAC(1), hostIPv4(1), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, 24*time.Hour, nil)
	short.state.RegisterName(hostMAC(1), "printer", "mdns", 12*time.Minute)
	expiration = short.state.NamesOf(hostMAC(1))[0].Expiration
	short.clock = expiration.Add(-7 * time.Minute)
	short.lookups()
	if got := short.asker.take(); len(got) != 0 {
		t.Errorf("asked with more than half its lifetime left: %v", got)
	}
	short.clock = expiration.Add(-5 * time.Minute)
	short.lookups()
	if got := short.asker.take(); len(got) != 1 {
		t.Errorf("with less than half its lifetime left, asked %v", got)
	}
}

// No more hosts than the rate are asked in a second, by all the protocols: the rest wait for the
// next, and each is asked once.
func TestNamingRate(t *testing.T) {
	n := newTestNamer(t)
	const hosts = 3*namingRate + 5
	for i := 1; i <= hosts; i++ {
		n.state.registerLocal(hostMAC(i), hostIPv4(i), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	}
	asked := make(map[netip.Addr]int)
	var perSecond []int
	for second := 0; second < 6; second++ {
		// It looks many times in a second, as after each change of the state.
		backlog := false
		for range 4 {
			backlog = n.lookups()
			n.clock = n.clock.Add(200 * time.Millisecond)
		}
		n.clock = n.clock.Add(200 * time.Millisecond)
		got := n.asker.take()
		for _, addr := range got {
			asked[addr]++
		}
		perSecond = append(perSecond, len(got))
		if want := len(asked) < hosts; backlog != want {
			t.Errorf("second %d: hosts left to ask: %v, with %d of %d asked", second, backlog, len(asked), hosts)
		}
	}
	if want := []int{namingRate, namingRate, namingRate, 5, 0, 0}; !slices.Equal(perSecond, want) {
		t.Errorf("asked in each second: %v, want %v", perSecond, want)
	}
	for addr, times := range asked {
		if times != 1 {
			t.Errorf("%s asked %d times", addr, times)
		}
	}
}

// A host is asked at one of its addresses, an IPv4 one first and a link-local one last; where it
// doesn't answer, at the next the time after; and where it answered, there again.
func TestNamingAsksWhereTheHostAnswers(t *testing.T) {
	n := newTestNamer(t)
	ipv4, global, linkLocal := hostIPv4(1), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fe80::1")
	for _, addr := range []netip.Addr{linkLocal, global, ipv4} {
		n.state.registerLocal(hostMAC(1), addr, Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	}
	next := func() netip.Addr {
		t.Helper()
		n.lookups()
		got := n.asker.take()
		if len(got) != 1 {
			t.Fatalf("asked %v, want one address", got)
		}
		n.clock = n.clock.Add(n.rediscover)
		return got[0]
	}
	var order []netip.Addr
	for range 4 {
		order = append(order, next())
	}
	if want := []netip.Addr{ipv4, global, linkLocal, ipv4}; !slices.Equal(order, want) {
		t.Errorf("asked at %v, want %v", order, want)
	}

	// It answers at its global address: asked there from then on, when its name is about to
	// expire.
	if got := next(); got != global {
		t.Fatalf("asked at %s, want %s", got, global)
	}
	for range 3 {
		n.answered("eth0", global, "printer")
		n.sayAgain(hostMAC(1), time.Hour, time.Minute)
		if got := next(); got != global {
			t.Errorf("after it answered at %s, asked at %s", global, got)
		}
	}
	// An answer for an address it wasn't asked at, as a late one, doesn't keep it there.
	n.answered("eth0", ipv4, "printer")
	n.sayAgain(hostMAC(1), time.Hour, time.Minute)
	if got := next(); got != linkLocal {
		t.Errorf("after no answer at %s, asked at %s, want %s", global, got, linkLocal)
	}
}

// What a response says names its sender only by a record of the sender's own address: the one it
// sent from, or another the state has at the same MAC. The records of other hosts it carries, as
// a proxy's does, name nobody: not the sender, nor the host of their address.
func TestNamingTakesOnlyTheSendersOwnRecords(t *testing.T) {
	n := newTestNamer(t)
	proxy, sleeper := hostMAC(1), hostMAC(2)
	proxy4, proxy6, sleeper4 := hostIPv4(1), netip.MustParseAddr("2001:db8::1"), hostIPv4(2)
	n.state.registerLocal(proxy, proxy4, Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	n.state.registerLocal(proxy, proxy6, Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	n.state.registerLocal(sleeper, sleeper4, Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)

	// The proxy's response: its own records, and the sleeper's.
	n.said("eth0", proxy4, "proxy.local.", proxy4, true)
	n.said("eth0", proxy4, "proxy.local.", proxy6, true)
	n.said("eth0", proxy4, "sleeper.local.", sleeper4, true)
	n.said("eth0", proxy4, "elsewhere.local.", netip.MustParseAddr("203.0.113.9"), false)
	n.said("eth0", proxy4, "_ipp._tcp.local.", proxy4, true)
	n.resolve()

	if got := namesOf(n.state, proxy); !slices.Equal(got, []string{"proxy (mdns)"}) {
		t.Errorf("the names of the sender: %v, want its own only", got)
	}
	if got := namesOf(n.state, sleeper); len(got) != 0 {
		t.Errorf("the host of a record another sent was named: %v", got)
	}
	if got := n.state.GetAll(); len(got) != 2 || len(got[proxy.String()].Get()) != 2 || len(got[sleeper.String()].Get()) != 1 {
		t.Errorf("the records registered addresses: %v", got)
	}
	// Nothing known was asked of the discovery, nor an address off the link; and what is settled
	// doesn't wait.
	if len(n.discovered) != 0 || len(n.wanted) != 0 {
		t.Errorf("asked of the discovery: %v; waiting: %v", n.discovered, n.wanted)
	}
	if len(n.claims) != 1 || n.claims[0].name != "elsewhere.local." {
		t.Errorf("waiting: %+v, want the record whose address is unknown only", n.claims)
	}
}

// A record never registers its address, at any MAC: an address the state doesn't have is asked
// of the discovery, and the name waits. It is its sender's once the discovery has put both
// addresses at one MAC, and nobody's if it put the record's at another.
func TestNamingWaitsForTheDiscovery(t *testing.T) {
	n := newTestNamer(t)
	host, other := hostMAC(1), hostMAC(2)
	from, own, others := netip.MustParseAddr("fe80::1"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")

	if !n.heard("eth0", from) {
		t.Error("a sender the state doesn't have is not new")
	}
	if n.heard("eth0", from) {
		t.Error("heard a second time, it is new again")
	}
	n.said("eth0", from, "printer.local.", own, true)
	n.said("eth0", from, "printer.local.", own, true)
	n.said("eth0", from, "other.local.", others, true)
	n.said("eth0", from, "far.local.", netip.MustParseAddr("2001:db8:ffff::9"), false)
	if got := n.state.GetAll(); len(got) != 0 || len(n.state.AllNames()) != 0 {
		t.Fatalf("registered from what was said: %v, %v", got, n.state.AllNames())
	}
	// Each address of the link asked of the discovery once, however many times it was heard of.
	if want := []string{"eth0 fe80::1", "eth0 2001:db8::1", "eth0 2001:db8::2"}; !slices.Equal(n.discovered, want) {
		t.Errorf("asked of the discovery: %v, want %v", n.discovered, want)
	}
	if len(n.claims) != 3 {
		t.Errorf("%d names wait, want 3", len(n.claims))
	}

	// Asked again after a while only.
	n.discovered = nil
	n.clock = n.clock.Add(namingSolicitEvery - time.Second)
	n.heard("eth0", from)
	n.clock = n.clock.Add(2 * time.Second)
	n.heard("eth0", from)
	if want := []string{"eth0 fe80::1"}; !slices.Equal(n.discovered, want) {
		t.Errorf("asked of the discovery again: %v, want %v", n.discovered, want)
	}

	// The discovery answers: the sender's address only, so far.
	n.state.registerLocal(host, from, Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	n.resolve()
	if got := n.state.AllNames(); len(got) != 0 {
		t.Errorf("named before its other address is known to be its own: %v", got)
	}
	n.state.registerLocal(host, own, Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	n.state.registerLocal(other, others, Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	n.resolve()
	if got := namesOf(n.state, host); !slices.Equal(got, []string{"printer (mdns)"}) {
		t.Errorf("the names of the sender: %v", got)
	}
	if got := namesOf(n.state, other); len(got) != 0 {
		t.Errorf("the host of the other address was named: %v", got)
	}
	if n.heard("eth0", from) {
		t.Error("a sender the state has is new")
	}

	// What still waits is dropped after a while.
	if len(n.claims) != 1 || len(n.wanted) != 0 {
		t.Errorf("waiting: %+v, %v", n.claims, n.wanted)
	}
	n.clock = n.clock.Add(namingPatience + time.Second)
	n.resolve()
	if len(n.claims) != 0 {
		t.Errorf("still waiting after %s: %+v", namingPatience, n.claims)
	}
}

// What was heard before the discovery could be asked, as before the listener of the interface
// started, is asked of it when it can; and no more waits than the bound, whatever is sent.
func TestNamingAsksTheDiscoveryWhenItCan(t *testing.T) {
	n := newTestNamer(t)
	n.listening = false
	from := netip.MustParseAddr("fe80::1")
	n.heard("eth0", from)
	n.resolve()
	if len(n.discovered) != 0 || len(n.wanted) != 1 {
		t.Fatalf("asked %v, waiting %v", n.discovered, n.wanted)
	}
	n.listening = true
	n.resolve()
	n.resolve()
	if want := []string{"eth0 fe80::1"}; !slices.Equal(n.discovered, want) {
		t.Errorf("asked of the discovery: %v, want %v", n.discovered, want)
	}

	for i := range 3 * namingPending {
		addr := netip.AddrFrom16([16]byte{0xfe, 0x80, 14: byte(i >> 8), byte(i)})
		n.heard("eth0", addr)
		n.said("eth0", addr, fmt.Sprintf("host%d.local.", i), netip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, 14: byte(i >> 8), byte(i)}), true)
	}
	if len(n.wanted) > namingPending || len(n.claims) > namingPending {
		t.Errorf("%d addresses and %d names wait, want %d at most", len(n.wanted), len(n.claims), namingPending)
	}
	n.clock = n.clock.Add(namingPatience + time.Second)
	n.resolve()
	if len(n.wanted) != 0 || len(n.claims) != 0 {
		t.Errorf("after %s, %d addresses and %d names still wait", namingPatience, len(n.wanted), len(n.claims))
	}
}

// The answer of the host asked at an address names the MAC the state has that address at, and
// nobody when it has it at none.
func TestNamingAnswered(t *testing.T) {
	n := newTestNamer(t)
	n.state.registerLocal(hostMAC(1), hostIPv4(1), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	n.answered("eth0", hostIPv4(9), "ghost.local.")
	n.answered("eth0", hostIPv4(1), "*")
	if got := n.state.AllNames(); len(got) != 0 {
		t.Errorf("names: %v", got)
	}
	n.answered("eth0", hostIPv4(1), "Printer.local.")
	if got := namesOf(n.state, hostMAC(1)); !slices.Equal(got, []string{"printer (mdns)"}) {
		t.Errorf("names: %v", got)
	}
}

// Without names asked for, a worker starts nothing of the naming layer; with them, and no
// interface, it stops with its context, and leaves no goroutine. The stats show the naming
// protocols of an interface under it.
func TestWorkerNaming(t *testing.T) {
	table := arpTable
	defer func() { arpTable = table }()
	arpTable = func() ([]arp.Neighbor, error) { return nil, nil }
	before := runtime.NumGoroutine()

	config := Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: Family{Enabled: true, Listen: true, Active: true}, IPv4: Family{Enabled: true, Listen: true},
		Interfaces: []string{"no-such-interface"}}
	run := func(config Config) (*Worker, int) {
		w := NewWorker(zap.NewNop().Sugar(), config)
		ctx, cancel := context.WithCancel(context.Background())
		if err := w.Start(ctx); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
		running := runtime.NumGoroutine()
		cancel()
		done := make(chan struct{})
		go func() { w.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Wait did not return after the context was done")
		}
		w.State.Close()
		return w, running
	}
	off, without := run(config)
	if off.State.Names() || off.naming.discover != nil {
		t.Error("the naming layer runs without names asked for")
	}
	// Names kept, and nothing that learns them: the plugins' alone, and no layer.
	config.Hostnames.Enabled = true
	kept, keeping := run(config)
	if !kept.State.Names() || kept.naming.discover != nil || keeping != without {
		t.Errorf("%d goroutines with names kept and no protocol of them, %d without", keeping, without)
	}
	config.Protocols.MDNS = MDNSProtocol{Enabled: true, Ask: true}
	on, with := run(config)
	if !on.State.Names() || with != without+2 {
		t.Errorf("%d goroutines with mDNS, %d without: want the two of the naming layer more", with, without)
	}
	// And mDNS without names kept: it finds hosts, by the same layer, which asks nothing.
	config.Hostnames.Enabled = false
	finding, found := run(config)
	if finding.State.Names() || finding.naming.discover == nil || finding.naming.names || found != with {
		t.Errorf("%d goroutines with mDNS and no names, %d with names", found, with)
	}
	// The subscription of the naming layer is gone with it.
	on.State.subscribersMutex.Lock()
	subscribers := len(on.State.subscribers)
	on.State.subscribersMutex.Unlock()
	if subscribers != 0 {
		t.Errorf("%d subscribers of the state left", subscribers)
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines after both stopped, %d before", runtime.NumGoroutine(), before)
		}
		time.Sleep(5 * time.Millisecond)
	}

	asker := &fakeAsker{}
	on.nameConns[nameKey{index: 2, name: "eth0"}] = &nameProcesses{InterfaceName: "eth0", Protocols: []*NameProtocol{{Name: "mdns", Worker: asker}}}
	listen(on, 2, "eth0", "2001:db8::5")
	if got := on.nameProtocols("eth0"); len(got) != 1 || got[0].Worker != worker(asker) || len(on.nameProtocols("eth1")) != 0 || len(on.nameProtocols("")) != 0 {
		t.Errorf("the protocols of eth0: %v", got)
	}
	stats := on.PrettyPrintStats("")
	if want := "    eth0:\n        2001:db8::5:\n        names:\n            mdns :\n"; !strings.Contains(stats, want) {
		t.Errorf("stats:\n%s\nwant\n%s", stats, want)
	}
}

// The names' lifetime is the discovery's unless it has its own, a negative one is refused, and
// one not longer than the rediscovery interval is warned of, when the local discovery asks.
func TestConfigHostnames(t *testing.T) {
	config := DefaultConfig()
	if config.Hostnames.Enabled || config.namesLocally() || config.naming() {
		t.Error("names on by default")
	}
	// Names kept: no protocol learns them until one is enabled.
	config.Hostnames.Enabled = true
	if got := config.withDefaults(); got.Hostnames.Lifetime != config.Lifetime || got.namesLocally() || got.asksNames() || len(got.warnings()) != 0 {
		t.Errorf("defaults: %+v, warnings %v", got.Hostnames, got.warnings())
	}
	config.Protocols.MDNS.Enabled = true
	if got := config.withDefaults(); !got.namesLocally() || !got.asksNames() || len(got.warnings()) != 0 {
		t.Errorf("with mDNS: names locally %v, asked %v, warnings %v", got.namesLocally(), got.asksNames(), got.warnings())
	}
	config.Hostnames.Lifetime = 30 * time.Minute
	if got := config.withDefaults(); got.Hostnames.Lifetime != 30*time.Minute || got.Rediscover != config.Lifetime/3 {
		t.Errorf("its own lifetime: %+v, rediscover %s", got.Hostnames, got.Rediscover)
	}
	if warnings := config.withDefaults().warnings(); len(warnings) != 1 || !strings.Contains(warnings[0], "names' lifetime, 30m0s") {
		t.Errorf("a names' lifetime shorter than the rediscovery interval: %v", warnings)
	}
	// mDNS that only listens asks nobody: nothing to warn of.
	listening := config
	listening.Protocols.MDNS.Ask = false
	if warnings := listening.withDefaults().warnings(); len(warnings) != 0 || !listening.namesLocally() || listening.asksNames() {
		t.Errorf("mDNS that only listens: %v", warnings)
	}
	// Only the plugins read names: nothing asks, so nothing to warn of.
	plugins := config
	plugins.IPv6.Listen = false
	if warnings := plugins.withDefaults().warnings(); len(warnings) != 0 || plugins.namesLocally() {
		t.Errorf("without local discovery: %v", warnings)
	}
	config.Hostnames.Lifetime = -time.Second
	if err := config.withDefaults().validate(); err == nil || !strings.Contains(err.Error(), "names' lifetime") {
		t.Errorf("a negative lifetime: %v", err)
	}

	// The worker gives the state the names' own lifetime, as given: without, each registration's.
	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: Family{Enabled: true}, Hostnames: Hostnames{Enabled: true}})
	defer w.State.Close()
	w.State.RegisterName(namedMAC, "printer", "router", time.Minute)
	if names := w.State.NamesOf(namedMAC); len(names) != 1 || time.Until(names[0].Expiration) > time.Minute {
		t.Errorf("a plugin's lifetime, without the names' own: %+v", names)
	}
	if w.naming.lifetime != time.Hour {
		t.Errorf("the local discovery's names stay %s, want the discovery's lifetime", w.naming.lifetime)
	}
}

// The bounds the discovery page gives of the names are the code's.
func TestDiscoveryPageNamesBounds(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("docs", "discovery.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		fmt.Sprintf("and %d questions a second are sent at most", namingRate),
		fmt.Sprintf("one after another, %d seconds apart", namingStep/time.Second),
		fmt.Sprintf("on port %d", mdns.Port),
		fmt.Sprintf("to port %d of the host", netbios.Port),
		fmt.Sprintf("on port %d, with a hop limit of 1", llmnr.Port),
		fmt.Sprintf("a question sent in the last %d seconds, from where it was sent", questions.Timeout/time.Second),
		fmt.Sprintf("The request has %d seconds, the document %d KB at most", fetch.Timeout/time.Second, fetch.Limit>>10),
		fmt.Sprintf("and %d are under way at once at most", fetch.AtOnce),
		fmt.Sprintf("and what was said waits for it, %d seconds at most", namingPatience/time.Second),
		"less than three rediscovery intervals left, or half its lifetime",
		"a reading of the neighbor table a second later",
	} {
		if !strings.Contains(string(page), want) {
			t.Errorf("docs/discovery.md doesn't say %q: the code does", want)
		}
	}
	// The order the page gives is the one they ask in.
	order := []string{"1. **mDNS**", "2. **The reverse DNS**", "3. **NetBIOS**", "4. **LLMNR**"}
	for i, protocol := range []string{NameMDNS, NameDNS, NameNetBIOS, NameLLMNR} {
		if nameOrder[i] != protocol || !strings.Contains(string(page), order[i]) {
			t.Errorf("docs/discovery.md doesn't have %q as the protocol %d to ask: the code has %s", order[i], i+1, nameOrder[i])
		}
	}
	// And every protocol that tells names is in its table, with its source.
	for _, protocol := range []string{NameMDNS, NameDNS, NameNetBIOS, NameLLMNR, NameWSD, NameSSDP, NameDHCP, NameLLDP} {
		if !strings.Contains(string(page), "| `"+protocol+"` |") {
			t.Errorf("docs/discovery.md has no row of the source %q", protocol)
		}
	}
	if ipv4WakeSettle != time.Second {
		t.Errorf("the neighbor table is read %s after an address was heard of: the page says a second", ipv4WakeSettle)
	}
}

// Many hosts at once, that come, are named by every way, asked, and go as their addresses and
// their names expire, while the state is read and printed: for the race detector, and for what
// is left when all stopped. Nothing waits on another's lock, the names of the hosts that went are
// gone with them, and no goroutine nor name outlives the state's Close.
func TestNamingManyHosts(t *testing.T) {
	before := runtime.NumGoroutine()
	state := NewState()
	state.SetFamilies(true, true)
	state.SetNames(true, 0)
	config := Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, Rediscover: 20 * time.Millisecond, Hostnames: Hostnames{Enabled: true, Lifetime: 60 * time.Millisecond}}.withDefaults()
	n := newNamer(state, zap.NewNop().Sugar(), config)
	asker := &fakeAsker{nets: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fe80::/10")}}
	n.askers = func(iface string) []*NameProtocol {
		if iface == "" {
			return nil
		}
		return []*NameProtocol{{Name: NameMDNS, Worker: asker}}
	}
	n.discover = func(string, netip.Addr) bool { return true }

	const hosts = 300
	addr4 := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{192, 168, byte(i >> 8), byte(i)}) }
	addr6 := func(i int) netip.Addr {
		return netip.AddrFrom16([16]byte{0xfe, 0x80, 14: byte(i >> 8), 15: byte(i)})
	}
	ctx, cancel := context.WithCancel(context.Background())
	var running sync.WaitGroup
	loop := func(f func(round int)) {
		running.Add(1)
		go func() {
			defer running.Done()
			for round := 0; ctx.Err() == nil; round++ {
				f(round)
			}
		}()
	}
	running.Add(1)
	go func() { defer running.Done(); n.run(ctx) }()
	changes, unsubscribe := state.Subscribe()
	defer unsubscribe()
	told := 0
	loop(func(int) {
		select {
		case <-changes:
			told++
		case <-ctx.Done():
		}
	})
	// The discovery: the hosts come, with addresses that last a moment, some seen again.
	loop(func(round int) {
		i := round % hosts
		state.registerLocal(hostMAC(i), addr4(i), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, 30*time.Millisecond, nil)
		if round%3 == 0 {
			state.registerLocal(hostMAC(i), addr6(i), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, 50*time.Millisecond, nil)
		}
		if i == 0 {
			time.Sleep(time.Millisecond)
		}
	})
	// What mDNS hears, in two sockets' readers: their own records, those of others, answers.
	// Of half the hosts: the others say nothing, and are asked.
	for reader := range 2 {
		loop(func(round int) {
			i := (round*7 + reader) % hosts
			n.heard("eth0", addr4(i))
			if i%2 != 0 {
				return
			}
			n.said("eth0", addr4(i), fmt.Sprintf("host-%d.local.", i), addr4(i), true)
			n.said("eth0", addr6(i), fmt.Sprintf("host-%d.local.", i), addr4(i), true)
			n.said("eth0", addr4(i), fmt.Sprintf("other-%d.local.", i), addr4((i+1)%hosts), true)
			n.answered("eth0", addr4(i), fmt.Sprintf("asked-%d.local.", i))
		})
	}
	// A plugin, and the readers.
	loop(func(round int) {
		i := round % hosts &^ 1
		state.RegisterName(hostMAC(i), fmt.Sprintf("lease-%d", i), "router", 40*time.Millisecond)
	})
	loop(func(round int) {
		state.NamesOf(hostMAC(round % hosts))
		if round%50 == 0 {
			state.AllNames()
			state.PrettyPrint("", true)
			state.GetAll()
		}
	})

	time.Sleep(time.Second)
	cancel()
	done := make(chan struct{})
	go func() { running.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the naming layer and the state wait on each other")
	}
	if told == 0 || len(asker.take()) == 0 {
		t.Errorf("%d changes told, and nobody asked, of %d hosts", told, hosts)
	}

	// With nothing said any more, the hosts go, and their names with them, to the last.
	deadline := time.Now().Add(5 * time.Second)
	for len(state.GetAll()) != 0 || state.namesKept() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d hosts and %d names left, a while after the last was said", len(state.GetAll()), state.namesKept())
		}
		time.Sleep(5 * time.Millisecond)
	}
	state.Close()
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines after all stopped and the state was closed, %d before", runtime.NumGoroutine(), before)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// namesKept is how many names the state holds, expired or not.
func (s *State) namesKept() int {
	s.namesMutex.Lock()
	defer s.namesMutex.Unlock()
	kept := 0
	for _, host := range s.names {
		kept += len(host)
	}
	return kept
}
