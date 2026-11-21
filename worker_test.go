package ipv6disc

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/arp"
	"go.uber.org/zap"
)

type blockingPlugin struct{ stopped chan struct{} }

func (p *blockingPlugin) Name() string          { return "blocking" }
func (p *blockingPlugin) Stats() map[string]any { return nil }
func (p *blockingPlugin) Start(ctx context.Context, _ *State, _ func(error)) error {
	<-ctx.Done()
	close(p.stopped)
	return nil
}

func TestWorkerStopsWithItsContext(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, Rediscover: time.Minute, IPv6: Family{Enabled: true}})
	plugin := &blockingPlugin{stopped: make(chan struct{})}
	w.RegisterPlugin(plugin)

	ctx, cancel := context.WithCancel(context.Background())
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()

	done := make(chan struct{})
	go func() { w.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after the context was done")
	}
	select {
	case <-plugin.stopped:
	default:
		t.Error("Wait returned before the plugin stopped")
	}
}

func TestWorkerWithNothingToDo(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, Rediscover: time.Minute, IPv6: Family{Enabled: true}})
	if err := w.Start(context.Background()); err == nil {
		t.Error("no plugins and no listening: want an error")
	}
}

func TestDiffWorkers(t *testing.T) {
	addr, other := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	eth0, eth0Other := workerKey{2, "eth0", addr, ""}, workerKey{2, "eth0", other, ""}
	for _, tt := range []struct {
		what                        string
		running, found, start, stop []workerKey
	}{
		{"nothing", nil, nil, nil, nil},
		{"unchanged", []workerKey{eth0, eth0Other}, []workerKey{eth0, eth0Other}, nil, nil},
		{"a new address", []workerKey{eth0}, []workerKey{eth0, eth0Other}, []workerKey{eth0Other}, nil},
		{"an address gone", []workerKey{eth0, eth0Other}, []workerKey{eth0}, nil, []workerKey{eth0Other}},
		{"the interface made again, with a new index", []workerKey{eth0}, []workerKey{{7, "eth0", addr, ""}}, []workerKey{{7, "eth0", addr, ""}}, []workerKey{eth0}},
		{"the address moved to a bridge", []workerKey{eth0}, []workerKey{{5, "br0", addr, ""}}, []workerKey{{5, "br0", addr, ""}}, []workerKey{eth0}},
		{"the interface renamed", []workerKey{eth0}, []workerKey{{2, "lan0", addr, ""}}, []workerKey{{2, "lan0", addr, ""}}, []workerKey{eth0}},
		{"the MAC of the interface changed", []workerKey{eth0}, []workerKey{{2, "eth0", addr, "00:1a:2b:3c:4d:16"}}, []workerKey{{2, "eth0", addr, "00:1a:2b:3c:4d:16"}}, []workerKey{eth0}},
		{"the same address on two interfaces", nil, []workerKey{{3, "eth1", addr, ""}, eth0}, []workerKey{eth0, {3, "eth1", addr, ""}}, nil},
	} {
		set := func(keys []workerKey) map[workerKey]bool {
			m := make(map[workerKey]bool)
			for _, key := range keys {
				m[key] = true
			}
			return m
		}
		start, stop := diffWorkers(set(tt.running), set(tt.found))
		if !slices.Equal(start, tt.start) || !slices.Equal(stop, tt.stop) {
			t.Errorf("%s: start %v, stop %v, want %v and %v", tt.what, start, stop, tt.start, tt.stop)
		}
	}
}

// The workers follow the addresses found: one starts on each new one, the one of an address that
// went, or that is now on another interface, stops, and one that ended by itself, as on a failure
// to listen, starts again at the next check.
func TestSyncWorkers(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: Family{Enabled: true}})
	ctx, cancel := context.WithCancel(context.Background())
	addr := netip.MustParseAddr("2001:db8::1")

	type event struct {
		index   int
		stopped bool
	}
	events := make(chan event, 8)
	fails := make(chan struct{}, 1)
	run := func(ctx context.Context, iface net.Interface, got netip.Addr) {
		if got != addr || iface.Name != "eth0" {
			t.Errorf("started on %s %s", iface.Name, got)
		}
		events <- event{iface.Index, false}
		select {
		case <-ctx.Done():
			events <- event{iface.Index, true}
		case <-fails:
		}
	}
	sync := func(indexes ...int) {
		found := make(map[workerKey]net.Interface)
		for _, index := range indexes {
			found[workerKey{index, "eth0", addr, ""}] = net.Interface{Index: index, Name: "eth0"}
		}
		w.syncWorkers(ctx, found, run)
	}
	expect := func(what string, want ...event) {
		t.Helper()
		var got []event
		for range want {
			select {
			case e := <-events:
				got = append(got, e)
			case <-time.After(5 * time.Second):
				t.Fatalf("%s: %v, want %v", what, got, want)
			}
		}
		// Of two workers, the one stopping and the one starting, either tells first.
		slices.SortFunc(got, func(a, b event) int { return a.index - b.index })
		if !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", what, got, want)
		}
		select {
		case e := <-events:
			t.Errorf("%s: also %v", what, e)
		case <-time.After(20 * time.Millisecond):
		}
	}
	running := func() int {
		w.pcMutex.RLock()
		defer w.pcMutex.RUnlock()
		return len(w.workerCancels)
	}

	sync(2)
	expect("a new address", event{2, false})
	sync(2)
	expect("still there")
	sync(7)
	expect("the interface made again", event{2, true}, event{7, false})
	if running() != 1 {
		t.Errorf("%d workers, want the new one: the one stopped must not take its entry", running())
	}

	// It ends by itself: it is no longer running, and the next check starts it again.
	fails <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	for running() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the worker that ended is still said running")
		}
		time.Sleep(time.Millisecond)
	}
	sync(7)
	expect("after it ended by itself", event{7, false})

	sync()
	expect("the address gone", event{7, true})
	sync(2, 3)
	expect("on two interfaces", event{2, false}, event{3, false})
	cancel()
	expect("the context done", event{2, true}, event{3, true})
	w.Wait()
}

// A worker stopped that is slow to end doesn't take the entry of the one started meanwhile on the
// same address of the same interface, as when the address went and came back: the next check
// would start a second one beside it.
func TestSyncWorkersStoppedWorkerLeavesItsSuccessor(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: Family{Enabled: true}})
	ctx, cancel := context.WithCancel(context.Background())
	key := workerKey{2, "eth0", netip.MustParseAddr("2001:db8::1"), ""}
	found := map[workerKey]net.Interface{key: {Index: 2, Name: "eth0"}}

	started := make(chan chan struct{}, 4)
	run := func(ctx context.Context, _ net.Interface, _ netip.Addr) {
		end := make(chan struct{})
		started <- end
		<-ctx.Done()
		<-end // closing its sockets
	}
	next := func() chan struct{} {
		t.Helper()
		select {
		case end := <-started:
			return end
		case <-time.After(5 * time.Second):
			t.Fatal("no worker started")
			return nil
		}
	}

	w.syncWorkers(ctx, found, run)
	first := next()
	w.syncWorkers(ctx, nil, run)
	w.syncWorkers(ctx, found, run)
	second := next()
	close(first)
	// It is through soon after: nothing tells when, as it leaves the entry alone.
	time.Sleep(50 * time.Millisecond)
	w.syncWorkers(ctx, found, run)
	select {
	case end := <-started:
		t.Error("a second worker started on the address: the one stopped took the entry of its successor")
		close(end)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	close(second)
	w.Wait()
}

// An address its interface no longer has leaves the state when its worker stops, not a lifetime
// later; it stays when the interface was only made again, for the worker that follows, and when
// the whole discovery stops, the machine still having it. With another MAC, the address under the
// old one goes.
func TestSyncWorkersRemovesTheAddressesGone(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: Family{Enabled: true}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:17")
	changed, _ := net.ParseMAC("00:1a:2b:3c:4d:18")
	gone, stays := netip.MustParseAddr("2001:db8::17"), netip.MustParseAddr("2001:db8::18")

	registered := make(chan struct{}, 8)
	run := func(ctx context.Context, iface net.Interface, addr netip.Addr) {
		w.State.RegisterSelf(iface.HardwareAddr, addr, iface.Name, false, time.Hour, nil)
		registered <- struct{}{}
		<-ctx.Done()
	}
	sync := func(starts int, ifaces map[netip.Addr]net.Interface) {
		t.Helper()
		found := make(map[workerKey]net.Interface)
		for addr, iface := range ifaces {
			found[keyOf(&iface, addr)] = iface
		}
		w.syncWorkers(ctx, found, run)
		for range starts {
			select {
			case <-registered:
			case <-time.After(5 * time.Second):
				t.Fatal("a worker did not start")
			}
		}
	}
	own := func(hw net.HardwareAddr) []string {
		return w.State.FilterMACs([]net.HardwareAddr{hw}).Strings()
	}
	eth0 := net.Interface{Index: 2, Name: "eth0", HardwareAddr: mac}

	sync(2, map[netip.Addr]net.Interface{gone: eth0, stays: eth0})
	changes, stop := w.State.Subscribe()
	defer stop()
	sync(0, map[netip.Addr]net.Interface{stays: eth0})
	if got := own(mac); !slices.Equal(got, []string{stays.String()}) {
		t.Errorf("an address gone: %v, want the other only", got)
	}
	select {
	case <-changes:
	default:
		t.Error("an address gone: no change told")
	}

	// Made again: the same address, of the same MAC, is never out of the state.
	again := eth0
	again.Index = 7
	select {
	case <-changes:
	default:
	}
	sync(1, map[netip.Addr]net.Interface{stays: again})
	if got := own(mac); !slices.Equal(got, []string{stays.String()}) {
		t.Errorf("the interface made again: %v", got)
	}
	select {
	case <-changes:
		t.Error("the interface made again: a change told, as if the address had gone")
	default:
	}

	again.HardwareAddr = changed
	sync(1, map[netip.Addr]net.Interface{stays: again})
	if len(own(mac)) != 0 || !slices.Equal(own(changed), []string{stays.String()}) {
		t.Errorf("the MAC changed: %v under the old one, %v under the new", own(mac), own(changed))
	}

	cancel()
	w.Wait()
	if got := own(changed); !slices.Equal(got, []string{stays.String()}) {
		t.Errorf("the discovery stopped: %v, want the address kept", got)
	}
	w.State.Close()
}

// A worker starts once.
func TestWorkerStartsOnce(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: Family{Enabled: true}})
	w.RegisterPlugin(&blockingPlugin{stopped: make(chan struct{})})
	ctx, cancel := context.WithCancel(context.Background())
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(ctx); err == nil {
		t.Error("a second Start: no error")
	}
	cancel()
	w.Wait()
}

// With the local discovery of both families on, Wait returns soon after the context is done, and
// then State.Close leaves no goroutine: neither of the worker nor of the addresses, which
// otherwise keep one each until they expire. No interface matches, so nothing needs privileges.
func TestWorkerLeavesNoGoroutines(t *testing.T) {
	table := arpTable
	defer func() { arpTable = table }()
	arpTable = func() ([]arp.Neighbor, error) { return nil, nil }
	before := runtime.NumGoroutine()

	w := NewWorker(zap.NewNop().Sugar(), Config{
		Lifetime:   time.Hour,
		IPv6:       Family{Enabled: true, Listen: true, Active: true},
		IPv4:       Family{Enabled: true, Listen: true},
		Interfaces: []string{"no-such-interface"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:19")
	for i := range 20 {
		w.State.Register(mac, netip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, 15: byte(i + 1)}), "router", time.Hour, nil)
	}
	cancel()
	done := make(chan struct{})
	go func() { w.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after the context was done")
	}
	// The 20 addresses have theirs until Close. Counted from here, not from before Start: the
	// goroutine of an address another test left can end meanwhile.
	afterWait := runtime.NumGoroutine()

	w.State.Close()
	w.State.Close()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > min(before, afterWait-20) {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines after Close, %d before Start and %d after Wait, with the 20 of the addresses", runtime.NumGoroutine(), before, afterWait)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := len(w.State.FilterMACs([]net.HardwareAddr{mac}).FilterValid().Get()); got != 20 {
		t.Errorf("%d valid addresses after Close, want the 20: it removes none", got)
	}
}

// The ping before an address expires goes from a listener of an interface that saw it, whichever
// is running then: not the one that first registered it, which can be gone.
func TestPingerFor(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: Family{Enabled: true}})
	stable, temporary, ula, other := &fakeConn{}, &fakeConn{}, &fakeConn{}, &fakeConn{}
	protocols := func(c *fakeConn) []*DiscoveryProtocol {
		return []*DiscoveryProtocol{{Name: "ndp", Worker: struct{ worker }{}}, {Name: "ping", Worker: c}}
	}
	listen(w, 2, "eth0", "fd00::5", protocols(ula)...)
	listen(w, 2, "eth0", "2001:db8:1::5", protocols(stable)...)
	listen(w, 2, "eth0", "2001:db8:1::6", protocols(temporary)...)
	listen(w, 3, "eth1", "2001:db8:2::5", protocols(other)...)

	from := func(target string, interfaces ...string) pinger {
		conn, processes := pingerFor(w.protocolConns, interfaces, netip.MustParseAddr(target))
		if (conn == nil) != (processes == nil) || conn != nil && !slices.Contains(interfaces, processes.InterfaceName) {
			t.Errorf("%s on %v: from %v, %+v", target, interfaces, conn, processes)
		}
		return conn
	}
	if got := from("2001:db8:1::99", "eth0"); got != stable {
		t.Error("an address of a /64 listened on: not from the first address of it")
	}
	// Not the first in order, which is of another /64 of the interface.
	if got := from("fd00::99", "eth0"); got != ula {
		t.Error("an address of the second /64 of an interface: not from the address of it")
	}
	if got := from("fe80::99", "eth0"); got != ula && got != stable && got != temporary {
		t.Error("a link-local address: not from its interface")
	}
	if got := from("fe80::99", "eth1"); got != other {
		t.Error("a link-local address seen on eth1: not from eth1")
	}
	if got := from("2001:db8:1::99", "eth0", "eth1"); got != stable {
		t.Error("seen on two interfaces: not from the one with its /64")
	}
	if got := from("2001:db8:1::99", "eth2"); got != nil {
		t.Error("seen on an interface not listened on: pinged")
	}
	if got := from("2001:db8:1::99"); got != nil {
		t.Error("seen by a plugin only: pinged")
	}

	// The worker that first saw the address stopped: another of the interface pings it.
	delete(w.protocolConns, workerKey{2, "eth0", netip.MustParseAddr("2001:db8:1::5"), ""})
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:14")
	a, _ := w.State.registerLocal(mac, netip.MustParseAddr("2001:db8:1::99"), "eth0", time.Hour, w.pingBeforeExpiration)
	defer a.Unwatch()
	w.pingBeforeExpiration(a, 3)
	if temporary.sent != 1 || stable.sent+ula.sent+other.sent != 0 {
		t.Errorf("pings: the other address of the /64 %d, the others %d", temporary.sent, stable.sent+ula.sent+other.sent)
	}
	// The expiration itself pings nothing, nor does an address no interface saw.
	w.pingBeforeExpiration(a, 0)
	b, _ := w.State.Register(mac, netip.MustParseAddr("2001:db8:1::98"), "router", time.Hour, nil)
	defer b.Unwatch()
	w.pingBeforeExpiration(b, 3)
	if temporary.sent != 1 {
		t.Errorf("pings after the expiration, and of a plugin's address: %d", temporary.sent-1)
	}
}

// The IPv6 discovery runs on the interfaces that have a MAC: a host is its MAC.
func TestIsValidInterface(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:15")
	for _, tt := range []struct {
		what  string
		iface net.Interface
		valid bool
	}{
		{"an Ethernet interface", net.Interface{Name: "eth0", Flags: net.FlagUp | net.FlagMulticast | net.FlagBroadcast, HardwareAddr: mac}, true},
		{"one that is down", net.Interface{Name: "eth0", Flags: net.FlagMulticast, HardwareAddr: mac}, false},
		{"one without multicast", net.Interface{Name: "eth0", Flags: net.FlagUp, HardwareAddr: mac}, false},
		{"the loopback", net.Interface{Name: "lo", Flags: net.FlagUp | net.FlagMulticast | net.FlagLoopback, HardwareAddr: mac}, false},
		{"a PPP link, without a MAC", net.Interface{Name: "ppp0", Flags: net.FlagUp | net.FlagMulticast | net.FlagPointToPoint}, false},
	} {
		if err := isValidInterface(&tt.iface); (err == nil) != tt.valid {
			t.Errorf("%s: %v, want valid %v", tt.what, err, tt.valid)
		}
	}
}

// A family without a lifetime of its own leaves each registration the one it gives, as a
// plugin's: NewWorker gives the state the families' lifetimes as they were set, not with the
// defaults, which would put Config.Lifetime in place of every plugin's.
func TestNewWorkerLeavesAPluginItsLifetime(t *testing.T) {
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:5f")
	w := NewWorker(zap.NewNop().Sugar(), Config{
		Lifetime: 4 * time.Hour,
		IPv6:     Family{Enabled: true},
		IPv4:     Family{Enabled: true, Lifetime: 2 * time.Hour},
	})
	a6, _ := w.State.Register(mac, netip.MustParseAddr("2001:db8::5f"), "plugin", 10*time.Minute, nil)
	a4, _ := w.State.Register(mac, netip.MustParseAddr("192.0.2.95"), "plugin", 10*time.Minute, nil)
	defer a6.Unwatch()
	defer a4.Unwatch()
	if until := time.Until(a6.GetExpiration()); until > 11*time.Minute {
		t.Errorf("IPv6, no family lifetime: expires in %s, want the plugin's 10m", until)
	}
	if until := time.Until(a4.GetExpiration()); until < 119*time.Minute || until > 121*time.Minute {
		t.Errorf("IPv4, a family lifetime of 2h: expires in %s", until)
	}
}
