package ipv6disc

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

var thirdMAC, _ = net.ParseMAC("00:1a:2b:3c:4d:a3")

// movesState is a state of both families, with names, that logs to the observer it returns.
func movesState(t *testing.T) (*State, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zap.InfoLevel)
	state := NewState()
	t.Cleanup(state.Close)
	state.SetLogger(zap.New(core).Sugar())
	state.SetFamilies(true, true)
	state.SetNames(true, 0)
	return state, logs
}

// at tells whether the state has ip at mac.
func at(state *State, mac net.HardwareAddr, ip netip.Addr) bool {
	collection, ok := state.GetAll()[mac.String()]
	if !ok {
		return false
	}
	for _, a := range collection.Get() {
		if a.WithZone("") == ip {
			return true
		}
	}
	return false
}

// addrAt is the address ip of mac in the state, or nil.
func addrAt(state *State, mac net.HardwareAddr, ip netip.Addr) *Addr {
	collection, ok := state.GetAll()[mac.String()]
	if !ok {
		return nil
	}
	for _, a := range collection.Get() {
		if a.WithZone("") == ip {
			return a
		}
	}
	return nil
}

// later waits for the clock to move on, so that the next sighting is after the last.
func later() { time.Sleep(2 * time.Millisecond) }

var (
	movedIPv4 = netip.MustParseAddr("192.168.1.30")
	movedIPv6 = netip.MustParseAddr("2001:db8::30")
	keptIPv4  = netip.MustParseAddr("192.168.1.31")
)

// An address that another MAC shows on the same link leaves the MAC that had it at once, of
// either family, by any protocol that tells the MAC: the host it left, of no other address, is
// gone, with its names, and the address is the new MAC's, whose names it takes. The change is
// told, and logged.
func TestAddressMovesOnALink(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ip     netip.Addr
		before Record
		after  Record
	}{
		{"IPv4, by ARP", movedIPv4, Record{Protocol: ProtocolARP, Way: Answered, On: "eth0"}, Record{Protocol: ProtocolARP, Way: Announced, On: "eth0"}},
		{"IPv4, by the kernel's neighbors", movedIPv4, Record{By: ReportedByKernel, From: FromNeighbors, On: "eth0"}, Record{By: ReportedByKernel, From: FromNeighbors, On: "eth0"}},
		{"IPv6, by NDP", movedIPv6, Record{Protocol: ProtocolNDP, Way: Answered, On: "eth0"}, Record{Protocol: ProtocolNDP, Way: Announced, On: "eth0"}},
		{"heard from the new MAC", movedIPv6, Record{Protocol: ProtocolNDP, Way: Answered, On: "eth0"}, Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, logs := movesState(t)
			state.registerLocal(otherMAC, tc.ip, tc.before, time.Hour, nil)
			state.RegisterName(otherMAC, "tv", "mdns", time.Hour)
			changes, cancel := state.Subscribe()
			defer cancel()
			later()

			state.registerLocal(namedMAC, tc.ip, tc.after, time.Hour, nil)
			if at(state, otherMAC, tc.ip) {
				t.Fatal("the address stays at the MAC it left")
			}
			if _, ok := state.GetAll()[otherMAC.String()]; ok {
				t.Error("the host it left, of no other address, is still there")
			}
			if names := state.NamesOf(otherMAC); len(names) != 0 {
				t.Errorf("the host it left keeps its names %v", names)
			}
			if !at(state, namedMAC, tc.ip) {
				t.Error("the address isn't at the MAC that showed it")
			}
			if mac, ok := state.macOf(tc.ip, "eth0"); !ok || mac.String() != namedMAC.String() {
				t.Errorf("macOf = %s, %v: want the new MAC", mac, ok)
			}
			select {
			case <-changes:
			default:
				t.Error("no change told")
			}
			moved := logs.FilterMessage("address moved").AllUntimed()
			if len(moved) != 1 {
				t.Fatalf("%d moves logged, want 1", len(moved))
			}
			fields := moved[0].ContextMap()
			if fields["from"] != otherMAC.String() || fields["to"] != namedMAC.String() || fields["on"] != "eth0" || fields["ip"] != tc.ip.String() {
				t.Errorf("logged %v", fields)
			}
		})
	}
}

// A host whose address moves keeps its other addresses, and its names.
func TestAddressMovesTheHostStays(t *testing.T) {
	state, _ := movesState(t)
	state.registerLocal(otherMAC, movedIPv4, Record{Protocol: ProtocolARP, Way: Answered, On: "eth0"}, time.Hour, nil)
	state.registerLocal(otherMAC, keptIPv4, Record{Protocol: ProtocolARP, Way: Answered, On: "eth0"}, time.Hour, nil)
	state.RegisterName(otherMAC, "tv", "mdns", time.Hour)
	later()
	state.registerLocal(namedMAC, movedIPv4, Record{Protocol: ProtocolARP, Way: Announced, On: "eth0"}, time.Hour, nil)

	if at(state, otherMAC, movedIPv4) || !at(state, otherMAC, keptIPv4) {
		t.Errorf("the host it left: %v", state.GetAll()[otherMAC.String()])
	}
	if names := state.NamesOf(otherMAC); len(names) != 1 || names[0].Name != "tv" {
		t.Errorf("the host it left has the names %v", names)
	}
}

// Nothing moves where an address can be at two MACs, or where nothing says the other MAC has it
// since.
func TestAddressStays(t *testing.T) {
	arp := func(on string) Record { return Record{Protocol: ProtocolARP, Way: Answered, On: on} }
	for _, tc := range []struct {
		name string
		// The other MAC, then namedMAC: each registers the address.
		before, after func(*State)
	}{
		{
			"on another link",
			func(s *State) { s.registerLocal(otherMAC, movedIPv4, arp("eth0"), time.Hour, nil) },
			func(s *State) { s.registerLocal(namedMAC, movedIPv4, arp("eth1"), time.Hour, nil) },
		},
		{
			"this machine's own address",
			func(s *State) { s.RegisterSelf(otherMAC, movedIPv4, "eth0", false, time.Hour, nil) },
			func(s *State) { s.registerLocal(namedMAC, movedIPv4, arp("eth0"), time.Hour, nil) },
		},
		{
			"taken by this machine",
			func(s *State) { s.registerLocal(otherMAC, movedIPv4, arp("eth0"), time.Hour, nil) },
			func(s *State) { s.RegisterSelf(namedMAC, movedIPv4, "eth0", false, time.Hour, nil) },
		},
		{
			"in DHCP leases, which keep an address of a MAC after it went",
			func(s *State) { s.Report(otherMAC, movedIPv4, "router", "mikrotik", FromLeases, time.Hour, nil) },
			func(s *State) { s.Report(namedMAC, movedIPv4, "router", "mikrotik", FromLeases, time.Hour, nil) },
		},
		{
			"in the neighbor tables of two reporters",
			func(s *State) { s.Report(otherMAC, movedIPv4, "router", "mikrotik", FromNeighbors, time.Hour, nil) },
			func(s *State) { s.Report(namedMAC, movedIPv4, "switch", "mikrotik", FromNeighbors, time.Hour, nil) },
		},
		{
			"reported, of an address seen on a link",
			func(s *State) { s.registerLocal(otherMAC, movedIPv4, arp("eth0"), time.Hour, nil) },
			func(s *State) { s.Report(namedMAC, movedIPv4, "router", "mikrotik", FromNeighbors, time.Hour, nil) },
		},
		{
			"registered by a source of no table",
			func(s *State) { s.registerLocal(otherMAC, movedIPv4, arp("eth0"), time.Hour, nil) },
			func(s *State) { s.Register(namedMAC, movedIPv4, "eth0", time.Hour, nil) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, logs := movesState(t)
			tc.before(state)
			later()
			tc.after(state)
			if !at(state, otherMAC, movedIPv4) || !at(state, namedMAC, movedIPv4) {
				t.Errorf("at the other MAC: %v, at the new one: %v; want both", at(state, otherMAC, movedIPv4), at(state, namedMAC, movedIPv4))
			}
			if n := logs.FilterMessage("address moved").Len(); n != 0 {
				t.Errorf("%d moves logged", n)
			}
		})
	}
}

// A router's neighbor table has one MAC for each address, as a link does: an address it reports at
// another MAC leaves the one it reported before.
func TestAddressMovesInANeighborTable(t *testing.T) {
	state, logs := movesState(t)
	state.Report(otherMAC, movedIPv4, "router", "mikrotik", FromNeighbors, time.Hour, nil)
	later()
	state.Report(namedMAC, movedIPv4, "router", "mikrotik", FromNeighbors, time.Hour, nil)
	if at(state, otherMAC, movedIPv4) || !at(state, namedMAC, movedIPv4) {
		t.Errorf("at the other MAC: %v, at the new one: %v", at(state, otherMAC, movedIPv4), at(state, namedMAC, movedIPv4))
	}
	moved := logs.FilterMessage("address moved").AllUntimed()
	if len(moved) != 1 || moved[0].ContextMap()["on"] != "router neighbors" {
		t.Errorf("logged %v", moved)
	}
}

// An address that moves on one link stays at the MAC it left while another of its records keeps
// it, and only as long as that one does; a lease attached to it doesn't keep it.
func TestAddressMovesKeptByAnotherRecord(t *testing.T) {
	t.Run("by a report", func(t *testing.T) {
		state, _ := movesState(t)
		state.registerLocal(otherMAC, movedIPv4, Record{Protocol: ProtocolARP, Way: Answered, On: "eth0"}, time.Hour, nil)
		state.Report(otherMAC, movedIPv4, "router", "mikrotik", FromLeases, 30*time.Second, nil)
		later()
		state.registerLocal(namedMAC, movedIPv4, Record{Protocol: ProtocolARP, Way: Announced, On: "eth0"}, time.Hour, nil)

		addr := addrAt(state, otherMAC, movedIPv4)
		if addr == nil {
			t.Fatal("the address left the MAC whose lease keeps it")
		}
		if left := time.Until(addr.GetExpiration()); left > 30*time.Second || left < 25*time.Second {
			t.Errorf("it stays %s, want the lease's 30s", left)
		}
		for _, r := range addr.Records() {
			if r.On == "eth0" {
				t.Errorf("it keeps the record %s of the link it left", r)
			}
		}
		if mac, ok := state.macOf(movedIPv4, "eth0"); !ok || mac.String() != namedMAC.String() {
			t.Errorf("macOf on the link = %s, %v: want the new MAC", mac, ok)
		}
	})
	t.Run("not by a lease attached", func(t *testing.T) {
		state, _ := movesState(t)
		state.registerLocal(otherMAC, movedIPv4, Record{Protocol: ProtocolARP, Way: Answered, On: "eth0"}, time.Hour, nil)
		if !state.Attach(otherMAC, movedIPv4, "router", "mikrotik", FromLeases, time.Hour) {
			t.Fatal("not attached")
		}
		later()
		state.registerLocal(namedMAC, movedIPv4, Record{Protocol: ProtocolARP, Way: Announced, On: "eth0"}, time.Hour, nil)
		if at(state, otherMAC, movedIPv4) {
			t.Error("the address stays at the MAC it left, by the lease attached to it")
		}
	})
}

// An address at three MACs moves off both others; one that two MACs showed as late as each other
// is nobody's on the link until one shows it again.
func TestAddressMovesOffEveryOther(t *testing.T) {
	state, logs := movesState(t)
	// Two hosts on two links, which a bridge between them later joins.
	state.registerLocal(otherMAC, movedIPv4, Record{Protocol: ProtocolARP, Way: Answered, On: "eth0"}, time.Hour, nil)
	state.registerLocal(thirdMAC, movedIPv4, Record{Protocol: ProtocolARP, Way: Answered, On: "eth0"}, time.Hour, nil)
	if _, ok := state.macOf(movedIPv4, "eth0"); ok {
		// The second came later, and took it.
		if at(state, otherMAC, movedIPv4) {
			t.Fatal("seen later at the third MAC, it stays at the other too")
		}
	}
	later()
	state.registerLocal(namedMAC, movedIPv4, Record{Protocol: ProtocolARP, Way: Announced, On: "eth0"}, time.Hour, nil)
	if at(state, otherMAC, movedIPv4) || at(state, thirdMAC, movedIPv4) || !at(state, namedMAC, movedIPv4) {
		t.Errorf("at the others: %v, %v; at the new one: %v", at(state, otherMAC, movedIPv4), at(state, thirdMAC, movedIPv4), at(state, namedMAC, movedIPv4))
	}
	if n := logs.FilterMessage("address moved").Len(); n != 2 {
		t.Errorf("%d moves logged, want 2", n)
	}

	// Seen at two MACs at the same moment: neither is the later, and it stays at both.
	tied := netip.MustParseAddr("192.168.1.40")
	seen := time.Now().Add(-time.Second)
	record := Record{By: ReportedByKernel, From: FromNeighbors, On: "eth0"}
	state.registerLocalSeen(otherMAC, tied, record, time.Hour, seen)
	state.registerLocalSeen(namedMAC, tied, record, time.Hour, seen)
	if !at(state, otherMAC, tied) || !at(state, namedMAC, tied) {
		t.Errorf("seen at the same moment: at one %v, at the other %v; want both", at(state, otherMAC, tied), at(state, namedMAC, tied))
	}
	if _, ok := state.macOf(tied, "eth0"); ok {
		t.Error("seen at two MACs at the same moment, it is one's")
	}
}

// Two devices with one address: it moves each time, and the log warns once that it goes back and
// forth, not at every move.
func TestAddressMovesBackAndForth(t *testing.T) {
	state, logs := movesState(t)
	record := Record{Protocol: ProtocolARP, Way: Heard, On: "eth0"}
	for i, mac := range []net.HardwareAddr{otherMAC, namedMAC, otherMAC, namedMAC, otherMAC, namedMAC} {
		state.registerLocal(mac, movedIPv4, record, time.Hour, nil)
		if !at(state, mac, movedIPv4) {
			t.Fatalf("sighting %d: the address isn't at %s", i, mac)
		}
		later()
	}
	if at(state, otherMAC, movedIPv4) {
		t.Error("the address stays at both")
	}
	warnings := logs.FilterLevelExact(zapcore.WarnLevel).AllUntimed()
	if len(warnings) != 1 {
		t.Fatalf("%d warnings, want 1: %v", len(warnings), warnings)
	}
	if moved := logs.FilterMessage("address moved").Len(); moved != 4 {
		t.Errorf("%d moves logged as moves, want 4 beside the warning", moved)
	}
	// Another address that moves once is no warning.
	state.registerLocal(otherMAC, keptIPv4, record, time.Hour, nil)
	later()
	state.registerLocal(thirdMAC, keptIPv4, record, time.Hour, nil)
	if n := logs.FilterLevelExact(zapcore.WarnLevel).Len(); n != 1 {
		t.Errorf("%d warnings after a single move of another address, want still 1", n)
	}
}

// The moves remembered are forgotten once they are older than the warning's window.
func TestNoteMoveForgets(t *testing.T) {
	state := NewState()
	defer state.Close()
	key := func(ip string) moveKey { return moveKey{moveScope{on: "eth0"}, netip.MustParseAddr(ip)} }
	start := time.Now()
	if state.noteMove(key("192.168.1.1"), "a", "b", start) {
		t.Error("a first move warns")
	}
	if !state.noteMove(key("192.168.1.1"), "b", "a", start.Add(time.Minute)) {
		t.Error("a move back within the window doesn't warn")
	}
	if state.noteMove(key("192.168.1.1"), "a", "b", start.Add(2*time.Minute)) {
		t.Error("it warns twice within the window")
	}
	state.noteMove(key("192.168.1.2"), "c", "d", start.Add(moveFlapping+3*time.Minute))
	state.movesMutex.Lock()
	n := len(state.moves)
	state.movesMutex.Unlock()
	if n != 1 {
		t.Errorf("%d moves remembered, want the last alone", n)
	}
}

// A sighting older than the last one at another MAC, as a neighbor table read after the address
// moved, whose entry still has the MAC it left, is of an address that isn't that MAC's any more:
// it isn't registered, nor does it move the address back.
func TestAddressMovesNotBackByAnOlderSighting(t *testing.T) {
	state, logs := movesState(t)
	neighbors := Record{By: ReportedByKernel, From: FromNeighbors, On: "eth0"}
	confirmed := time.Now().Add(-time.Second)
	state.registerLocalSeen(otherMAC, movedIPv4, neighbors, time.Hour, confirmed)
	state.registerLocal(namedMAC, movedIPv4, Record{Protocol: ProtocolARP, Way: Announced, On: "eth0"}, time.Hour, nil)
	if at(state, otherMAC, movedIPv4) {
		t.Fatal("the address didn't move")
	}

	// The kernel's table, read again, still has the old entry.
	if addr, _ := state.registerLocalSeen(otherMAC, movedIPv4, neighbors, time.Hour, confirmed); addr != nil {
		t.Error("an older sighting registered")
	}
	if at(state, otherMAC, movedIPv4) || !at(state, namedMAC, movedIPv4) {
		t.Errorf("at the MAC it left: %v, at the new one: %v", at(state, otherMAC, movedIPv4), at(state, namedMAC, movedIPv4))
	}
	if mac, ok := state.macOf(movedIPv4, "eth0"); !ok || mac.String() != namedMAC.String() {
		t.Errorf("macOf = %s, %v: want the new MAC", mac, ok)
	}

	// An older sighting of an address no other MAC has since is registered as before.
	state.registerLocalSeen(otherMAC, keptIPv4, neighbors, time.Hour, confirmed)
	if !at(state, otherMAC, keptIPv4) {
		t.Error("an older sighting of an address of no other MAC isn't registered")
	}
	// And a newer one at the old MAC takes the address back, as a move.
	later()
	state.registerLocal(otherMAC, movedIPv4, Record{Protocol: ProtocolARP, Way: Answered, On: "eth0"}, time.Hour, nil)
	if !at(state, otherMAC, movedIPv4) || at(state, namedMAC, movedIPv4) {
		t.Errorf("seen later at the old MAC: there %v, at the other %v", at(state, otherMAC, movedIPv4), at(state, namedMAC, movedIPv4))
	}
	if n := logs.FilterMessage("address moved").Len() + logs.FilterLevelExact(zapcore.WarnLevel).Len(); n != 2 {
		t.Errorf("%d moves logged, want 2", n)
	}
}
