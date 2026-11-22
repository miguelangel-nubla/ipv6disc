package ipv6disc

import (
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestCleanName(t *testing.T) {
	long := strings.Repeat("a", 63)
	for name, want := range map[string]string{
		"printer":            "printer",
		"Printer":            "printer",
		"LASERJET-4000":      "laserjet-4000",
		"printer.local":      "printer",
		"printer.local.":     "printer",
		"Printer.Home.Arpa.": "printer",
		"host.domain":        "host",
		"printer.":           "printer",
		"esp_1a2b3c":         "esp-1a2b3c",
		"ESP_1A2B3C":         "esp-1a2b3c",
		"Living Room TV":     "living-room-tv",
		"my__tv":             "my--tv",
		"-printer-":          "printer",
		"_-printer":          "",
		"printer_":           "printer",
		"xn--bcher-kva":      "xn--bcher-kva",
		"123":                "123",
		"192.local":          "192",
		"a":                  "a",
		long:                 long,
		long + ".local":      long,

		// No name.
		"":               "",
		".":              "",
		".local":         "",
		"..":             "",
		"*":              "",
		"*.local":        "",
		"_services":      "",
		"_ipp._tcp":      "",
		"_printer.local": "",
		"-":              "",
		"---":            "",
		"_":              "",
		" ":              "",
		"printer*":       "",
		"prin*ter":       "",
		"Miguel's-Mac":   "",
		"printer(2)":     "",
		"a/b":            "",
		"a\\b":           "",
		"a\tb":           "",
		"a\x00b":         "",
		"bücher":         "",
		"принтер":        "",
		"printer\u200b":  "",
		long + "a":       "",
		"192.168.1.20":   "",
		"192.168.1.20.":  "",
		"2001:db8::1":    "",
		"::1":            "",
	} {
		got, ok := CleanName(name)
		if got != want || ok != (want != "") {
			t.Errorf("CleanName(%q) = %q, %v, want %q", name, got, ok, want)
		}
	}
}

func FuzzCleanName(f *testing.F) {
	for _, s := range []string{"Printer.local.", "esp_1A2B3C", "*", "_ipp._tcp", "-a-", "bücher", "192.168.1.20", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		clean, ok := CleanName(name)
		if !ok {
			if clean != "" {
				t.Errorf("CleanName(%q) = %q, though no name", name, clean)
			}
			return
		}
		if len(clean) < 1 || len(clean) > 63 || clean[0] == '-' || clean[len(clean)-1] == '-' || strings.Trim(clean, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			t.Errorf("CleanName(%q) = %q, which is no label", name, clean)
		}
		// A name already clean stays as it is.
		if again, ok := CleanName(clean); !ok || again != clean {
			t.Errorf("CleanName(%q) = %q, %v: not the same again", clean, again, ok)
		}
	})
}

var (
	namedMAC, _ = net.ParseMAC("00:1a:2b:3c:4d:a1")
	otherMAC, _ = net.ParseMAC("00:1a:2b:3c:4d:a2")
)

// namesOf is the names of a MAC, each with its sources: "printer (mdns,router)".
func namesOf(state *State, hw net.HardwareAddr) []string {
	var result []string
	for _, n := range state.NamesOf(hw) {
		result = append(result, n.Name+" ("+strings.Join(n.Sources, ",")+")")
	}
	return result
}

// A state takes names only when told to, as a family: without, RegisterName leaves them out.
func TestNamesOffByDefault(t *testing.T) {
	state := NewState()
	defer state.Close()
	if state.Names() {
		t.Error("a new state takes names")
	}
	if name, known := state.RegisterName(namedMAC, "printer", "mdns", time.Hour); name != "" || !known {
		t.Errorf("registered %q, known %v, without names on", name, known)
	}
	if names := state.AllNames(); len(names) != 0 || state.namesTimer != nil {
		t.Errorf("names without asking for them: %v", names)
	}

	state.SetNames(true, 0)
	for what, register := range map[string]func() (string, bool){
		"no MAC":              func() (string, bool) { return state.RegisterName(nil, "printer", "mdns", time.Hour) },
		"no name":             func() (string, bool) { return state.RegisterName(namedMAC, "*", "mdns", time.Hour) },
		"no lifetime":         func() (string, bool) { return state.RegisterName(namedMAC, "printer", "mdns", 0) },
		"a negative lifetime": func() (string, bool) { return state.RegisterName(namedMAC, "printer", "mdns", -time.Second) },
	} {
		if name, known := register(); name != "" || !known {
			t.Errorf("%s: registered %q, known %v", what, name, known)
		}
	}
	if names := state.AllNames(); len(names) != 0 {
		t.Errorf("names of what is none: %v", names)
	}
}

// A name is its host's, with what said it; a host has several when its sources disagree, and each
// is refreshed by whatever says it again, and expires by itself.
func TestNames(t *testing.T) {
	state := NewState()
	defer state.Close()
	state.SetNames(true, 0)
	const lifetime = 300 * time.Millisecond

	started := time.Now()
	if name, known := state.RegisterName(namedMAC, "Printer.local.", "mdns", lifetime); name != "printer" || known {
		t.Errorf("registered %q, known %v", name, known)
	}
	if name, known := state.RegisterName(namedMAC, "PRINTER", "router", time.Hour); name != "printer" || !known {
		t.Errorf("registered again, by another source: %q, known %v", name, known)
	}
	state.RegisterName(namedMAC, "laserjet", "router", lifetime)
	state.RegisterName(otherMAC, "printer", "router", time.Hour)
	if got := namesOf(state, namedMAC); !slices.Equal(got, []string{"laserjet (router)", "printer (mdns,router)"}) {
		t.Errorf("names: %v", got)
	}
	if got := namesOf(state, otherMAC); !slices.Equal(got, []string{"printer (router)"}) {
		t.Errorf("names of the other host: %v", got)
	}
	if all := state.AllNames(); len(all) != 2 || len(all[namedMAC.String()]) != 2 {
		t.Errorf("all the names: %v", all)
	}
	// Each source has its own lifetime, and the name stays the longest of them: the router's hour.
	printer := state.NamesOf(namedMAC)[1]
	if left := time.Until(printer.Expiration); left < 59*time.Minute || printer.Seen.Before(started) || !printer.Valid() {
		t.Errorf("the name refreshed for an hour: %s left, seen %s", left, printer.Seen)
	}
	// What NamesOf gave is a copy.
	printer.Sources[0] = "changed"
	if got := namesOf(state, namedMAC)[1]; got != "printer (mdns,router)" {
		t.Errorf("after writing a copy: %v", got)
	}

	if said := printer.Said; len(said) != 2 || said[0].String() != "reported by mdns" || said[1].String() != "reported by router" ||
		time.Until(said[0].Expiration()) > lifetime || time.Until(said[1].Expiration()) < 59*time.Minute || printer.FirstSeen.Before(started) {
		t.Errorf("the sources of printer: %+v", said)
	}

	// The router says it again, for less: the latest of a source says how long it stays. Said
	// again and again by mDNS, the name stays; the source that isn't expires, alone, and so does
	// the name that isn't.
	state.RegisterName(namedMAC, "printer", "router", lifetime)
	state.RegisterName(namedMAC, "printer", "mdns", lifetime)
	for time.Since(started) < 3*lifetime {
		state.RegisterName(namedMAC, "printer", "mdns", lifetime)
		time.Sleep(lifetime / 10)
	}
	if got := namesOf(state, namedMAC); !slices.Equal(got, []string{"printer (mdns)"}) {
		t.Errorf("after the lifetime of the source and the name not said again: %v", got)
	}
	waitNames(t, state, namedMAC, 0)
	if got := namesOf(state, otherMAC); len(got) != 1 {
		t.Errorf("the other host's name went too: %v", got)
	}
	// Expired, it is new again: with the sources that say it now.
	if name, known := state.RegisterName(namedMAC, "printer", "router", time.Hour); name != "printer" || known {
		t.Errorf("registered after it expired: %q, known %v", name, known)
	}
	if got := namesOf(state, namedMAC); !slices.Equal(got, []string{"printer (router)"}) {
		t.Errorf("after it expired and came back: %v", got)
	}
}

// waitNames waits for a host to have that many names.
func waitNames(t *testing.T, state *State, hw net.HardwareAddr, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(state.NamesOf(hw)) != want || want == 0 && kept(state, hw) {
		if time.Now().After(deadline) {
			t.Fatalf("the names of %s: %v, want %d", hw, namesOf(state, hw), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// kept tells whether the state still keeps a host among those with names.
func kept(state *State, hw net.HardwareAddr) bool {
	state.namesMutex.Lock()
	defer state.namesMutex.Unlock()
	return state.names[hw.String()] != nil
}

// The names' lifetime of the state replaces the one of each registration, as a family's does.
func TestNamesLifetime(t *testing.T) {
	state := NewState()
	defer state.Close()
	state.SetNames(true, time.Hour)
	state.RegisterName(namedMAC, "printer", "router", time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	names := state.NamesOf(namedMAC)
	if len(names) != 1 || time.Until(names[0].Expiration) < 59*time.Minute {
		t.Errorf("with the state's lifetime of an hour: %+v", names)
	}
}

// A name belongs to the host, not to an address: learned with one, it is there with the others,
// and goes when the last address does, not before; one said of a host that has no address yet
// waits for it.
func TestNamesGoWithTheHost(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	state := NewState()
	defer state.Close()
	state.SetLogger(zap.New(core).Sugar())
	state.SetFamilies(true, true)
	state.SetNames(true, 0)
	changes, cancel := state.Subscribe()
	defer cancel()

	state.RegisterName(namedMAC, "printer", "router", time.Hour)
	if _, found := state.GetAll()[namedMAC.String()]; found {
		t.Error("a name made a host of a MAC without addresses")
	}
	state.Register(namedMAC, netip.MustParseAddr("192.168.1.20"), "eth0", 100*time.Millisecond, nil)
	state.Register(namedMAC, netip.MustParseAddr("2001:db8::20"), "eth0", 400*time.Millisecond, nil)
	state.Register(otherMAC, netip.MustParseAddr("2001:db8::21"), "eth0", time.Hour, nil)
	state.RegisterName(otherMAC, "scanner", "mdns", time.Hour)

	deadline := time.Now().Add(5 * time.Second)
	for len(state.GetAll()[namedMAC.String()].Get()) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the IPv4 address didn't expire")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := namesOf(state, namedMAC); len(got) != 1 {
		t.Errorf("with an address left, the names: %v", got)
	}
	for len(changes) > 0 {
		<-changes
	}
	for state.GetAll()[namedMAC.String()] != nil {
		if time.Now().After(deadline) {
			t.Fatal("the IPv6 address didn't expire")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := state.AllNames(); len(got) != 1 || len(got[otherMAC.String()]) != 1 {
		t.Errorf("after the host's last address went, the names: %v", got)
	}
	select {
	case <-changes:
	case <-time.After(time.Second):
		t.Error("no change told")
	}
	removed := logs.FilterMessage("host name removed").All()
	if len(removed) != 1 || removed[0].ContextMap()["name"] != "printer" || removed[0].ContextMap()["mac"] != namedMAC.String() {
		t.Errorf("logged: %v", removed)
	}

	// This machine's own address, which its interface no longer has: its names go with it too.
	state.RegisterSelf(namedMAC, netip.MustParseAddr("2001:db8::5"), "eth0", false, time.Hour, nil)
	state.RegisterName(namedMAC, "self", "router", time.Hour)
	state.removeSelf(namedMAC.String(), netip.MustParseAddr("2001:db8::5"), "eth0")
	if got := namesOf(state, namedMAC); len(got) != 0 {
		t.Errorf("after this machine's address was removed, the names: %v", got)
	}
}

// The change notification tells when the names of a host change: a new one, a new source of one,
// and one that expires; not one said again by what said it.
func TestNamesChanges(t *testing.T) {
	state := NewState()
	defer state.Close()
	state.SetNames(true, 0)
	changes, cancel := state.Subscribe()
	defer cancel()
	expectChange := func(what string, want bool, within time.Duration) {
		t.Helper()
		select {
		case <-changes:
			if !want {
				t.Errorf("%s: a change told", what)
			}
		case <-time.After(within):
			if want {
				t.Errorf("%s: no change told", what)
			}
		}
	}

	state.RegisterName(namedMAC, "printer", "mdns", 300*time.Millisecond)
	expectChange("a new name", true, time.Second)
	state.RegisterName(namedMAC, "printer", "mdns", 300*time.Millisecond)
	expectChange("said again", false, 50*time.Millisecond)
	state.RegisterName(namedMAC, "printer", "router", 300*time.Millisecond)
	expectChange("a new source", true, time.Second)
	state.RegisterName(namedMAC, "*", "router", 300*time.Millisecond)
	expectChange("no name", false, 50*time.Millisecond)
	state.RegisterName(namedMAC, "laserjet", "router", time.Hour)
	expectChange("another name", true, time.Second)
	expectChange("the expiration", true, 2*time.Second)
	if got := namesOf(state, namedMAC); !slices.Equal(got, []string{"laserjet (router)"}) {
		t.Errorf("after the expiration: %v", got)
	}
	expectChange("nothing more", false, 100*time.Millisecond)

	// A source whose time ran out, of a name another still says, is new when it says it again.
	state.RegisterName(namedMAC, "laserjet", "mdns", 100*time.Millisecond)
	expectChange("one more source", true, time.Second)
	time.Sleep(150 * time.Millisecond)
	if got := namesOf(state, namedMAC); !slices.Equal(got, []string{"laserjet (router)"}) {
		t.Errorf("after the source's time: %v", got)
	}
	state.RegisterName(namedMAC, "laserjet", "mdns", time.Hour)
	expectChange("a source that says it again", true, time.Second)
}

// The log has an event for a name that comes, and for one that goes, with the name and the MAC:
// a refresh at debug only.
func TestNamesLogEvents(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	state := NewState()
	defer state.Close()
	state.SetLogger(zap.New(core).Sugar())
	state.SetNames(true, 0)

	state.RegisterName(namedMAC, "Printer.local.", "mdns", 100*time.Millisecond)
	state.RegisterName(namedMAC, "printer", "mdns", 100*time.Millisecond)
	waitNames(t, state, namedMAC, 0)
	deadline := time.Now().Add(5 * time.Second)
	for logs.FilterMessage("host name expired").Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	for _, tt := range []struct {
		msg    string
		level  zapcore.Level
		source any
	}{
		{"host named", zap.InfoLevel, "mdns"},
		{"name refreshed", zap.DebugLevel, "mdns"},
		{"host name expired", zap.InfoLevel, nil},
	} {
		entries := logs.FilterMessage(tt.msg).All()
		if len(entries) != 1 {
			t.Errorf("%q: %d entries, want 1", tt.msg, len(entries))
			continue
		}
		fields := entries[0].ContextMap()
		if entries[0].Level != tt.level || fields["name"] != "printer" || fields["mac"] != namedMAC.String() || fields["source"] != tt.source {
			t.Errorf("%q: level %s, fields %v", tt.msg, entries[0].Level, fields)
		}
	}
}

// The names have one timer among them all, and no goroutine: Close stops it, and none is taken
// out after it, though NamesOf leaves out those whose lifetime passed. One registered again
// starts it again.
func TestNamesClose(t *testing.T) {
	before := runtime.NumGoroutine()
	state := NewState()
	state.SetNames(true, 0)
	const lifetime = 50 * time.Millisecond
	for i := range 100 {
		mac := net.HardwareAddr{0, 0x1a, 0x2b, 0x3c, 0x4d, byte(i)}
		state.RegisterName(mac, "host", "mdns", lifetime)
		state.RegisterName(mac, "other", "mdns", time.Hour)
	}
	if got := runtime.NumGoroutine(); got > before {
		t.Errorf("%d goroutines with 200 names, %d before", got, before)
	}
	state.Close()
	state.Close()
	time.Sleep(3 * lifetime)
	state.namesMutex.Lock()
	kept, stopped := 0, state.namesStopped && state.namesTimerAt.IsZero()
	for _, host := range state.names {
		kept += len(host)
	}
	state.namesMutex.Unlock()
	if kept != 200 || !stopped {
		t.Errorf("after Close and a lifetime: %d names kept, want all 200; the timer stopped: %v", kept, stopped)
	}
	if all := state.AllNames(); len(all) != 100 || len(all[namedMAC.String()]) != 0 {
		t.Errorf("the names still valid after Close: of %d hosts, want 100, one each", len(all))
	}

	// Registered again: the timer runs again, and takes out those that expired meanwhile too.
	state.RegisterName(namedMAC, "late", "mdns", lifetime)
	deadline := time.Now().Add(5 * time.Second)
	for {
		state.namesMutex.Lock()
		kept = 0
		for _, host := range state.names {
			kept += len(host)
		}
		state.namesMutex.Unlock()
		if kept == 100 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d names kept after one was registered again and expired, want the 100 of an hour", kept)
		}
		time.Sleep(5 * time.Millisecond)
	}
	state.Close()
	if got := runtime.NumGoroutine(); got > before {
		t.Errorf("%d goroutines at the end, %d before", got, before)
	}
}

// A name refreshed as its timer fires stays: the timer takes out only what is past its lifetime
// then, and waits again for the rest.
func TestNamesRefreshedAtExpiration(t *testing.T) {
	state := NewState()
	defer state.Close()
	state.SetNames(true, 0)
	const lifetime = 40 * time.Millisecond
	stop := time.Now().Add(10 * lifetime)
	for time.Now().Before(stop) {
		state.RegisterName(namedMAC, "printer", "mdns", lifetime)
		if len(state.NamesOf(namedMAC)) != 1 {
			t.Fatal("a name refreshed within its lifetime is gone")
		}
		time.Sleep(lifetime - 5*time.Millisecond)
	}
	waitNames(t, state, namedMAC, 0)
}

// The MAC of an address is the one the state has it at, among the valid ones: the one the
// interface saw it at when two have it, and nobody's when that doesn't tell them apart.
func TestMacOf(t *testing.T) {
	state := NewState()
	state.SetFamilies(true, true)
	defer state.Close()
	linkLocal := netip.MustParseAddr("fe80::20")
	state.registerLocal(namedMAC, linkLocal, Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	state.registerLocal(otherMAC, linkLocal, Record{Protocol: ProtocolNDP, Way: Heard, On: "eth1"}, time.Hour, nil)
	state.registerLocal(namedMAC, netip.MustParseAddr("192.168.1.20"), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	state.Register(otherMAC, netip.MustParseAddr("2001:db8::21"), "router", time.Hour, nil)
	expired, _ := state.registerLocal(otherMAC, netip.MustParseAddr("2001:db8::22"), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	expired.mutex.Lock()
	expired.expirationTime = time.Now().Add(-time.Second)
	expired.mutex.Unlock()

	for _, tt := range []struct {
		ip, iface string
		want      net.HardwareAddr
	}{
		{"fe80::20", "eth0", namedMAC},
		{"fe80::20%eth0", "eth0", namedMAC},
		{"fe80::20", "eth1", otherMAC},
		{"fe80::20", "eth2", nil}, // at two MACs, on neither interface
		{"192.168.1.20", "eth0", namedMAC},
		{"::ffff:192.168.1.20", "eth0", namedMAC},
		{"192.168.1.20", "eth1", namedMAC}, // the only one there is
		{"2001:db8::21", "eth0", otherMAC}, // a plugin's
		{"2001:db8::22", "eth0", nil},      // expired
		{"2001:db8::99", "eth0", nil},
	} {
		got, ok := state.macOf(netip.MustParseAddr(tt.ip), tt.iface)
		if ok != (tt.want != nil) || got.String() != tt.want.String() {
			t.Errorf("macOf(%s, %s) = %s, %v, want %s", tt.ip, tt.iface, got, ok, tt.want)
		}
	}
}

// The state shows a host's names under its MAC, each with what said it, and its addresses, each
// with its records, lined up.
func TestPrettyPrintNames(t *testing.T) {
	state := NewState()
	defer state.Close()
	state.SetNames(true, 0)
	state.Register(namedMAC, netip.MustParseAddr("2001:db8::20"), "eth0", time.Hour, nil)
	state.Register(otherMAC, netip.MustParseAddr("2001:db8::21"), "eth0", time.Hour, nil)
	state.RegisterName(namedMAC, "printer", "mdns", time.Hour)
	state.RegisterName(namedMAC, "printer", "router", time.Hour)
	state.RegisterName(namedMAC, "laserjet", "router", time.Hour)
	got := state.PrettyPrint("", true)
	for _, want := range []string{
		"Discovery: 2 hosts, 1 named, 2 addresses\n",
		"    00:1a:2b:3c:4d:a1\n        names:\n            laserjet                 1h 0m 0s             0s\n                reported by router   1h 0m 0s             0s\n            printer ",
		"                reported by mdns     1h 0m 0s             0s\n                reported by router   1h 0m 0s             0s\n        addresses:\n            2001:db8::20 ",
		"    00:1a:2b:3c:4d:a2\n        addresses:\n            2001:db8::21 ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("got:\n%s\nwant a line %q", got, want)
		}
	}
}
