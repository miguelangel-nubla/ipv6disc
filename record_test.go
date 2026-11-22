package ipv6disc

import (
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"go.uber.org/zap"
)

func recordsOf(a *Addr) []string {
	var out []string
	for _, r := range a.Records() {
		out = append(out, r.String())
	}
	return out
}

// An address has a record for each way it was seen, each with its own times: seen again, a record
// is refreshed, not added; and the address lasts while the longest of them does.
func TestRecords(t *testing.T) {
	state := NewState()
	state.SetFamilies(true, true)
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:21")
	ip := netip.MustParseAddr("2001:db8::21")

	a, _ := state.registerLocal(mac, ip, Record{Protocol: ProtocolNDP, Way: Answered, On: "eth0"}, time.Minute, nil)
	defer a.Unwatch()
	first := a.Records()[0].FirstSeen
	state.registerLocal(mac, ip, Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Minute, nil)
	state.registerLocal(mac, ip, Record{Protocol: ProtocolMDNS, Way: Announced, On: "eth0"}, time.Minute, nil)
	state.Report(mac, ip, "router", "mikrotik", FromNeighbors, time.Hour, nil)
	time.Sleep(5 * time.Millisecond)
	state.registerLocal(mac, ip, Record{Protocol: ProtocolNDP, Way: Answered, On: "eth0"}, time.Minute, nil)

	want := []string{"ndp:answered on eth0", "ndp:heard on eth0", "mdns:announced on eth0", "reported by router from neighbors"}
	if got := recordsOf(a); !slices.Equal(got, want) {
		t.Errorf("records %q, want %q", got, want)
	}
	r := a.Records()[0]
	if !r.FirstSeen.Equal(first) || !r.LastSeen.After(first) {
		t.Errorf("the record seen again: first %s, last %s; it was first seen %s", r.FirstSeen, r.LastSeen, first)
	}
	if got := a.Records()[3]; got.By != "router" || got.Type != "mikrotik" || got.From != FromNeighbors || !got.Reported() {
		t.Errorf("the report: %+v", got)
	}
	// The router's hour keeps it, whatever the minutes of the others.
	if until := time.Until(a.GetExpiration()); until < 59*time.Minute {
		t.Errorf("expires in %s, want the hour of the report", until)
	}
	if got := a.Sources(); !slices.Equal(got, []string{"eth0", "router"}) {
		t.Errorf("sources %v", got)
	}
	if got := a.Interfaces(); !slices.Equal(got, []string{"eth0"}) {
		t.Errorf("interfaces %v", got)
	}
}

// A record that is over no longer counts, while the address stays by another: and an address goes
// when its last record does.
func TestRecordsExpireOnTheirOwn(t *testing.T) {
	state := NewState()
	state.SetFamilies(true, true)
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:22")
	ip := netip.MustParseAddr("2001:db8::22")
	a, _ := state.registerLocal(mac, ip, Record{Protocol: ProtocolMDNS, Way: Announced, On: "eth0"}, 100*time.Millisecond, nil)
	defer a.Unwatch()
	state.registerLocal(mac, ip, Record{Protocol: ProtocolNDP, Way: Answered, On: "eth0"}, 400*time.Millisecond, nil)

	time.Sleep(200 * time.Millisecond)
	if !a.Valid() {
		t.Fatal("the address went with its first record, though another lasts")
	}
	if got := recordsOf(a); !slices.Equal(got, []string{"ndp:answered on eth0"}) {
		t.Errorf("records after the first is over: %q", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(state.GetAll()) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("the address stayed after its last record was over")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// What a protocol saw of an address whose MAC isn't known waits for it, and is the address's record
// once the discovery finds it; of a MAC said, of that one alone.
func TestCauses(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour,
		IPv6: Family{Enabled: true, Listen: true}, IPv4: Family{Enabled: true, Listen: true}})
	t.Cleanup(w.State.Close)
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:23")
	other, _ := net.ParseMAC("00:1a:2b:3c:4d:24")
	ip := netip.MustParseAddr("2001:db8::23")

	// Before the MAC is known: a ping answered, from it; and DHCP saying it is other's.
	w.saw("eth0", ip, ProtocolPing, Answered, nil)
	w.saw("eth0", ip, ProtocolDHCP, Announced, other)
	// The solicitation's answer: mac has it.
	a, _ := w.registerFound(mac, ip, Record{Protocol: ProtocolNDP, Way: Answered, On: "eth0"}, nil)
	defer a.Unwatch()
	if got := recordsOf(a); !slices.Equal(got, []string{"ndp:answered on eth0", "ping:answered on eth0"}) {
		t.Errorf("records of the address found: %q, want the ping's, and not DHCP's of another MAC", got)
	}
	// Taken: the next registration doesn't add them again, nor on another interface.
	w.registerFound(mac, ip, Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, nil)
	if got := len(a.Records()); got != 3 {
		t.Errorf("%d records, want 3", got)
	}

	// An address the State has: the record at once, of its MAC; not of another's.
	w.saw("eth0", ip, ProtocolLLMNR, Answered, nil)
	w.saw("eth0", ip, ProtocolLLDP, Announced, other)
	got := recordsOf(a)
	if !slices.Contains(got, "llmnr:answered on eth0") || slices.Contains(got, "lldp:announced on eth0") {
		t.Errorf("records of an address known: %q", got)
	}

	// A cause too old is dropped.
	ip2 := netip.MustParseAddr("2001:db8::25")
	w.causes.add("eth0", ip2, ProtocolSSDP, Answered, nil, time.Now().Add(-causeWait-time.Second))
	b, _ := w.registerFound(mac, ip2, Record{Protocol: ProtocolNDP, Way: Answered, On: "eth0"}, nil)
	defer b.Unwatch()
	if got := recordsOf(b); slices.Contains(got, "ssdp:answered on eth0") {
		t.Errorf("a cause past its wait was taken: %q", got)
	}
}

// The causes of one address are bounded, as the addresses that have any are: messages that say it
// is at one MAC after another, as DHCP requests made up, fill no more than causesEach, and those
// that waited too long give way to the ones that come, though its MAC never does.
func TestCausesOfAnAddressAreBounded(t *testing.T) {
	var c causes
	ip := netip.MustParseAddr("192.168.1.50")
	start := time.Now()
	said := func(i int, at time.Time) {
		c.add("eth0", ip, ProtocolDHCP, Announced, net.HardwareAddr{0x02, 0, 0, 0, byte(i >> 8), byte(i)}, at)
	}
	for i := range 10 * causesEach {
		said(i, start)
	}
	if got := len(c.waiting[causeKey{"eth0", ip}]); got != causesEach {
		t.Fatalf("%d causes wait for one address, want %d at most", got, causesEach)
	}
	// One of them said again is seen again, not another.
	said(0, start.Add(time.Second))
	if got := len(c.waiting[causeKey{"eth0", ip}]); got != causesEach {
		t.Errorf("%d causes after one was said again, want %d", got, causesEach)
	}
	// Past their wait they go, as another comes: nothing ever took them.
	later := start.Add(causeWait + 2*time.Second)
	said(1000, later)
	if got := c.waiting[causeKey{"eth0", ip}]; len(got) != 1 || !got[0].at.Equal(later) {
		t.Errorf("after the wait: %d causes, want the one that came", len(got))
	}
}

// An mDNS address record of the sender's own is its announcement: of the address it sent from, or
// of another the State has at its MAC. Of another host's, it is nothing.
func TestAnnouncedBy(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Protocols: DefaultProtocols(), Lifetime: time.Hour, IPv6: Family{Enabled: true, Listen: true}})
	t.Cleanup(w.State.Close)
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:26")
	victim, _ := net.ParseMAC("00:1a:2b:3c:4d:27")
	sender := netip.MustParseAddr("fe80::26")
	stable := netip.MustParseAddr("2001:db8::26")
	other := netip.MustParseAddr("2001:db8::27")
	s, _ := w.State.registerLocal(mac, sender, Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	defer s.Unwatch()
	st, _ := w.State.registerLocal(mac, stable, Record{Protocol: ProtocolNDP, Way: Answered, On: "eth0"}, time.Hour, nil)
	defer st.Unwatch()
	o, _ := w.State.registerLocal(victim, other, Record{Protocol: ProtocolNDP, Way: Answered, On: "eth0"}, time.Hour, nil)
	defer o.Unwatch()

	w.announcedBy("eth0", sender, stable, ProtocolMDNS)
	w.announcedBy("eth0", sender, other, ProtocolMDNS)
	if got := recordsOf(st); !slices.Contains(got, "mdns:announced on eth0") {
		t.Errorf("the sender's own address, announced: %q", got)
	}
	if got := recordsOf(o); slices.Contains(got, "mdns:announced on eth0") {
		t.Errorf("another host's address, announced by the sender: %q", got)
	}
	// Of an address not known yet: it waits, of the sender's MAC alone.
	later := netip.MustParseAddr("2001:db8::28")
	w.announcedBy("eth0", sender, later, ProtocolMDNS)
	l, _ := w.registerFound(victim, later, Record{Protocol: ProtocolNDP, Way: Answered, On: "eth0"}, nil)
	defer l.Unwatch()
	if got := recordsOf(l); slices.Contains(got, "mdns:announced on eth0") {
		t.Errorf("announced by one MAC, found at another: %q", got)
	}
}
