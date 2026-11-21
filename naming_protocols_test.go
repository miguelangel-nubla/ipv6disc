package ipv6disc

import (
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

// protocolsNamer is a naming layer with every protocol that asks: mDNS, NetBIOS, which is of
// IPv4 alone, and LLMNR, on eth0; and the reverse DNS, which is of no interface, and asks of
// every address but the link-local ones.
type protocolsNamer struct {
	*testNamer
	askers map[string]*fakeAsker
}

func newProtocolsNamer(t *testing.T) *protocolsNamer {
	link := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("2001:db8::/64"), netip.MustParsePrefix("fe80::/10")}
	n := &protocolsNamer{testNamer: newTestNamer(t), askers: map[string]*fakeAsker{
		NameLLMNR:   {nets: link},
		NameNetBIOS: {nets: link[:1]},
		NameDNS:     {nets: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("2000::/3")}},
	}}
	n.askers[NameMDNS] = n.asker
	n.namer.askers = func(iface string) []*NameProtocol {
		switch iface {
		case "eth0":
			// In another order than they ask in.
			return []*NameProtocol{{Name: NameLLMNR, Worker: n.askers[NameLLMNR]}, {Name: NameNetBIOS, Worker: n.askers[NameNetBIOS]}, {Name: NameMDNS, Worker: n.askers[NameMDNS]}}
		case "":
			return []*NameProtocol{{Name: NameDNS, Worker: n.askers[NameDNS]}}
		}
		return nil
	}
	return n
}

// asked returns what each protocol asked since the last time, in the order of nameOrder: "mdns
// 192.168.1.1".
func (n *protocolsNamer) asked() []string {
	var asked []string
	for _, protocol := range nameOrder {
		for _, addr := range n.askers[protocol].take() {
			asked = append(asked, protocol+" "+addr.String())
		}
	}
	return asked
}

// round looks every second for as long as a round takes, and returns what was asked at each
// look that asked.
func (n *protocolsNamer) round() [][]string {
	var asked [][]string
	for range 12 {
		n.lookups()
		if got := n.asked(); len(got) > 0 {
			asked = append(asked, got)
		}
		n.clock = n.clock.Add(time.Second)
	}
	return asked
}

// A host without a name is asked by each protocol that can ask it, once, one after another, a
// step apart, in the order of nameOrder: once in a rediscovery interval. Each asks at one of the
// addresses it reaches, and at the next of them the time after.
func TestNamingRounds(t *testing.T) {
	n := newProtocolsNamer(t)
	ipv4, global, linkLocal := hostIPv4(1), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fe80::1")
	for _, addr := range []netip.Addr{linkLocal, global, ipv4} {
		n.state.registerLocal(hostMAC(1), addr, "eth0", 24*time.Hour, nil)
	}

	// The first asks at once, and hosts are left to ask until the last did.
	var at []time.Duration
	var asked []string
	start := n.clock
	for range 24 {
		backlog := n.lookups()
		got := n.asked()
		if len(got) > 1 {
			t.Fatalf("asked %v at one look: want one protocol at a time", got)
		}
		if len(got) == 1 {
			at, asked = append(at, n.clock.Sub(start)), append(asked, got[0])
		}
		if want := len(asked) < 4; backlog != want {
			t.Errorf("after %v: hosts left to ask %v, want %v", asked, backlog, want)
		}
		n.clock = n.clock.Add(500 * time.Millisecond)
	}
	if want := []string{"mdns 192.168.1.1", "dns 192.168.1.1", "netbios 192.168.1.1", "llmnr 192.168.1.1"}; !slices.Equal(asked, want) {
		t.Errorf("asked %v, want %v", asked, want)
	}
	if want := []time.Duration{0, namingStep, 2 * namingStep, 3 * namingStep}; !slices.Equal(at, want) {
		t.Errorf("asked at %v, want at %v", at, want)
	}

	// Not again within the rediscovery interval; then by each at its next address: NetBIOS has
	// one, and the reverse DNS none for a link-local one.
	for n.clock.Sub(start) < n.rediscover-n.rediscover/5 {
		n.lookups()
		n.clock = n.clock.Add(n.rediscover / 20)
	}
	if got := n.asked(); len(got) != 0 {
		t.Errorf("asked again within the rediscovery interval: %v", got)
	}
	for i, want := range [][][]string{
		{{"mdns 2001:db8::1"}, {"dns 2001:db8::1"}, {"netbios 192.168.1.1"}, {"llmnr 2001:db8::1"}},
		{{"mdns fe80::1"}, {"dns 192.168.1.1"}, {"netbios 192.168.1.1"}, {"llmnr fe80::1"}},
	} {
		n.clock = start.Add(time.Duration(i+1) * n.rediscover)
		if got := n.round(); !slices.EqualFunc(got, want, slices.Equal) {
			t.Errorf("the round %d: %v, want %v", i+2, got, want)
		}
	}
}

// A round ends as soon as the host has a name: the protocols after the one that answered don't
// ask. And that one asks first the next time, where it answered, when the name is about to
// expire: a host that keeps answering it is sent one question.
func TestNamingRoundEndsWithAName(t *testing.T) {
	n := newProtocolsNamer(t)
	ipv4, global := hostIPv4(1), netip.MustParseAddr("2001:db8::1")
	for _, addr := range []netip.Addr{global, ipv4} {
		n.state.registerLocal(hostMAC(1), addr, "eth0", 24*time.Hour, nil)
	}
	// It answers NetBIOS alone.
	var asked []string
	for range 12 {
		n.lookups()
		got := n.asked()
		asked = append(asked, got...)
		if slices.Contains(got, "netbios 192.168.1.1") {
			n.answeredBy(NameNetBIOS, "eth0", ipv4, "WINBOX-P")
		}
		n.clock = n.clock.Add(time.Second)
	}
	if want := []string{"mdns 192.168.1.1", "dns 192.168.1.1", "netbios 192.168.1.1"}; !slices.Equal(asked, want) {
		t.Errorf("asked %v, want %v: the round ends with the name", asked, want)
	}
	if got := namesOf(n.state, hostMAC(1)); !slices.Equal(got, []string{"winbox-p (netbios)"}) {
		t.Errorf("names: %v", got)
	}

	// Its name about to expire: NetBIOS first, where it answered, and nothing else when it does.
	for range 3 {
		n.clock = n.clock.Add(n.rediscover)
		n.sayAgain(hostMAC(1), time.Hour, time.Minute)
		n.lookups()
		if got := n.asked(); !slices.Equal(got, []string{"netbios 192.168.1.1"}) {
			t.Fatalf("with its name about to expire, asked %v", got)
		}
		n.answeredBy(NameNetBIOS, "eth0", ipv4, "WINBOX-P")
		n.sayAgain(hostMAC(1), time.Hour, time.Hour)
		if got := n.round(); len(got) != 0 {
			t.Errorf("asked %v after it answered", got)
		}
	}
	// It stops answering: the others ask again, after it, in their order.
	n.clock = n.clock.Add(n.rediscover)
	n.sayAgain(hostMAC(1), time.Hour, time.Minute)
	if got, want := n.round(), [][]string{{"netbios 192.168.1.1"}, {"mdns 2001:db8::1"}, {"dns 2001:db8::1"}, {"llmnr 192.168.1.1"}}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("when it stops answering: %v, want %v", got, want)
	}
}

// The questions of every protocol count for the rate: no more of them in a second, of all.
func TestNamingRateOfAllProtocols(t *testing.T) {
	n := newProtocolsNamer(t)
	const hosts = 12
	for i := 1; i <= hosts; i++ {
		n.state.registerLocal(hostMAC(i), hostIPv4(i), "eth0", time.Hour, nil)
	}
	total := 0
	for second := range 30 {
		for range 5 {
			n.lookups()
			n.clock = n.clock.Add(200 * time.Millisecond)
		}
		got := len(n.asked())
		if got > namingRate {
			t.Errorf("second %d: %d questions, want %d at most", second, got, namingRate)
		}
		total += got
	}
	// Each host by each of the four, once.
	if total != 4*hosts {
		t.Errorf("%d questions in all, want %d", total, 4*hosts)
	}
}

// A protocol of no interface, as the reverse DNS, asks of the hosts the plugins found too, which
// no local interface saw; those of an interface don't.
func TestNamingAsksOfTheHostsOfPlugins(t *testing.T) {
	n := newProtocolsNamer(t)
	n.state.Register(hostMAC(2), hostIPv4(2), "router", time.Hour, nil)
	n.state.Register(hostMAC(2), netip.MustParseAddr("fe80::2"), "router", time.Hour, nil)
	if got, want := n.round(), [][]string{{"dns 192.168.1.2"}}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("asked %v, want %v", got, want)
	}
	n.answeredBy(NameDNS, "", hostIPv4(2), "printer.lan.")
	if got := namesOf(n.state, hostMAC(2)); !slices.Equal(got, []string{"printer (dns)"}) {
		t.Errorf("names: %v", got)
	}
	// An address at two MACs is nobody's: an answer for it names none of them.
	n.state.Register(hostMAC(3), hostIPv4(9), "router", time.Hour, nil)
	n.state.Register(hostMAC(4), hostIPv4(9), "other-router", time.Hour, nil)
	n.answeredBy(NameDNS, "", hostIPv4(9), "twice.lan.")
	if len(n.state.NamesOf(hostMAC(3)))+len(n.state.NamesOf(hostMAC(4))) != 0 {
		t.Error("an address at two MACs named one")
	}
}

// What tells a name with a MAC, as a DHCP client's message, names the host there once the
// discovery found one: until then it waits, and the address it tells is asked of the discovery,
// never registered on its word.
func TestNamingClaimed(t *testing.T) {
	n := newProtocolsNamer(t)
	client, addr := hostMAC(1), hostIPv4(20)
	if !n.claimed(NameDHCP, "eth0", client, "Printer", []netip.Addr{addr}) {
		t.Error("a name a host can have was not taken")
	}
	if len(n.state.GetAll()) != 0 || len(n.state.AllNames()) != 0 {
		t.Fatalf("registered on the word of a packet: %v, %v", n.state.GetAll(), n.state.AllNames())
	}
	if want := []string{"eth0 192.168.1.20"}; !slices.Equal(n.discovered, want) {
		t.Errorf("the discovery was asked for %v, want %v", n.discovered, want)
	}
	// The address is asked for again while the name waits, as the client is given it a moment
	// after it asked: every namingSolicitEvery, and not more.
	for range 12 {
		n.clock = n.clock.Add(time.Second)
		if !n.resolve() {
			t.Fatal("no name waits")
		}
	}
	if len(n.discovered) != 3 {
		t.Errorf("the discovery was asked %d times in 12 seconds, want every %s", len(n.discovered), namingSolicitEvery)
	}
	// Said again, it waits once.
	n.claimed(NameDHCP, "eth0", client, "Printer", []netip.Addr{addr})
	if len(n.claims) != 1 {
		t.Errorf("%d names wait, want one", len(n.claims))
	}

	// The address is another host's: the name is not that one's, and still waits for its own.
	n.state.registerLocal(hostMAC(2), addr, "eth0", time.Hour, nil)
	n.resolve()
	if len(n.state.AllNames()) != 0 {
		t.Errorf("the host of the address it told was named: %v", n.state.AllNames())
	}
	// The discovery finds a host at the MAC, by any address: it is named.
	n.state.registerLocal(client, netip.MustParseAddr("2001:db8::20"), "eth0", time.Hour, nil)
	if n.resolve() || len(n.claims) != 0 {
		t.Error("a name still waits")
	}
	if got := namesOf(n.state, client); !slices.Equal(got, []string{"printer (dhcp)"}) {
		t.Errorf("names: %v", got)
	}
	// A host already there is named at once, by a name alone too.
	n.claimed(NameLLDP, "eth0", client, "switch-1.lan", nil)
	if got := namesOf(n.state, client); !slices.Equal(got, []string{"printer (dhcp)", "switch-1 (lldp)"}) || len(n.claims) != 0 {
		t.Errorf("names: %v", got)
	}

	// What is no name is none, but its address is still looked for.
	n.discovered = nil
	if n.claimed(NameDHCP, "eth0", hostMAC(3), "*", []netip.Addr{hostIPv4(30)}) || len(n.claims) != 0 {
		t.Error("what is no name was kept")
	}
	if want := []string{"eth0 192.168.1.30"}; !slices.Equal(n.discovered, want) {
		t.Errorf("the discovery was asked for %v, want %v", n.discovered, want)
	}

	// A name whose host never comes is dropped, and names nobody later.
	n.claimed(NameDHCP, "eth0", hostMAC(4), "ghost", nil)
	n.clock = n.clock.Add(namingPatience + time.Second)
	if n.resolve() {
		t.Error("a name waits after its patience")
	}
	n.state.registerLocal(hostMAC(4), hostIPv4(40), "eth0", time.Hour, nil)
	n.resolve()
	if len(n.state.NamesOf(hostMAC(4))) != 0 {
		t.Error("named by what was said too long before")
	}
	// No more wait than namingPending: a link full of MACs that are no host's fills nothing.
	for i := range 2 * namingPending {
		n.claimed(NameDHCP, "eth0", hostMAC(1000+i), fmt.Sprintf("spoofed-%d", i), []netip.Addr{netip.AddrFrom4([4]byte{192, 168, 2, byte(i)})})
	}
	if len(n.claims) != namingPending || len(n.wanted) > namingPending || len(n.state.AllNames()) != 1 {
		t.Errorf("%d names wait, %d addresses are looked for, %d hosts have names", len(n.claims), len(n.wanted), len(n.state.AllNames()))
	}
}

// What tells the MAC its frame came from, as a DHCPv6 client's message, names the host of the
// address it was sent from only when that is the MAC the state has the address at: an address is
// whatever its sender wrote, and one who writes another's names nobody, now or later.
func TestNamingNamedFrom(t *testing.T) {
	n := newProtocolsNamer(t)
	host, other := hostMAC(1), hostMAC(2)
	linkLocal := netip.MustParseAddr("fe80::1")
	n.state.registerLocal(host, linkLocal, "eth0", time.Hour, nil)
	n.state.registerLocal(other, netip.MustParseAddr("fe80::2"), "eth0", time.Hour, nil)

	n.namedFrom(NameDHCP, "eth0", linkLocal, other, "evil")
	n.namedFrom(NameDHCP, "eth0", linkLocal, nil, "evil")
	if len(n.state.AllNames()) != 0 || len(n.claims) != 0 {
		t.Fatalf("named from another MAC than the address's: %v; %d wait", n.state.AllNames(), len(n.claims))
	}
	n.namedFrom(NameDHCP, "eth0", linkLocal, host, "Laptop.lan")
	if got := namesOf(n.state, host); !slices.Equal(got, []string{"laptop (dhcp)"}) || len(n.state.AllNames()) != 1 {
		t.Errorf("names: %v, of %d hosts", got, len(n.state.AllNames()))
	}

	// An address the state doesn't have is asked of the discovery, and the name waits: for the
	// MAC that answers for it, which names it only if the frame came from there.
	for i, frame := range []net.HardwareAddr{other, hostMAC(3)} {
		addr := netip.AddrFrom16([16]byte{0xfe, 0x80, 15: byte(0x30 + i)})
		n.discovered = nil
		n.namedFrom(NameDHCP, "eth0", addr, frame, "waits")
		if want := []string{"eth0 " + addr.String()}; !slices.Equal(n.discovered, want) || len(n.claims) != 1 {
			t.Fatalf("the discovery was asked for %v, want %v; %d wait", n.discovered, want, len(n.claims))
		}
		n.state.registerLocal(hostMAC(3), addr, "eth0", time.Hour, nil)
		n.resolve()
		if len(n.claims) != 0 {
			t.Errorf("%d still wait", len(n.claims))
		}
	}
	if got := namesOf(n.state, hostMAC(3)); !slices.Equal(got, []string{"waits (dhcp)"}) || len(n.state.NamesOf(other)) != 0 {
		t.Errorf("names: %v; of the other, %v", got, n.state.NamesOf(other))
	}
}

// An LLDP neighbor is named at the MAC its frame came from, and at its chassis's when that is
// of the same maker, as a switch's whose ports have each their MAC: not at whatever MAC the
// frame says its chassis has, which would let any host of the link name any other.
func TestNamingNeighbor(t *testing.T) {
	n := newProtocolsNamer(t)
	port, chassis := net.HardwareAddr{0x00, 0x1b, 0x21, 0, 0, 0x11}, net.HardwareAddr{0x00, 0x1b, 0x21, 0, 0, 0x10}
	victim := hostMAC(7)
	for i, mac := range []net.HardwareAddr{port, chassis, victim} {
		n.state.registerLocal(mac, hostIPv4(10+i), "eth0", time.Hour, nil)
	}
	management := []netip.Addr{hostIPv4(99)}
	if !n.neighbor("eth0", port, chassis, "switch-1", management) {
		t.Error("a name a host can have was not taken")
	}
	for _, mac := range []net.HardwareAddr{port, chassis} {
		if got := namesOf(n.state, mac); !slices.Equal(got, []string{"switch-1 (lldp)"}) {
			t.Errorf("names of %s: %v", mac, got)
		}
	}
	// The address it is managed at is only looked for.
	if want := []string{"eth0 192.168.1.99"}; !slices.Equal(n.discovered, want) {
		t.Errorf("the discovery was asked for %v, want %v", n.discovered, want)
	}
	// A host says its chassis is another's MAC: only itself is named.
	n.neighbor("eth0", port, victim, "evil", nil)
	if got := n.state.NamesOf(victim); len(got) != 0 || len(n.claims) != 0 {
		t.Errorf("named by a frame of another host: %v; %d wait", got, len(n.claims))
	}
	if got := namesOf(n.state, port); !slices.Equal(got, []string{"evil (lldp)", "switch-1 (lldp)"}) {
		t.Errorf("names of the sender: %v", got)
	}
	// Without a chassis MAC, or with its own, the sender alone.
	n.neighbor("eth0", victim, nil, "host-7", nil)
	n.neighbor("eth0", victim, victim, "host-7", nil)
	if got := namesOf(n.state, victim); !slices.Equal(got, []string{"host-7 (lldp)"}) {
		t.Errorf("names: %v", got)
	}
}

// The answer to a question for the name of an address, that came from another address, as
// LLMNR's over IPv6 from the link-local one, is the host's asked only when the state has both at
// one MAC: from another host's it names nobody.
func TestNamingAnswerFromAnotherAddress(t *testing.T) {
	n := newProtocolsNamer(t)
	host, other := hostMAC(1), hostMAC(2)
	global, linkLocal := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fe80::1")
	n.state.registerLocal(host, global, "eth0", time.Hour, nil)
	n.state.registerLocal(other, netip.MustParseAddr("fe80::2"), "eth0", time.Hour, nil)
	n.round()

	// Another host answers for it: nobody is named, neither of them.
	n.saidBy(NameLLMNR, "eth0", netip.MustParseAddr("fe80::2"), "evil.", global, true, true)
	if len(n.state.AllNames()) != 0 {
		t.Fatalf("named by another host's answer: %v", n.state.AllNames())
	}
	// Its own link-local address, which the state doesn't have yet: the discovery is asked,
	// and the answer waits for it.
	n.discovered = nil
	n.saidBy(NameLLMNR, "eth0", linkLocal, "Winbox.", global, true, true)
	if want := []string{"eth0 fe80::1"}; !slices.Equal(n.discovered, want) || len(n.state.AllNames()) != 0 {
		t.Fatalf("the discovery was asked for %v, want %v; names %v", n.discovered, want, n.state.AllNames())
	}
	n.state.registerLocal(host, linkLocal, "eth0", time.Hour, nil)
	n.resolve()
	if got := namesOf(n.state, host); !slices.Equal(got, []string{"winbox (llmnr)"}) {
		t.Errorf("names: %v", got)
	}
	// It answered LLMNR, at the address asked: that asks first the next time, there.
	n.clock = n.clock.Add(n.rediscover)
	n.sayAgain(host, time.Hour, time.Minute)
	n.lookups()
	// The other host, which has no name, is asked too, as before.
	got := slices.DeleteFunc(n.asked(), func(asked string) bool { return strings.HasSuffix(asked, " fe80::2") })
	if !slices.Equal(got, []string{"llmnr 2001:db8::1"}) {
		t.Errorf("with its name about to expire, asked %v", got)
	}
	// Once both are known, the answer names at once.
	n.saidBy(NameLLMNR, "eth0", linkLocal, "renamed.", global, true, true)
	if got := namesOf(n.state, host); !slices.Equal(got, []string{"renamed (llmnr)", "winbox (llmnr)"}) {
		t.Errorf("names: %v", got)
	}
}

// The name of a host that answers a probe is fetched from it once in a rediscovery interval at
// most, by each protocol that does, and not while it has a name that stays; and what it gives is
// its own, at the MAC the state has its address at.
func TestNamingFetches(t *testing.T) {
	n := newProtocolsNamer(t)
	addr := netip.MustParseAddr("2001:db8::1")
	if !n.fetches(NameWSD, "eth0", addr) || n.fetches(NameWSD, "eth0", addr.WithZone("eth0")) {
		t.Error("fetched twice at once, or not at all")
	}
	if !n.fetches(NameSSDP, "eth0", addr) || !n.fetches(NameWSD, "eth1", addr) || !n.fetches(NameWSD, "eth0", netip.MustParseAddr("2001:db8::2")) {
		t.Error("another protocol, interface or host is not another's to fetch")
	}
	n.clock = n.clock.Add(n.rediscover / 2)
	if n.fetches(NameWSD, "eth0", addr) {
		t.Error("fetched again within the rediscovery interval")
	}
	// The probe of the next interval, which comes a moment sooner or later.
	n.clock = n.clock.Add(n.rediscover/2 - 10*time.Millisecond)
	if !n.fetches(NameWSD, "eth0", addr) {
		t.Error("not fetched again a rediscovery interval later")
	}

	// Its name comes before the discovery told its MAC: it waits for it, and the discovery is
	// asked.
	n.named(NameWSD, "eth0", addr, "WINBOX-P")
	if want := []string{"eth0 2001:db8::1"}; !slices.Equal(n.discovered, want) || len(n.state.AllNames()) != 0 {
		t.Fatalf("the discovery was asked for %v, want %v", n.discovered, want)
	}
	n.state.registerLocal(hostMAC(1), addr, "eth0", time.Hour, nil)
	n.resolve()
	if got := namesOf(n.state, hostMAC(1)); !slices.Equal(got, []string{"winbox-p (wsd)"}) {
		t.Errorf("names: %v", got)
	}
	// A friendly name is cleaned as any, and what is no name is none.
	n.named(NameSSDP, "eth0", addr, "Living Room TV")
	n.named(NameSSDP, "eth0", addr, "TV (salón)")
	if got := namesOf(n.state, hostMAC(1)); !slices.Equal(got, []string{"living-room-tv (ssdp)", "winbox-p (wsd)"}) {
		t.Errorf("names: %v", got)
	}

	// With a name that stays, nothing is fetched: until it is about to expire.
	n.clock = n.clock.Add(2 * n.rediscover)
	n.sayAgain(hostMAC(1), time.Hour, time.Hour)
	if n.fetches(NameWSD, "eth0", addr) {
		t.Error("fetched from a host whose name stays")
	}
	n.sayAgain(hostMAC(1), time.Hour, time.Minute)
	if !n.fetches(NameWSD, "eth0", addr) {
		t.Error("not fetched from a host whose name is about to expire")
	}

	// No more are remembered than a link of hosts that answer: the rest is not fetched, until
	// those of a rediscovery interval before are forgotten.
	for i := range 8 * namingPending {
		n.fetches(NameWSD, "eth0", netip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, 13: 1, 14: byte(i >> 8), 15: byte(i)}))
	}
	if len(n.fetched) > 4*namingPending {
		t.Errorf("%d fetches remembered", len(n.fetched))
	}
	n.clock = n.clock.Add(n.rediscover)
	if !n.fetches(NameWSD, "eth0", netip.MustParseAddr("2001:db8::ffff")) || len(n.fetched) != 1 {
		t.Errorf("%d fetches remembered a rediscovery interval later, want the one new", len(n.fetched))
	}
}

// The protocols of the names are those the configuration names, or all: an unknown one is
// refused, and the DNS servers are asked at the port of DNS unless they have their own.
func TestConfigHostnamesProtocols(t *testing.T) {
	config := DefaultConfig()
	for _, protocol := range NameProtocols() {
		if config.names(protocol) {
			t.Errorf("%s runs without names asked for", protocol)
		}
	}
	config.Hostnames.Enabled = true
	for _, protocol := range NameProtocols() {
		if !config.names(protocol) {
			t.Errorf("%s doesn't run by default", protocol)
		}
	}
	if !slices.Equal(NameProtocols()[:4], nameOrder) {
		t.Errorf("the protocols that ask, %v, are not in the order they ask in, %v", NameProtocols()[:4], nameOrder)
	}
	config.Hostnames.Protocols = []string{NameMDNS, NameDHCP}
	if !config.names(NameMDNS) || !config.names(NameDHCP) || config.names(NameLLMNR) || config.names(NameWSD) {
		t.Error("the protocols that run are not those named")
	}
	if err := config.withDefaults().validate(); err != nil {
		t.Error(err)
	}
	config.Hostnames.Protocols = []string{NameMDNS, "bonjour"}
	if err := config.withDefaults().validate(); err == nil || !strings.Contains(err.Error(), `"bonjour"`) || !strings.Contains(err.Error(), "mdns, dns, netbios, llmnr, wsd, ssdp, dhcp, lldp") {
		t.Errorf("an unknown protocol: %v", err)
	}

	config.Hostnames.Protocols = nil
	given := []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 0), netip.MustParseAddrPort("[fd00::1]:5353")}
	config.Hostnames.DNS = given
	got := config.withDefaults()
	if want := []netip.AddrPort{netip.MustParseAddrPort("192.168.1.1:53"), given[1]}; !slices.Equal(got.Hostnames.DNS, want) || given[0].Port() != 0 {
		t.Errorf("the servers: %v, want %v; given %v", got.Hostnames.DNS, want, given)
	}
	if err := got.validate(); err != nil || len(got.warnings()) != 0 {
		t.Errorf("servers given: %v, %v", err, got.warnings())
	}
	for _, server := range []string{"0.0.0.0:53", "224.0.0.1:53"} {
		config.Hostnames.DNS = []netip.AddrPort{netip.MustParseAddrPort(server)}
		if err := config.withDefaults().validate(); err == nil {
			t.Errorf("the server %s is taken", server)
		}
	}
	config.Hostnames.DNS = []netip.AddrPort{{}}
	if err := config.withDefaults().validate(); err == nil {
		t.Error("no server is taken as one")
	}
	if server, err := ParseNameServer("192.168.1.1"); err != nil || server != netip.MustParseAddrPort("192.168.1.1:53") {
		t.Errorf("a server as it is written: %s, %v", server, err)
	}
	if _, err := ParseNameServer("router.lan"); err == nil {
		t.Error("a server by its name, which something would have to resolve")
	}

	// Servers nothing asks, and a protocol with nobody to ask, are told.
	config.Hostnames = Hostnames{Enabled: true, Protocols: []string{NameMDNS}, DNS: given}
	if warnings := config.withDefaults().warnings(); len(warnings) != 1 || !strings.Contains(warnings[0], "dns is not among the protocols") {
		t.Errorf("servers that are not asked: %v", warnings)
	}
	config.Hostnames = Hostnames{Enabled: true, Protocols: []string{NameDNS}}
	if warnings := config.withDefaults().warnings(); len(warnings) != 1 || !strings.Contains(warnings[0], "no DNS server is given") {
		t.Errorf("the reverse DNS without servers: %v", warnings)
	}
	// With servers, the hosts of the plugins are asked of without any local discovery; without,
	// nothing asks.
	config = Config{Lifetime: time.Hour, IPv6: Family{Enabled: true}, Hostnames: Hostnames{Enabled: true, DNS: given}}
	if config.namesLocally() || !config.asksNames() {
		t.Error("the servers given are not asked without local discovery")
	}
	config.Hostnames.DNS = nil
	if config.asksNames() {
		t.Error("something asks without local discovery nor servers")
	}
}

// The sender of an ARP packet heard is registered as a neighbor of the table is, on its
// interface: a host of a subnet of the interface, and not the interface itself.
func TestHeardARP(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Lifetime: time.Hour, IPv4: Family{Enabled: true, Listen: true}})
	defer w.State.Close()
	own := hostMAC(5)
	heard := w.heardARP(ipv4Interface{iface: net.Interface{Index: 2, Name: "eth0", HardwareAddr: own},
		prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.5/24"), netip.MustParsePrefix("10.0.0.5/8")}})
	if !heard(hostIPv4(20), hostMAC(1)) || heard(hostIPv4(20), hostMAC(1)) {
		t.Error("a host heard is found once")
	}
	if !heard(netip.MustParseAddr("10.9.9.9"), hostMAC(1)) {
		t.Error("a host of the other subnet of the interface was left out")
	}
	for name, c := range map[string]struct {
		ip  netip.Addr
		mac net.HardwareAddr
	}{
		"an address of no subnet of the interface": {netip.MustParseAddr("172.16.0.1"), hostMAC(2)},
		"the interface's own address":              {hostIPv4(5), hostMAC(2)},
		"the interface's own MAC":                  {hostIPv4(30), own},
		"the broadcast address of a subnet":        {netip.MustParseAddr("192.168.1.255"), hostMAC(2)},
		"the address of a subnet itself":           {netip.MustParseAddr("10.0.0.0"), hostMAC(2)},
	} {
		if heard(c.ip, c.mac) {
			t.Errorf("%s was taken as a host found", name)
		}
	}
	all := w.State.GetAll()
	if len(all) != 1 || len(all[hostMAC(1).String()].Get()) != 2 {
		t.Fatalf("the state has %v", all)
	}
	for _, addr := range all[hostMAC(1).String()].Get() {
		if !slices.Equal(addr.Interfaces(), []string{"eth0"}) || addr.Self() {
			t.Errorf("%s seen on %v, self %v", addr.WithZone(""), addr.Interfaces(), addr.Self())
		}
	}
	// A link where every frame is of another MAC, made up, fills the state with arpNewMost in an
	// interval, no more; the hosts it has are still heard, and refreshed.
	flood := NewWorker(zap.NewNop().Sugar(), Config{Lifetime: time.Hour, IPv4: Family{Enabled: true, Listen: true}})
	defer flood.State.Close()
	heard = flood.heardARP(ipv4Interface{iface: net.Interface{Index: 2, Name: "eth0", HardwareAddr: own}, prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.5/8")}})
	if !heard(netip.MustParseAddr("10.1.1.1"), hostMAC(1)) {
		t.Error("the first host was left out")
	}
	for i := range 2 * arpNewMost {
		heard(netip.AddrFrom4([4]byte{10, 2, byte(i >> 8), byte(i)}), hostMAC(100+i))
	}
	if got := len(flood.State.GetAll()); got != arpNewMost {
		t.Errorf("%d hosts registered of a flood, want %d", got, arpNewMost)
	}
	expires := flood.State.GetAll()[hostMAC(1).String()].Get()[0].GetExpiration()
	time.Sleep(2 * time.Millisecond)
	if heard(netip.MustParseAddr("10.1.1.1"), hostMAC(1)) || !flood.State.GetAll()[hostMAC(1).String()].Get()[0].GetExpiration().After(expires) {
		t.Error("a host the state has was not refreshed, heard again while too many new ones are")
	}
	// A subnet of two addresses has no broadcast one: both are hosts.
	if !hostOf(netip.MustParsePrefix("10.0.0.0/31"), netip.MustParseAddr("10.0.0.1")) || hostOf(netip.MustParsePrefix("10.0.0.0/31"), netip.MustParseAddr("10.0.0.2")) {
		t.Error("the hosts of a /31")
	}

	// Without the IPv4 family, the state takes none.
	off := NewWorker(zap.NewNop().Sugar(), Config{Lifetime: time.Hour, IPv6: Family{Enabled: true}})
	defer off.State.Close()
	if off.heardARP(ipv4Interface{iface: net.Interface{Name: "eth0", HardwareAddr: own}, prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.5/24")}})(hostIPv4(20), hostMAC(1)) || len(off.State.GetAll()) != 0 {
		t.Error("an IPv4 host registered without the family")
	}
}

// The stats show the listener of ARP of an interface under it, and the naming protocols of no
// interface after those of all.
func TestWorkerStatsOfTheProtocols(t *testing.T) {
	w := NewWorker(zap.NewNop().Sugar(), Config{Lifetime: time.Hour, IPv4: Family{Enabled: true, Listen: true}, Hostnames: Hostnames{Enabled: true}})
	defer w.State.Close()
	w.arpListeners[arpKey{index: 2, name: "eth0"}] = &arp.Listener{}
	w.nameConns[nameKey{index: 2, name: "eth0"}] = &nameProcesses{InterfaceName: "eth0", Protocols: []*NameProtocol{{Name: NameDHCP, Worker: &fakeAsker{}}}}
	w.nameGlobal = []*NameProtocol{{Name: NameDNS, Worker: &fakeAsker{}}}
	stats := w.PrettyPrintStats("")
	if want := "    eth0:\n        ipv4:\n            arp  : hosts=0 recv=0\n        names:\n            dhcp :\n    names:\n            dns  :\nPlugins:\n"; !strings.Contains(stats, want) {
		t.Errorf("stats:\n%s\nwant\n%s", stats, want)
	}
	if got := w.nameProtocols(""); len(got) != 1 || got[0].Name != NameDNS {
		t.Errorf("the protocols of no interface: %v", got)
	}
}
