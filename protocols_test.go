package ipv6disc

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/arp"
	"go.uber.org/zap"
)

// everyProtocol is every protocol enabled, with all it needs to be: servers for the reverse DNS,
// and both families probing.
func everyProtocol() Config {
	on := Protocol{Enabled: true}
	probing := Family{Enabled: true, Listen: true, Active: true}
	return Config{Lifetime: time.Hour, IPv6: probing, IPv4: probing,
		Protocols: Protocols{NDP: on, Ping: on, SSDP: SSDPProtocol{Enabled: true, Names: true}, WSD: WSDProtocol{Enabled: true, Names: true},
			MDNS: MDNSProtocol{Enabled: true, Ask: true}, ARP: on, ARPSweep: ARPSweepProtocol{Enabled: true}, ARPListen: on, DHCP: on, LLDP: on,
			NetBIOS: on, LLMNR: on, DNS: DNSProtocol{Enabled: true, Servers: []netip.AddrPort{netip.MustParseAddrPort("192.168.1.1:53")}}}}
}

// withPacketSockets has the system taken as one that has packet sockets, or as one that
// doesn't, for the test.
func withPacketSockets(t *testing.T, has bool) {
	t.Helper()
	before := packetSockets
	packetSockets = has
	t.Cleanup(func() { packetSockets = before })
}

// The names of the protocols are the fields of Protocols, one each and in their order, and
// enabled knows every one.
func TestProtocolNames(t *testing.T) {
	typ := reflect.TypeFor[Protocols]()
	names := ProtocolNames()
	if typ.NumField() != len(names) {
		t.Fatalf("%d fields of Protocols, %d names", typ.NumField(), len(names))
	}
	for i, name := range names {
		field := typ.Field(i)
		if strings.ToLower(field.Name) != strings.ReplaceAll(name, "-", "") {
			t.Errorf("the protocol %d is %q, and the field %s", i, name, field.Name)
		}
		if _, ok := field.Type.FieldByName("Enabled"); !ok {
			t.Errorf("%s has no Enabled", field.Name)
		}
		// Each alone is the one enabled knows.
		var p Protocols
		reflect.ValueOf(&p).Elem().Field(i).FieldByName("Enabled").SetBool(true)
		for _, other := range names {
			if p.enabled(other) != (other == name) {
				t.Errorf("with %s alone, %s enabled: %v", field.Name, other, p.enabled(other))
			}
		}
	}
	if (Protocols{}).enabled("bonjour") {
		t.Error("a protocol there is none of, enabled")
	}
}

// The defaults are every protocol, with its options on: those that hear frames where the system
// can, and the reverse DNS once it has servers.
func TestDefaultProtocols(t *testing.T) {
	// As the system is: only Linux has what hears frames.
	if (DefaultProtocols().ARPListen.Enabled) != (runtime.GOOS == "linux") {
		t.Errorf("on %s, the ARP heard by default: %v", runtime.GOOS, DefaultProtocols().ARPListen.Enabled)
	}
	for _, linux := range []bool{true, false} {
		withPacketSockets(t, linux)
		want := map[string]bool{}
		for _, name := range ProtocolNames() {
			want[name] = true
		}
		want[ProtocolARPListen], want[ProtocolDHCP], want[ProtocolLLDP] = linux, linux, linux
		defaults := DefaultProtocols()
		for _, name := range ProtocolNames() {
			if defaults.enabled(name) != want[name] {
				t.Errorf("packet sockets %v: %s enabled %v by default, want %v", linux, name, defaults.enabled(name), want[name])
			}
		}
		if !defaults.SSDP.Names || !defaults.WSD.Names || !defaults.MDNS.Ask || defaults.ARPSweep.MaxPrefix != 22 || len(defaults.DNS.Servers) != 0 {
			t.Errorf("the options by default: %+v", defaults)
		}
		config := DefaultConfig()
		if !reflect.DeepEqual(config.Protocols, defaults) || config.IPv4.Enabled || !config.IPv4.Listen || !config.IPv4.Active {
			t.Errorf("the default configuration: %+v", config)
		}
		if err := config.Validate(); err != nil {
			t.Errorf("packet sockets %v: the default: %v", linux, err)
		}
		// IPv6 alone runs, until IPv4 is turned on; the reverse DNS, with no server, not.
		wantIPv6 := []string{"ndp", "ping", "ssdp", "wsd", "mdns", "llmnr"}
		wantIPv4 := []string{"ndp", "ping", "ssdp", "wsd", "mdns", "arp", "arp-sweep", "netbios", "llmnr"}
		if linux {
			wantIPv6 = []string{"ndp", "ping", "ssdp", "wsd", "mdns", "dhcp", "lldp", "llmnr"}
			wantIPv4 = []string{"ndp", "ping", "ssdp", "wsd", "mdns", "arp", "arp-sweep", "arp-listen", "dhcp", "lldp", "netbios", "llmnr"}
		}
		if got := config.running(); !slices.Equal(got, wantIPv6) {
			t.Errorf("the default runs %v, want %v", got, wantIPv6)
		}
		config.IPv4.Enabled = true
		if got := config.running(); !slices.Equal(got, wantIPv4) {
			t.Errorf("with IPv4, it runs %v, want %v", got, wantIPv4)
		}
	}
}

// A worker tells the protocols it runs, for a program that shows them: those of its
// configuration, and none of a Config made by hand without them.
func TestWorkerProtocols(t *testing.T) {
	withPacketSockets(t, false)
	if got := NewWorker(zap.NewNop().Sugar(), DefaultConfig()).Protocols(); !slices.Equal(got, []string{"ndp", "ping", "ssdp", "wsd", "mdns", "llmnr"}) {
		t.Errorf("the default runs %v", got)
	}
	config := DefaultConfig()
	config.Protocols.SSDP.Enabled, config.Protocols.MDNS.Enabled = false, false
	if got := NewWorker(zap.NewNop().Sugar(), config).Protocols(); !slices.Equal(got, []string{"ndp", "ping", "wsd", "llmnr"}) {
		t.Errorf("without ssdp and mdns, it runs %v", got)
	}
	if got := NewWorker(zap.NewNop().Sugar(), Config{Lifetime: time.Hour, IPv6: Family{Enabled: true, Listen: true}}).Protocols(); len(got) != 0 {
		t.Errorf("a Config without protocols runs %v", got)
	}
}

// protocolRuns is the family, and the way, a protocol runs with: what the page of the discovery
// tells of each.
var protocolRuns = map[string]struct {
	family string
	way    string
}{
	ProtocolNDP:       {"IPv6", "listen"},
	ProtocolPing:      {"IPv6", "listen"},
	ProtocolSSDP:      {"IPv6", "listen"},
	ProtocolWSD:       {"IPv6", "listen"},
	ProtocolMDNS:      {"either", "listen"},
	ProtocolARP:       {"IPv4", "listen"},
	ProtocolARPSweep:  {"IPv4", "active"},
	ProtocolARPListen: {"IPv4", "listen"},
	ProtocolDHCP:      {"either", "listen"},
	ProtocolLLDP:      {"either", "listen"},
	ProtocolNetBIOS:   {"IPv4", "listen"},
	ProtocolLLMNR:     {"either", "listen"},
	ProtocolDNS:       {"none", ""},
}

// A protocol runs only when it is enabled, and its family is, and listens, or for the sweep
// probes; the reverse DNS, of no family, once it has servers.
func TestProtocolsRunWithTheirFamily(t *testing.T) {
	withPacketSockets(t, true)
	all := everyProtocol()
	if err := all.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := all.running(); !slices.Equal(got, ProtocolNames()) {
		t.Fatalf("every protocol enabled, and %v run", got)
	}
	off, listening, probing := Family{Listen: true, Active: true}, Family{Enabled: true, Listen: true}, Family{Enabled: true, Listen: true, Active: true}
	for _, name := range ProtocolNames() {
		want := protocolRuns[name]
		runs := func(ipv6, ipv4 Family) bool {
			c := all
			c.IPv6, c.IPv4 = ipv6, ipv4
			return c.runs(name)
		}
		// By family.
		got := "none"
		switch v6, v4 := runs(probing, off), runs(off, probing); {
		case v6 && v4 && runs(off, off):
		case v6 && v4:
			got = "either"
		case v6:
			got = "IPv6"
		case v4:
			got = "IPv4"
		default:
			t.Errorf("%s runs with no family", name)
		}
		if got != want.family {
			t.Errorf("%s is of the family %s, want %s", name, got, want.family)
		}
		// By way: listening is enough, or it needs the probes.
		way := ""
		switch {
		case want.family == "none":
		case runs(listening, listening):
			way = "listen"
		case runs(probing, probing):
			way = "active"
		}
		if way != want.way {
			t.Errorf("%s runs with %q, want %q", name, way, want.way)
		}
		// A family that only has active on, without listening, runs nothing.
		if want.family != "none" && runs(Family{Enabled: true, Active: true}, Family{Enabled: true, Active: true}) {
			t.Errorf("%s runs without listening", name)
		}
		// And never when it is off.
		c := everyProtocol()
		c.Protocols = Protocols{}
		if c.runs(name) {
			t.Errorf("%s runs disabled", name)
		}
	}

	// The names of SSDP and WS-Discovery are fetched with their protocol, the option and the
	// names kept.
	if !all.fetchesNames(ProtocolSSDP) || !all.fetchesNames(ProtocolWSD) || all.fetchesNames(ProtocolMDNS) {
		t.Error("the names fetched with everything on")
	}
	for what, change := range map[string]func(*Config){
		"the protocol off":  func(c *Config) { c.Protocols.SSDP.Enabled, c.Protocols.WSD.Enabled = false, false },
		"the option off":    func(c *Config) { c.Protocols.SSDP.Names, c.Protocols.WSD.Names = false, false },
		"IPv6 off":          func(c *Config) { c.IPv6.Enabled = false },
		"IPv6 not listened": func(c *Config) { c.IPv6.Listen = false },
	} {
		c := everyProtocol()
		change(&c)
		if c.fetchesNames(ProtocolSSDP) || c.fetchesNames(ProtocolWSD) {
			t.Errorf("with %s, names are fetched", what)
		}
	}
}

// The page of the discovery has the table of the protocols as the code has them: each with its
// default, its family and the way it runs with.
func TestDiscoveryPageProtocols(t *testing.T) {
	withPacketSockets(t, true)
	page, err := os.ReadFile(filepath.Join("docs", "discovery.md"))
	if err != nil {
		t.Fatal(err)
	}
	defaults := DefaultProtocols()
	for _, name := range ProtocolNames() {
		runs := protocolRuns[name]
		row := fmt.Sprintf("| `%s` | %s | %s | %s |", name,
			map[bool]string{true: "on", false: "off"}[defaults.enabled(name)],
			map[string]string{"IPv6": "IPv6", "IPv4": "IPv4", "either": "Either", "none": "None"}[runs.family],
			map[string]string{"listen": "`listen`", "active": "`active`", "": "-"}[runs.way])
		if name == ProtocolARPListen || name == ProtocolDHCP || name == ProtocolLLDP {
			row = strings.Replace(row, "| on |", "| on, on Linux |", 1)
		}
		if !strings.Contains(string(page), row) {
			t.Errorf("docs/discovery.md has no row %q: the code has it so", row)
		}
	}
	for _, want := range []string{
		fmt.Sprintf("from %d to %d", MinSweepPrefix, MaxSweepPrefix),
		fmt.Sprintf("`max_prefix`, %d by default", arp.DefaultSweepPrefix),
	} {
		if !strings.Contains(string(page), want) {
			t.Errorf("docs/discovery.md doesn't say %q: the code does", want)
		}
	}
}

// What can't run is refused at start, each with its own error: all of them at once.
func TestProtocolsValidate(t *testing.T) {
	withPacketSockets(t, true)
	if err := everyProtocol().Validate(); err != nil {
		t.Fatalf("every protocol: %v", err)
	}
	for _, tt := range []struct {
		what   string
		change func(*Config)
		want   []string
	}{
		{"a server that is none", func(c *Config) {
			c.Protocols.DNS.Servers = []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:53"), netip.MustParseAddrPort("224.0.0.1:53"), {}}
		}, []string{"invalid server of the dns protocol: 0.0.0.0:53", "invalid server of the dns protocol: 224.0.0.1:53", "invalid server of the dns protocol: invalid AddrPort"}},
		{"the protocols of IPv6 without NDP", func(c *Config) { c.Protocols.NDP.Enabled = false }, []string{
			"the ping protocol is enabled without ndp, which tells the MAC of the hosts it hears: it would find none",
			"the ssdp protocol is enabled without ndp, which tells the MAC of the hosts it hears: it would find none",
			"the wsd protocol is enabled without ndp, which tells the MAC of the hosts it hears: it would find none",
		}},
		{"the sweep with nothing to tell its answers", func(c *Config) { c.Protocols.ARP.Enabled, c.Protocols.ARPListen.Enabled = false, false },
			[]string{"the arp-sweep protocol is enabled without arp or arp-listen, which tell the hosts that answer it: it would find none"}},
		{"a subnet too large to sweep", func(c *Config) { c.Protocols.ARPSweep.MaxPrefix = 15 },
			[]string{"invalid max_prefix of the arp-sweep protocol, 15: it is from 16 to 30"}},
		{"a subnet of no host to sweep", func(c *Config) { c.Protocols.ARPSweep.MaxPrefix = 31 },
			[]string{"invalid max_prefix of the arp-sweep protocol, 31: it is from 16 to 30"}},
		{"a negative prefix", func(c *Config) { c.Protocols.ARPSweep.MaxPrefix = -1 },
			[]string{"invalid max_prefix of the arp-sweep protocol, -1: it is from 16 to 30"}},
		{"what hears frames, where the system has no packet sockets", func(c *Config) { packetSockets = false }, []string{
			"the arp-listen protocol is enabled, and this system can't run it: it needs Linux",
			"the dhcp protocol is enabled, and this system can't run it: it needs Linux",
			"the lldp protocol is enabled, and this system can't run it: it needs Linux",
		}},
	} {
		packetSockets = true
		c := everyProtocol()
		tt.change(&c)
		err := c.Validate()
		var got []string
		if err != nil {
			got = strings.Split(err.Error(), "\n")
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s:\n%s\nwant\n%s", tt.what, strings.Join(got, "\n"), strings.Join(tt.want, "\n"))
		}
		// And the worker doesn't start with it.
		w := NewWorker(zap.NewNop().Sugar(), c)
		if err := w.Start(t.Context()); err == nil || err.Error() != strings.Join(tt.want, "\n") {
			t.Errorf("%s: the worker started: %v", tt.what, err)
		}
		w.State.Close()
	}
	packetSockets = true

	// The options of a protocol that is off are not looked at, whatever they are; and both ends
	// of the range of the sweep are in it.
	c := everyProtocol()
	c.Protocols.SSDP, c.Protocols.WSD = SSDPProtocol{Names: true}, WSDProtocol{Names: true}
	c.Protocols.DNS = DNSProtocol{Servers: []netip.AddrPort{{}}}
	c.Protocols.ARPSweep = ARPSweepProtocol{MaxPrefix: 99}
	c.Protocols.Ping.Enabled = false
	if err := c.Validate(); err != nil {
		t.Errorf("options of protocols that are off: %v", err)
	}
	for _, bits := range []int{MinSweepPrefix, MaxSweepPrefix, 0} {
		c := everyProtocol()
		c.Protocols.ARPSweep.MaxPrefix = bits
		if err := c.Validate(); err != nil {
			t.Errorf("a max_prefix of %d: %v", bits, err)
		}
	}
	// The reverse DNS without servers is valid, and runs not.
	c = everyProtocol()
	c.Protocols.DNS.Servers = nil
	if err := c.Validate(); err != nil || c.runs(ProtocolDNS) {
		t.Errorf("the reverse DNS without servers: %v, runs %v", err, c.runs(ProtocolDNS))
	}

	// On a system without packet sockets the defaults are valid: the ARP heard is not among them.
	packetSockets = false
	if err := DefaultConfig().Validate(); err != nil {
		t.Errorf("the default, without packet sockets: %v", err)
	}
}

// The options left zero are their defaults, and the servers are asked at the port of DNS unless
// they have their own: in a copy, what was given stays as it was.
func TestProtocolsDefaults(t *testing.T) {
	given := []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 0), netip.MustParseAddrPort("[fd00::1]:5353")}
	c := Config{Lifetime: time.Hour, Protocols: Protocols{ARPSweep: ARPSweepProtocol{Enabled: true}, DNS: DNSProtocol{Enabled: true, Servers: given}}}
	got := c.withDefaults()
	if got.Protocols.ARPSweep.MaxPrefix != arp.DefaultSweepPrefix || arp.DefaultSweepPrefix != 22 || 32-arp.MaxSweepBits != 22 {
		t.Errorf("the largest subnet swept: /%d", got.Protocols.ARPSweep.MaxPrefix)
	}
	if want := []netip.AddrPort{netip.MustParseAddrPort("192.168.1.1:53"), given[1]}; !slices.Equal(got.Protocols.DNS.Servers, want) || given[0].Port() != 0 {
		t.Errorf("the servers: %v, want %v; given %v", got.Protocols.DNS.Servers, want, given)
	}
	c.Protocols.ARPSweep.MaxPrefix = 24
	if got := c.withDefaults().Protocols.ARPSweep.MaxPrefix; got != 24 {
		t.Errorf("a max_prefix given: /%d", got)
	}
}

// A family that listens with no protocol to find its hosts is warned of: a Config made by hand,
// without DefaultProtocols, finds this machine's own addresses only.
func TestProtocolsWarnings(t *testing.T) {
	withPacketSockets(t, true)
	listening := Family{Enabled: true, Listen: true}
	for _, tt := range []struct {
		what string
		c    Config
		want []string
	}{
		{"no protocol at all", Config{Lifetime: time.Hour, IPv6: listening, IPv4: listening}, []string{
			"IPv6 listens, but no protocol that finds its hosts is enabled: this machine's own addresses only",
			"IPv4 listens, but no protocol that finds its hosts is enabled: this machine's own addresses only"}},
		{"the defaults", Config{Lifetime: time.Hour, IPv6: listening, IPv4: listening, Protocols: DefaultProtocols()}, nil},
		{"the ARP heard alone", Config{Lifetime: time.Hour, IPv4: listening, Protocols: Protocols{ARPListen: Protocol{Enabled: true}}}, nil},
		{"mDNS alone, which is of both", Config{Lifetime: time.Hour, IPv6: listening, IPv4: listening, Protocols: Protocols{MDNS: MDNSProtocol{Enabled: true}}}, nil},
		{"the families off, or not listening", Config{Lifetime: time.Hour, IPv6: Family{Enabled: true}, IPv4: Family{Listen: true}}, nil},
		{"names alone, which find nothing", Config{Lifetime: time.Hour, IPv4: listening, Protocols: Protocols{NetBIOS: Protocol{Enabled: true}}},
			[]string{"IPv4 listens, but no protocol that finds its hosts is enabled: this machine's own addresses only"}},
	} {
		c := tt.c.withDefaults()
		if err := c.validate(); err != nil {
			t.Errorf("%s: %v", tt.what, err)
		}
		if got := c.warnings(); !slices.Equal(got, tt.want) {
			t.Errorf("%s: warnings %q, want %q", tt.what, got, tt.want)
		}
	}
}

// mDNS told not to ask is no protocol to ask a host by: the others still do.
func TestNamingLeavesOutASilentProtocol(t *testing.T) {
	n := newTestNamer(t)
	other := &fakeAsker{nets: n.asker.nets}
	n.askers = func(iface string) []*NameProtocol {
		return []*NameProtocol{{Name: NameMDNS, Worker: n.asker, silent: true}, {Name: NameLLMNR, Worker: other}}
	}
	n.state.registerLocal(hostMAC(1), hostIPv4(1), Record{Protocol: ProtocolNDP, Way: Heard, On: "eth0"}, time.Hour, nil)
	n.lookups()
	if asked := n.asker.take(); len(asked) != 0 {
		t.Errorf("mDNS, told not to ask, asked %v", asked)
	}
	if asked := other.take(); !slices.Equal(asked, []netip.Addr{hostIPv4(1)}) {
		t.Errorf("LLMNR asked %v, want the host", asked)
	}
}

// The sweep is of the subnets no larger than max_prefix, and what a host is asked without
// prefixes is what a sweep would ask.
func TestSweepFollowsMaxPrefix(t *testing.T) {
	local := netip.MustParsePrefix("10.0.0.5/20")
	if got := probeTargets(local, nil, 22); len(got) != 253 {
		t.Errorf("a /20 with a /22 at most: %d addresses, want those of its /24", len(got))
	}
	if got := probeTargets(local, nil, 20); len(got) != 4093 {
		t.Errorf("a /20 with a /20 at most: %d addresses, want all of it", len(got))
	}
	// The option of a sweep that is off is not looked at, which nothing validated: a host is
	// asked what the default sweep would ask, not the whole of a subnet of any size.
	for maxPrefix, want := range map[int]int{0: 22, 20: 20, 8: 8, -3: -3, 99: 99} {
		c := Config{Lifetime: time.Hour, Protocols: Protocols{ARPSweep: ARPSweepProtocol{Enabled: true, MaxPrefix: maxPrefix}}}.withDefaults()
		if got := c.sweepPrefix(); got != want {
			t.Errorf("a sweep that is on, with a max_prefix of %d: /%d, want /%d", maxPrefix, got, want)
		}
		c.Protocols.ARPSweep.Enabled = false
		if got := c.sweepPrefix(); got != 22 {
			t.Errorf("a sweep that is off, with a max_prefix of %d: /%d, want the default", maxPrefix, got)
		}
	}
}
