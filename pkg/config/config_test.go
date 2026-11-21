package config

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

// linux tells whether the system runs what hears frames, the ARP heard, DHCP and LLDP: an error
// to enable elsewhere.
const linux = runtime.GOOS == "linux"

// A command without a configuration, and one with an empty file, discover as
// ipv6disc.DefaultConfig does: nothing of the file's form has a default of its own.
func TestDefaultIsDefaultConfig(t *testing.T) {
	if got, want := Default().Config(), ipv6disc.DefaultConfig(); !reflect.DeepEqual(got, want) {
		t.Errorf("the default of the file:\n%+v\nwant ipv6disc.DefaultConfig:\n%+v", got, want)
	}
	if err := Default().Validate(); err != nil {
		t.Errorf("the default: %v", err)
	}
	for _, empty := range []string{"", "\n", "# nothing\n", "{}", "---\n", "protocols:\n", "protocols: {}\nipv6:\nplugins:\n"} {
		file, err := Parse([]byte(empty))
		if err != nil || !reflect.DeepEqual(file, Default()) {
			t.Errorf("%q: %+v, %v, want the default", empty, file, err)
		}
	}
	if plugins, err := Default().NewPlugins(); err != nil || len(plugins) != 0 {
		t.Errorf("the plugins of the default: %v, %v", plugins, err)
	}
}

// The defaults, as a file would write them: every protocol, those that hear frames where they can.
func TestDefaultsTable(t *testing.T) {
	got, err := json.MarshalIndent(Default(), "", " ")
	if err != nil {
		t.Fatal(err)
	}
	want := `{
 "lifetime": "4h0m0s",
 "rediscover": "0s",
 "interfaces": null,
 "exclude_interfaces": null,
 "ipv6": {"enabled": true, "listen": true, "active": true, "lifetime": "0s"},
 "ipv4": {"enabled": false, "listen": true, "active": true, "lifetime": "0s"},
 "hostnames": {"lifetime": "0s"},
 "protocols": {
  "ndp": {"enabled": true},
  "ping": {"enabled": true},
  "ssdp": {"enabled": true, "names": true},
  "wsd": {"enabled": true, "names": true},
  "mdns": {"enabled": true, "ask": true},
  "arp": {"enabled": true},
  "arp-sweep": {"enabled": true, "max_prefix": 22},
  "arp-listen": {"enabled": ` + map[bool]string{true: "true", false: "false"}[linux] + `},
  "dhcp": {"enabled": ` + map[bool]string{true: "true", false: "false"}[linux] + `},
  "lldp": {"enabled": ` + map[bool]string{true: "true", false: "false"}[linux] + `},
  "netbios": {"enabled": true},
  "llmnr": {"enabled": true},
  "dns": {"enabled": true, "servers": []}
 },
 "plugins": null,
 "log_level": "info"
}`
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("the defaults:\n%s\nwant\n%s", got, want)
	}
	// And the keys of the protocols are the library's names, in its order.
	var names []string
	for _, field := range reflect.VisibleFields(reflect.TypeFor[Protocols]()) {
		names = append(names, field.Tag.Get("json"))
	}
	if !slices.Equal(names, ipv6disc.ProtocolNames()) {
		t.Errorf("the protocols of a file are %v, the library's %v", names, ipv6disc.ProtocolNames())
	}
}

// Every key of a file reaches the configuration of the worker, and the plugins.
func TestParse(t *testing.T) {
	file, err := Parse([]byte(`
lifetime: 2h
rediscover: 600        # seconds
interfaces:
  - eth0
  - "en*"
exclude_interfaces: docker*, veth*
ipv6:
  active: false
  lifetime: 30m
ipv4:
  enabled: true
  listen: true
  active: true
  lifetime: 1h30m
hostnames:
  lifetime: 90m
protocols:
  ndp:
    enabled: true
  ping:
    enabled: false
  ssdp:
    enabled: true
    names: true
  wsd:
    enabled: false
    names: true
  mdns:
    enabled: true
    ask: false
  arp:
    enabled: true
  arp-sweep:
    enabled: true
    max_prefix: 24
  arp-listen:
    enabled: false
  netbios:
    enabled: true
  llmnr:
    enabled: true
  dns:
    enabled: true
    servers:
      - 192.168.1.1
      - "[fd00::1]:5353"
plugins:
  router:
    type: mikrotik
    interval: 60s
    address: 192.168.88.1
    username: ipv6disc
    password: "se,cret\\"
    use_tls: true
  ap:
    type: linux
    interval: 90
    address: "[2001:db8::1]:2222"
    username: root
    identity_file: /key
log_level: debug
`))
	if err != nil {
		t.Fatal(err)
	}
	on := ipv6disc.Protocol{Enabled: true}
	want := ipv6disc.Config{
		Lifetime: 2 * time.Hour, Rediscover: 10 * time.Minute,
		Interfaces: []string{"eth0", "en*"}, ExcludeInterfaces: []string{"docker*", "veth*"},
		IPv6:      ipv6disc.Family{Enabled: true, Listen: true, Lifetime: 30 * time.Minute},
		IPv4:      ipv6disc.Family{Enabled: true, Listen: true, Active: true, Lifetime: 90 * time.Minute},
		Hostnames: ipv6disc.Hostnames{Lifetime: 90 * time.Minute},
		Protocols: ipv6disc.Protocols{
			NDP: on, SSDP: ipv6disc.SSDPProtocol{Enabled: true, Names: true}, WSD: ipv6disc.WSDProtocol{Names: true},
			MDNS: ipv6disc.MDNSProtocol{Enabled: true}, ARP: on, ARPSweep: ipv6disc.ARPSweepProtocol{Enabled: true, MaxPrefix: 24},
			// Not in the file: on where they can run.
			DHCP: ipv6disc.Protocol{Enabled: linux}, LLDP: ipv6disc.Protocol{Enabled: linux},
			NetBIOS: on, LLMNR: on,
			DNS: ipv6disc.DNSProtocol{Enabled: true, Servers: []netip.AddrPort{netip.MustParseAddrPort("192.168.1.1:53"), netip.MustParseAddrPort("[fd00::1]:5353")}},
		},
	}
	if got := file.Config(); !reflect.DeepEqual(got, want) {
		t.Errorf("the configuration:\n%+v\nwant\n%+v", got, want)
	}
	if file.LogLevel != "debug" {
		t.Errorf("log_level: %q", file.LogLevel)
	}
	// The plugins, in the order of their names, with their fields as their params: a comma and
	// a backslash of a password escaped, a number of seconds as a duration.
	made, err := file.NewPlugins()
	if err != nil || len(made) != 2 || made[0].Name() != "ap" || made[1].Name() != "router" {
		t.Fatalf("the plugins: %v, %v", made, err)
	}
	for name, want := range map[string]string{
		"router": `1m0s,192.168.88.1,ipv6disc,se\,cret\\,true`,
		"ap":     `1m30s,[2001:db8::1]:2222,root,,/key`,
	} {
		if got, err := file.Plugins[name].Params(); err != nil || got != want {
			t.Errorf("the params of %s: %q, %v, want %q", name, got, err, want)
		}
	}

	// JSON is YAML too, and what a file leaves out stays its default.
	file, err = Parse([]byte(`{"ipv4": {"enabled": true}, "protocols": {"arp-sweep": {"enabled": false}}}`))
	wantFile := Default()
	wantFile.IPv4.Enabled, wantFile.Protocols.ARPSweep.Enabled = true, false
	if err != nil || !reflect.DeepEqual(file, wantFile) {
		t.Errorf("JSON: %+v, %v", file, err)
	}
	if file.Protocols.ARPSweep.MaxPrefix != 22 || !file.IPv4.Listen || !file.IPv4.Active {
		t.Errorf("what was left out: %+v, %+v", file.Protocols.ARPSweep, file.IPv4)
	}
}

// What a file can't say is refused, each with its own error, which names where it is and what
// there is: nothing is left out without a word, nor taken as something else.
func TestParseErrors(t *testing.T) {
	protocols := "ndp, ping, ssdp, wsd, mdns, arp, arp-sweep, arp-listen, dhcp, lldp, netbios, llmnr, dns"
	for _, tt := range []struct {
		what, file string
		want       []string
	}{
		{"a protocol there is none of", "protocols:\n  bonjour:\n    enabled: true",
			[]string{"protocols.bonjour: no such protocol: they are " + protocols}},
		{"an option its protocol doesn't have", "protocols:\n  mdns:\n    enabled: true\n    asks: false",
			[]string{"protocols.mdns.asks: no such option of mdns: it has enabled, ask"}},
		{"an option of another protocol", "protocols:\n  ndp:\n    names: true\n  arp-sweep:\n    servers:\n      - 192.168.1.1",
			[]string{"protocols.arp-sweep.servers: no such option of arp-sweep: it has enabled, max_prefix", "protocols.ndp.names: no such option of ndp: it has enabled"}},
		{"a switch in place of the settings", "protocols:\n  mdns: true\n  lldp: false",
			[]string{"protocols.lldp: false is not its settings: it is written as lldp, with enabled: false under it", "protocols.mdns: true is not its settings: it is written as mdns, with enabled: true under it"}},
		{"a family as a switch", "ipv4: true", []string{"ipv4: true is not its settings: it is written as ipv4, with enabled: true under it"}},
		{"the names as a switch, as they were", "hostnames: true", []string{"hostnames: true: " + namesAlwaysKept}},
		{"the names' switch, as it was", "hostnames:\n  enabled: false", []string{"hostnames.enabled: " + namesAlwaysKept}},
		{"a list in place of the protocols", "protocols:\n  - mdns\n  - dhcp", []string{`protocols: ["mdns","dhcp"] is not a mapping of its keys`}},
		{"a switch of the wrong type", `protocols: {mdns: {enabled: "sometimes"}}`, []string{`protocols.mdns.enabled: "sometimes" is not true or false`}},
		{"an option of the wrong type: a boolean", "protocols:\n  ssdp:\n    names: 1\n  mdns:\n    ask:\n      - true",
			[]string{"protocols.mdns.ask: [true] is not true or false", "protocols.ssdp.names: 1 is not true or false"}},
		{"an option of the wrong type: a number", `protocols: {arp-sweep: {max_prefix: "/24"}}`, []string{`protocols.arp-sweep.max_prefix: "/24" is not a whole number`}},
		{"a number that is not whole", "protocols:\n  arp-sweep:\n    max_prefix: 22.5", []string{"protocols.arp-sweep.max_prefix: 22.5 is not a whole number"}},
		{"an option of the wrong type: the servers", "protocols:\n  dns:\n    enabled: true\n    servers:\n      a: 1", []string{`protocols.dns.servers: {"a":1} is not a string, nor a list of them`}},
		{"a server by its name", "protocols:\n  dns:\n    enabled: true\n    servers:\n      - router.lan\n      - 192.168.1.1", []string{`protocols.dns.servers: invalid DNS server "router.lan": an address, as 192.168.1.1, or one with its port, as 192.168.1.1:5353 or [fd00::1]:53`}},
		{"a subnet too large to sweep", "protocols:\n  arp-sweep:\n    max_prefix: 8", []string{"invalid max_prefix of the arp-sweep protocol, 8: it is from 16 to 30"}},
		{"a sweep of no subnet at all", "protocols:\n  arp-sweep:\n    max_prefix: 0", []string{"invalid max_prefix of the arp-sweep protocol, 0: it is from 16 to 30"}},
		{"a negative one", "protocols:\n  arp-sweep:\n    max_prefix: -24", []string{"invalid max_prefix of the arp-sweep protocol, -24: it is from 16 to 30"}},
		{"a subnet of no host to sweep", "protocols:\n  arp-sweep:\n    max_prefix: 31", []string{"invalid max_prefix of the arp-sweep protocol, 31: it is from 16 to 30"}},
		{"the protocols of IPv6 without NDP", "protocols:\n  ndp:\n    enabled: false\n  ping:\n    enabled: false\n  ssdp:\n    enabled: false",
			[]string{"the wsd protocol is enabled without ndp, which tells the MAC of the hosts it hears: it would find none"}},

		{"a key there is none of", "hostname:\n  enabled: true\nlive: true", []string{
			"hostname: no such key: the configuration has lifetime, rediscover, interfaces, exclude_interfaces, ipv6, ipv4, hostnames, protocols, plugins, log_level",
			"live: no such key: the configuration has lifetime, rediscover, interfaces, exclude_interfaces, ipv6, ipv4, hostnames, protocols, plugins, log_level"}},
		{"a key a family doesn't have", "ipv6:\n  solicit: true", []string{"ipv6.solicit: no such key: ipv6 has enabled, listen, active, lifetime"}},
		{"the protocols of the names, where they were", "hostnames:\n  protocols:\n    - mdns", []string{"hostnames.protocols: no such key: hostnames has lifetime"}},
		{"a duration that is none", "lifetime: soon\nipv4:\n  lifetime:\n    - 1\nrediscover: 1e300", []string{
			"ipv4.lifetime: [1] is not a duration, as 90s or 4h, nor a number of seconds",
			`lifetime: "soon" is not a duration, as 90s or 4h, nor a number of seconds`,
			"rediscover: 1e+300 is not a duration, as 90s or 4h, nor a number of seconds"}},
		{"a lifetime of nothing", "lifetime: 0", []string{"invalid lifetime 0s or rediscovery interval 0s: they must be positive"}},
		{"a negative lifetime of a family", "ipv4:\n  lifetime: -1s", []string{"invalid family lifetime: IPv6 4h0m0s, IPv4 -1s"}},
		{"a pattern that is none", `interfaces: "["`, []string{`invalid interface pattern "[": syntax error in pattern`}},
		{"interfaces that are no names", "interfaces:\n  - eth0\n  - 3", []string{"interfaces: 3 is not a string, nor a list of them"}},
		{"a level of the log there is none of", "log_level: loud", []string{`log_level: "loud" is no level of the log: they are debug, info, warn, error`}},
		{"a level that is no string", "log_level: 3", []string{"log_level: 3 is not a string"}},
		{"a file that is no mapping", "- ipv6", []string{`the configuration is ["ipv6"], not a mapping of its keys`}},
		{"a key twice", "ipv4:\n  enabled: true\nipv4:\n  enabled: false", []string{`not YAML: yaml: unmarshal errors:`, `  line 4: key "ipv4" already set in map`}},
		{"an option twice", "protocols:\n  mdns:\n    enabled: true\n    enabled: false", []string{`not YAML: yaml: unmarshal errors:`, `  line 4: key "enabled" already set in map`}},
		{"a key there is none of, at every depth", "protocols:\n  mdns:\n    ask:\n      often: true\nplugins:\n  router:\n    type: linux\n    interval: 60s\n    address: 192.168.1.1\n    username: root\n    password: x\n    port: 22\nhostnames:\n  names: true", []string{
			"hostnames.names: no such key: hostnames has lifetime",
			"plugins.router.port: no such field of a linux plugin: it has interval, address, username, password, identity_file, host_key",
			`protocols.mdns.ask: {"often":true} is not true or false`}},
		{"two documents", "ipv4:\n  enabled: true\n---\nipv4:\n  enabled: false\n", []string{"the configuration is more than one YAML document: it is one, without a --- after it"}},
		{"what is no YAML", "ipv4: {enabled", []string{"not YAML: yaml: line 1: did not find expected ',' or '}'"}},

		{"a plugin without its type", "plugins:\n  router:\n    address: 192.168.1.1", []string{"plugins.router: a plugin has a type: one of freebsd, linux, mikrotik"}},
		{"a plugin of a type there is none of", "plugins:\n  router:\n    type: cisco", []string{`plugins.router.type: no such type of plugin, "cisco": they are freebsd, linux, mikrotik`}},
		{"a field its type doesn't have", "plugins:\n  router:\n    type: linux\n    interval: 60s\n    address: 192.168.1.1\n    username: root\n    password: x\n    use_tls: true",
			[]string{"plugins.router.use_tls: no such field of a linux plugin: it has interval, address, username, password, identity_file, host_key"}},
		{"a plugin without what it needs", "plugins:\n  router:\n    type: mikrotik\n    interval: 60s",
			[]string{"plugins.router: a mikrotik plugin needs its address", "plugins.router: a mikrotik plugin needs its username"}},
		// A number is not taken for a string: YAML reads 012345 as 5349.
		{"fields of the wrong type", "plugins:\n  router:\n    type: mikrotik\n    interval: often\n    address: 192.168.88.1\n    username: admin\n    password: 012345\n    use_tls: \"yes\"", []string{
			`plugins.router.interval: "often" is not a duration, as 90s or 4h, nor a number of seconds`,
			"plugins.router.password: 5349 is not a string: write it in quotes",
			`plugins.router.use_tls: "yes" is not true or false`}},
		{"a plugin that is nothing", "plugins:\n  router:", []string{"plugins.router: it is empty"}},
		{"what the plugin itself refuses", "plugins:\n  router:\n    type: linux\n    interval: 60s\n    address: 192.168.1.1\n    username: root",
			[]string{"plugins.router: a linux plugin needs a password or an identity file"}},
		{"a fingerprint without TLS", "plugins:\n  router:\n    type: mikrotik\n    interval: 60s\n    address: 192.168.88.1\n    username: admin\n    tls_fingerprint: \"" + strings.Repeat("ab", 32) + "\"",
			[]string{"plugins.router: tls_fingerprint needs use_tls=true: without TLS there is no certificate to check"}},
	} {
		_, err := Parse([]byte(tt.file))
		var got []string
		if err != nil {
			got = strings.Split(err.Error(), "\n")
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s:\n%s\nwant\n%s", tt.what, strings.Join(got, "\n"), strings.Join(tt.want, "\n"))
		}
	}
}

// What hears frames is an error to enable where the system can't run it, and only there: by
// default it is on where it can be, and off elsewhere, with no error.
func TestParseProtocolsOfLinux(t *testing.T) {
	for _, protocol := range []string{"arp-listen", "dhcp", "lldp"} {
		_, err := Parse([]byte("protocols:\n  " + protocol + ":\n    enabled: true"))
		want := "the " + protocol + " protocol is enabled, and this system can't run it: it needs Linux"
		if linux && err != nil || !linux && (err == nil || err.Error() != want) {
			t.Errorf("%s enabled on %s: %v", protocol, runtime.GOOS, err)
		}
		if _, err := Parse([]byte("protocols:\n  " + protocol + ":\n    enabled: false")); err != nil {
			t.Errorf("%s disabled: %v", protocol, err)
		}
	}
	if file, err := Parse(nil); err != nil || file.Protocols.ARPListen.Enabled != linux {
		t.Errorf("the ARP heard by default on %s: %v, %v", runtime.GOOS, file.Protocols.ARPListen.Enabled, err)
	}
}

// Load tells the file its errors are of, and one that isn't there.
func TestLoad(t *testing.T) {
	dir := t.TempDir()
	good, bad := filepath.Join(dir, "good.yaml"), filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(good, []byte("ipv4:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("ipv4:\n  enable: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if file, err := Load(good); err != nil || !file.IPv4.Enabled {
		t.Errorf("%+v, %v", file.IPv4, err)
	}
	if _, err := Load(bad); err == nil || err.Error() != bad+": ipv4.enable: no such key: ipv4 has enabled, listen, active, lifetime" {
		t.Errorf("a file with an error: %v", err)
	}
	if _, err := Load(filepath.Join(dir, "none.yaml")); !os.IsNotExist(err) {
		t.Errorf("a file that isn't there: %v", err)
	}
}

// A program that has the discovery among its settings reads it with encoding/json, into its own
// defaults: as strictly, and what the document leaves out stays.
func TestDiscoveryAmongOtherSettings(t *testing.T) {
	type settings struct {
		Discovery Discovery `json:"discovery"`
		Tasks     []string  `json:"tasks"`
	}
	s := settings{Discovery: DefaultDiscovery()}
	s.Discovery.Lifetime = Duration(time.Hour)
	if err := json.Unmarshal([]byte(`{"tasks": ["nas"], "discovery": {"ipv4": {"enabled": true}, "protocols": {"mdns": {"enabled": true}}}}`), &s); err != nil {
		t.Fatal(err)
	}
	config := s.Discovery.Config()
	if config.Lifetime != time.Hour || !config.IPv4.Enabled || !config.IPv4.Listen || !config.Protocols.MDNS.Enabled || !config.Protocols.MDNS.Ask || !config.Protocols.NDP.Enabled || len(s.Tasks) != 1 {
		t.Errorf("the discovery of the program: %+v", config)
	}
	err := json.Unmarshal([]byte(`{"discovery": {"ipv4": true, "log_level": "debug", "protocols": {"mdns": {"asks": true}}}}`), &s)
	for _, want := range []string{
		"ipv4: true is not its settings: it is written as ipv4, with enabled: true under it",
		"log_level: no such key: the configuration has lifetime, rediscover, interfaces, exclude_interfaces, ipv6, ipv4, hostnames, protocols, plugins",
		"protocols.mdns.asks: no such option of mdns: it has enabled, ask",
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the errors of the discovery: %v, want %q among them", err, want)
		}
	}
	// The protocols alone too, and a duration and a list on their own.
	var p Protocols
	if err := json.Unmarshal([]byte(`{"dhcp": {"enable": true}}`), &p); err == nil || err.Error() != "protocols.dhcp.enable: no such option of dhcp: it has enabled" {
		t.Errorf("the protocols alone: %v", err)
	}
	var d Duration
	var l StringList
	if err := json.Unmarshal([]byte(`90`), &d); err != nil || d != Duration(90*time.Second) || d.String() != "1m30s" {
		t.Errorf("a duration: %s, %v", d, err)
	}
	if err := json.Unmarshal([]byte(`"eth0, en*"`), &l); err != nil || !slices.Equal(l, StringList{"eth0", "en*"}) {
		t.Errorf("a list: %v, %v", l, err)
	}
	// What it writes is what it reads.
	written, err := json.Marshal(s.Discovery)
	read := Discovery{}
	if err != nil || json.Unmarshal(written, &read) != nil || !reflect.DeepEqual(read.Config(), s.Discovery.Config()) {
		t.Errorf("written and read again: %s, %v", written, err)
	}
}

// The plugins of a file are those the registry has, each field as its type writes it.
func TestPluginWrittenAndRead(t *testing.T) {
	file, err := Parse([]byte("plugins:\n  router:\n    type: mikrotik\n    interval: 60s\n    address: 192.168.88.1\n    username: admin\n    password: \" secret \"\n    use_tls: true"))
	if err != nil {
		t.Fatal(err)
	}
	written, err := json.Marshal(file.Plugins)
	var read map[string]Plugin
	if err != nil || decode("plugins", written, reflect.ValueOf(&read).Elem()) != nil || !reflect.DeepEqual(read, file.Plugins) {
		t.Errorf("written %s, read %+v, %v", written, read, err)
	}
	if file.Plugins["router"].Fields["password"] != " secret " || file.Plugins["router"].Fields["use_tls"] != "true" {
		t.Errorf("the fields: %q", file.Plugins["router"].Fields)
	}
	for _, name := range plugins.Types() {
		if fields, err := plugins.Fields(name); err != nil || len(fields) == 0 {
			t.Errorf("the plugin type %s: %v, %v", name, fields, err)
		}
	}
}
