package main

import (
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

// resetFlags gives the test the flags as a new process has them, none given, and leaves them so:
// the flags are the process's, and what a test gives them would otherwise stay for the next, and
// for its own next run under -count. A flag set can't forget what it was given, so the test has
// one of its own, and the process's, which has those of the tests too, comes back after it.
func resetFlags(t *testing.T) {
	t.Helper()
	original := flag.CommandLine
	define := func() {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
		flag.CommandLine.Usage = func() { flag.Usage() }
		defineFlags()
	}
	define()
	t.Cleanup(func() {
		// The values the flags were given are of the variables, which both sets have.
		define()
		flag.CommandLine = original
	})
}

func TestDeprecatedFlags(t *testing.T) {
	resetFlags(t)
	for old, current := range deprecatedFlags {
		if flag.Lookup(current) == nil {
			t.Errorf("-%s: no flag -%s", old, current)
		}
	}
	if err := flag.CommandLine.Parse([]string{"-ipv4-active=false", "-ipv4-lifetime=3m", "-exclude-interfaces=docker*", "-ipv6_listen=false"}); err != nil {
		t.Fatal(err)
	}
	if ipv4Active || ipv4Lifetime != 3*time.Minute || len(excludeInterfaces) != 1 || excludeInterfaces[0] != "docker*" || ipv6Listen {
		t.Errorf("got ipv4_active %v, ipv4_lifetime %s, exclude_interfaces %v, ipv6_listen %v", ipv4Active, ipv4Lifetime, excludeInterfaces, ipv6Listen)
	}
	if warnings := deprecatedFlagsGiven(); len(warnings) != 3 {
		t.Errorf("warnings: %v", warnings)
	}

	// From before the families: both.
	if err := flag.CommandLine.Parse([]string{"-discovery-active=false", "-discovery-listen"}); err != nil {
		t.Fatal(err)
	}
	if ipv6Active || ipv4Active || !ipv6Listen || !ipv4Listen {
		t.Errorf("-discovery-*: active %v/%v, listen %v/%v", ipv6Active, ipv4Active, ipv6Listen, ipv4Listen)
	}
}

// A deprecated name of one family is given bare as the flag it became, and sets that family alone.
func TestDeprecatedBoolFlagWithoutValue(t *testing.T) {
	resetFlags(t)
	if err := flag.CommandLine.Parse([]string{"-ipv6-listen=false", "-ipv4_listen=false"}); err != nil {
		t.Fatal(err)
	}
	if err := flag.CommandLine.Parse([]string{"-ipv6-listen", "-ipv4"}); err != nil {
		t.Fatal(err)
	}
	if !ipv6Listen || ipv4Listen || !ipv4 {
		t.Errorf("-ipv6-listen -ipv4: ipv6_listen %v, ipv4_listen %v, ipv4 %v, want true, false, true", ipv6Listen, ipv4Listen, ipv4)
	}
}

// The usage is of the flags of now, with their defaults, whatever was given before the error.
func TestUsage(t *testing.T) {
	resetFlags(t)
	if err := flag.CommandLine.Parse([]string{"-ipv6_active=false", "-lifetime=7m"}); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	previous := flag.CommandLine.Output()
	flag.CommandLine.SetOutput(&out)
	defer flag.CommandLine.SetOutput(previous)
	usage()

	for old := range deprecatedFlags {
		if strings.Contains(out.String(), "-"+old+" ") || strings.Contains(out.String(), "-"+old+"\n") {
			t.Errorf("the usage lists the deprecated -%s", old)
		}
	}
	if strings.Contains(out.String(), "Deprecated") {
		t.Error("the usage lists a deprecated flag")
	}
	for _, want := range []string{
		"IPv6: probe the links, by multicast ping, SSDP and WS-Discovery (default true)",
		"How long an address stays after it was last seen (default 4h0m0s)",
		"-plugin value",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the usage lacks %q:\n%s", want, out.String())
		}
	}
}

// flag stops at the first word that is no flag, and a boolean flag takes none: what follows
// "-ipv6 false" was left out without a word.
func TestUnexpectedArgs(t *testing.T) {
	parse := func(args ...string) (*flag.FlagSet, *bool, *bool) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		v6, v4 := fs.Bool("ipv6", true, ""), fs.Bool("ipv4", false, "")
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return fs, v6, v4
	}

	fs, v6, v4 := parse("-ipv6", "false", "-ipv4")
	if !*v6 || *v4 || fs.NArg() != 2 {
		t.Fatalf("-ipv6 false -ipv4: ipv6 %v, ipv4 %v, left %v: flag changed, and so must this test", *v6, *v4, fs.Args())
	}
	if err := unexpectedArgs(fs.Args()); err == nil || !strings.Contains(err.Error(), `"false"`) || !strings.Contains(err.Error(), "-name=false") {
		t.Errorf("-ipv6 false -ipv4: error %v, want one naming \"false\" and the way to write it", err)
	}

	fs, v6, v4 = parse("-ipv6=false", "-ipv4")
	if *v6 || !*v4 {
		t.Errorf("-ipv6=false -ipv4: ipv6 %v, ipv4 %v", *v6, *v4)
	}
	if err := unexpectedArgs(fs.Args()); err != nil {
		t.Errorf("-ipv6=false -ipv4: %v", err)
	}
}

// name=type:params, split at the first = and then the first colon: the params have both, as a
// host key's fingerprint and an IPv6 address.
func TestPluginsFlag(t *testing.T) {
	for _, tt := range []struct {
		value, name, typ, params string
		wantErr                  bool
	}{
		{value: "router=mikrotik:interval=60s,address=192.168.88.1", name: "router", typ: "mikrotik", params: "interval=60s,address=192.168.88.1"},
		{value: "ap=linux:60s,[2001:db8::1]:22,root,host_key=SHA256:abc=", name: "ap", typ: "linux", params: "60s,[2001:db8::1]:22,root,host_key=SHA256:abc="},
		{value: "salón=linux:", name: "salón", typ: "linux", params: ""},
		{value: "mikrotik:60s,192.168.88.1", wantErr: true},
		{value: "=mikrotik:60s", wantErr: true},
		{value: "router=mikrotik", wantErr: true},
		{value: "", wantErr: true},
	} {
		var p pluginsFlag
		err := p.Set(tt.value)
		if tt.wantErr {
			if err == nil {
				t.Errorf("-plugin %q: want an error, got %v", tt.value, p)
			}
			continue
		}
		if err != nil || len(p) != 1 || p[0].Name != tt.name || p[0].Type != tt.typ || p[0].Params != tt.params {
			t.Errorf("-plugin %q: %v, %v, want %s, %s, %s", tt.value, p, err, tt.name, tt.typ, tt.params)
		}
	}

	// Given several times, several plugins.
	var p pluginsFlag
	for _, v := range []string{"a=linux:1", "b=freebsd:2"} {
		if err := p.Set(v); err != nil {
			t.Fatal(err)
		}
	}
	if len(p) != 2 || p[1].Name != "b" {
		t.Errorf("two plugins: %v", p)
	}
}

// The names are off unless asked for, and their lifetime the discovery's unless given.
func TestHostnamesFlags(t *testing.T) {
	resetFlags(t)
	if err := flag.CommandLine.Parse(nil); err != nil || hostnames || hostnamesLifetime != 0 {
		t.Errorf("without the flags: hostnames %v, lifetime %s, %v", hostnames, hostnamesLifetime, err)
	}
	if err := flag.CommandLine.Parse([]string{"-hostnames", "-hostnames_lifetime=30m"}); err != nil || !hostnames || hostnamesLifetime != 30*time.Minute {
		t.Errorf("with the flags: hostnames %v, lifetime %s, %v", hostnames, hostnamesLifetime, err)
	}
}

// The protocols of the names and the DNS servers are lists, given at once or one by one: all
// the protocols, and no server, without them. A server is an address, alone or with its port.
func TestHostnamesProtocolsFlags(t *testing.T) {
	resetFlags(t)
	if err := flag.CommandLine.Parse(nil); err != nil || len(hostnamesProtocols) != 0 || len(hostnamesDNS) != 0 {
		t.Errorf("without the flags: protocols %v, servers %v, %v", hostnamesProtocols, hostnamesDNS, err)
	}
	if err := flag.CommandLine.Parse([]string{"-hostnames_protocols=mdns, dhcp", "-hostnames_protocols", "dns", "-hostnames_dns=192.168.1.1,[fd00::1]:5353", "-hostnames_dns", "10.0.0.1:54"}); err != nil {
		t.Fatal(err)
	}
	if got := hostnamesProtocols.String(); got != "mdns,dhcp,dns" {
		t.Errorf("protocols: %s", got)
	}
	if got := hostnamesDNS.String(); got != "192.168.1.1:53,[fd00::1]:5353,10.0.0.1:54" {
		t.Errorf("servers: %s", got)
	}
	for _, server := range []string{"router.lan", "192.168.1.1:0", "192.168.1.1,nonsense"} {
		var servers serversFlag
		if err := servers.Set(server); err == nil {
			t.Errorf("-hostnames_dns=%s: read as %v", server, servers)
		}
	}
	// The usage names the protocols there are.
	if usage := flag.Lookup("hostnames_protocols").Usage; !strings.Contains(usage, "mdns, dns, netbios, llmnr, wsd, ssdp, dhcp, lldp") {
		t.Errorf("the usage of -hostnames_protocols: %s", usage)
	}
}
