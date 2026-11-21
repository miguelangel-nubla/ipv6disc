//go:build linux && integration

package ipv6disc

// The switches of the protocols, over a real link: what each sends, joins and opens when it is
// enabled, and that none of it is there when it is not.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// onlyProtocols is a worker of both families, probing, with the names kept, and no protocol but
// those named, each as its switch alone turns it on: the test says what runs, and doesn't ask the
// configuration, which is what it tests. The options are there whatever is enabled, as they are
// by default, mDNS to ask, and the servers of the reverse DNS given: those of a protocol that is
// off do nothing.
func onlyProtocols(t *testing.T, names ...string) Config {
	t.Helper()
	config := Config{Lifetime: time.Minute, Rediscover: 3 * time.Second, IPv6: probing, IPv4: probing, Hostnames: Hostnames{Enabled: true},
		Protocols: Protocols{MDNS: MDNSProtocol{Ask: true}, SSDP: SSDPProtocol{Names: true}, WSD: WSDProtocol{Names: true},
			DNS: DNSProtocol{Servers: []netip.AddrPort{netip.AddrPortFrom(lan["b"].ipv4, 53)}}}}
	p := &config.Protocols
	for _, name := range names {
		switch name {
		case "ndp":
			p.NDP.Enabled = true
		case "ping":
			p.Ping.Enabled = true
		case "ssdp":
			p.SSDP.Enabled = true
		case "wsd":
			p.WSD.Enabled = true
		case "mdns":
			p.MDNS.Enabled = true
		case "arp":
			p.ARP.Enabled = true
		case "arp-sweep":
			p.ARPSweep.Enabled = true
		case "arp-listen":
			p.ARPListen.Enabled = true
		case "dhcp":
			p.DHCP.Enabled = true
		case "lldp":
			p.LLDP.Enabled = true
		case "netbios":
			p.NetBIOS.Enabled = true
		case "llmnr":
			p.LLMNR.Enabled = true
		case "dns":
			p.DNS.Enabled = true
		default:
			t.Fatalf("no such protocol: %s", name)
		}
	}
	return config
}

// sockets are what a machine has open, and joined, on its link: what the worker in its namespace
// does, as nothing else runs there.
type sockets struct {
	// The raw sockets of ICMPv6, and the UDP ones of both families.
	raw6, udp int
	// The local ports of the UDP sockets.
	ports []string
	// The protocols of the packet sockets, as /proc/net/packet has them: 0806.
	packet []string
	// The groups joined on the interface, of IP and of the link.
	groups string
}

func socketsOf(t *testing.T, namespace string) sockets {
	t.Helper()
	lines := func(file string) [][]string {
		var rows [][]string
		for i, line := range strings.Split(strings.TrimSpace(inNamespace(t, namespace, "cat", file)), "\n") {
			if i > 0 && strings.TrimSpace(line) != "" {
				rows = append(rows, strings.Fields(line))
			}
		}
		return rows
	}
	s := sockets{raw6: len(lines("/proc/net/raw6")), groups: inNamespace(t, namespace, "ip", "maddr", "show", "dev", "lan")}
	for _, file := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		for _, row := range lines(file) {
			s.udp++
			// The local address, and its port in hexadecimal after the colon.
			if _, port, ok := strings.Cut(row[1], ":"); ok {
				s.ports = append(s.ports, port)
			}
		}
	}
	for _, row := range lines("/proc/net/packet") {
		// sk, RefCnt, Type, Proto.
		s.packet = append(s.packet, row[3])
	}
	slices.Sort(s.packet)
	return s
}

// Each protocol alone, with only what it can't run without: what it sends is on the wire, and
// what it joins and opens is there, when it is enabled; and of every protocol that is not,
// nothing is sent, joined nor opened. With none at all the worker sends nothing and has no
// socket, though both families listen and probe.
func TestLiveProtocolSwitches(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveProtocolSwitches")
		return
	}
	a, p, q := lan["a"], lan["p"], lan["q"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")

	// What only one protocol sends, as the capture names it: of NDP, the solicitation the test
	// has the worker send, as nothing else of the row makes it ask.
	sends := map[string]string{
		"ndp": "solicitation", "ping": "multicast ping", "ssdp": "ssdp", "wsd": "wsd", "mdns": "mdns",
		"arp-sweep": "discard", "netbios": "netbios", "llmnr": "llmnr", "dns": "dns",
	}
	// The packet sockets of each that hears frames, by their protocol.
	hears := map[string][]string{"arp-listen": {"0806"}, "dhcp": {"0800", "86dd"}, "lldp": {"88cc"}}
	// And what has a UDP socket while it runs.
	udp := []string{"ssdp", "wsd", "mdns", "netbios", "llmnr", "dns"}
	// Every protocol, in the order the log names them.
	all := []string{"ndp", "ping", "ssdp", "wsd", "mdns", "arp", "arp-sweep", "arp-listen", "dhcp", "lldp", "netbios", "llmnr", "dns"}

	for _, row := range []struct {
		// The protocol of the row, and all that are enabled in it: itself, and what it can't
		// run without.
		name    string
		enabled []string
		// An option of it, and more of the row than its protocols tell.
		option func(*Protocols)
		check  func(t *testing.T, sent map[string]int, open sockets)
	}{
		{name: "none", check: func(t *testing.T, sent map[string]int, open sockets) {
			// Nothing of the worker at all: what is left is the kernel's ARP, for the pings of the test.
			for kind, count := range sent {
				if kind != "arp" && count != 0 {
					t.Errorf("%d of %q sent with no protocol enabled: %v", count, kind, sent)
				}
			}
		}},
		{name: "ndp", enabled: []string{"ndp"}},
		{name: "ping", enabled: []string{"ndp", "ping"}},
		{name: "ssdp", enabled: []string{"ndp", "ssdp"}},
		{name: "wsd", enabled: []string{"ndp", "wsd"}},
		{name: "mdns", enabled: []string{"mdns"}},
		// Told not to ask, mDNS is there, and sends nothing.
		{name: "mdns, not asking", enabled: []string{"mdns"}, option: func(p *Protocols) { p.MDNS.Ask = false }, check: func(t *testing.T, sent map[string]int, open sockets) {
			if sent["mdns"] != 0 || sent["mdns lookup"] != 0 {
				t.Errorf("mDNS told not to ask sent: %v", sent)
			}
			if !strings.Contains(open.groups, "224.0.0.251") || !strings.Contains(open.groups, "ff02::fb") || !slices.Contains(open.ports, "14E9") {
				t.Errorf("mDNS told not to ask doesn't listen: ports %v, groups:\n%s", open.ports, open.groups)
			}
		}},
		{name: "arp", enabled: []string{"arp"}},
		// The whole subnet, a /26 of 61 other addresses, most of which nothing has: the kernel
		// asks for each three times.
		{name: "arp-sweep", enabled: []string{"arp", "arp-sweep"}, check: func(t *testing.T, sent map[string]int, open sockets) {
			if sent["arp"] < 100 {
				t.Errorf("%d ARP requests of a sweep of a /26, want those for its 61 addresses, thrice: %v", sent["arp"], sent)
			}
		}},
		// And only the /28 of the address, of 13 others, when the subnet is larger than the most
		// to sweep whole.
		{name: "arp-sweep, of a /28 at most", enabled: []string{"arp", "arp-sweep"}, option: func(p *Protocols) { p.ARPSweep.MaxPrefix = 28 }, check: func(t *testing.T, sent map[string]int, open sockets) {
			if sent["arp"] > 45 || sent["arp"] < 10 {
				t.Errorf("%d ARP requests of a sweep of the /28 of a /26, want those for its 13 addresses, thrice at most: %v", sent["arp"], sent)
			}
		}},
		{name: "arp-listen", enabled: []string{"arp-listen"}},
		{name: "dhcp", enabled: []string{"dhcp"}},
		{name: "lldp", enabled: []string{"lldp"}},
		// What asks a host its name, of the hosts the ARP heard tells.
		{name: "netbios", enabled: []string{"arp-listen", "netbios"}},
		{name: "llmnr", enabled: []string{"arp-listen", "llmnr"}},
		{name: "dns", enabled: []string{"arp-listen", "dns"}},
	} {
		config := onlyProtocols(t, row.enabled...)
		if row.option != nil {
			row.option(&config.Protocols)
		}
		enabled := row.enabled
		t.Run(strings.NewReplacer(" ", "_", ",", "").Replace(row.name), func(t *testing.T) {
			if err := config.Validate(); err != nil {
				t.Fatal(err)
			}
			for _, h := range lan {
				ip(t, "-n", h.namespace, "neigh", "flush", "all")
			}
			// The kernel of a knows p, before the worker starts: its table has it.
			exec.Command("ip", "netns", "exec", a.namespace, "ping", "-4", "-c1", "-W1", p.ipv4.String()).Run()
			time.Sleep(time.Second)
			wire.reset()
			instance := startInstance(t, a.namespace, config)
			instance.report()
			time.Sleep(2 * time.Second)
			// p asks for a, to all: the ARP of a host, for what hears it.
			ip(t, "-n", p.namespace, "neigh", "flush", "all")
			exec.Command("ip", "netns", "exec", p.namespace, "ping", "-4", "-c1", "-W1", a.ipv4.String()).Run()
			// And the worker is told to solicit an address: only NDP can.
			for range 3 {
				instance.solicit(q.ipv6)
				time.Sleep(time.Second)
			}
			time.Sleep(4 * time.Second)
			if slices.Contains(enabled, "arp-sweep") {
				// The table is read once the kernel has the answers to the sweep, and the
				// worker's own addresses registered with it.
				time.Sleep(8 * time.Second)
			}

			sent, r, open := wire.from(a.mac), instance.report(), socketsOf(t, a.namespace)
			t.Logf("on the wire %v; sent %v, received %v; raw6 %d, udp %d at %v, packet %v", sent, r.Sent, r.Received, open.raw6, open.udp, open.ports, open.packet)
			runs := func(protocol string) bool { return slices.Contains(enabled, protocol) }

			// On the wire.
			for _, protocol := range all {
				kind, ok := sends[protocol]
				if !ok || row.name == "mdns, not asking" && protocol == "mdns" {
					continue
				}
				if runs(protocol) && sent[kind] == 0 {
					t.Errorf("%s is enabled, and nothing of %q is on the wire: %v", protocol, kind, sent)
				}
				if !runs(protocol) && sent[kind] != 0 {
					t.Errorf("%s is disabled, and %d of %q are on the wire: %v", protocol, sent[kind], kind, sent)
				}
			}
			// The raw sockets of ICMPv6: one of NDP, one of the ping.
			raw := 0
			for _, protocol := range []string{"ndp", "ping"} {
				if runs(protocol) {
					raw++
				}
			}
			if open.raw6 != raw {
				t.Errorf("%d raw sockets of IPv6, want %d: one of each of NDP and the ping that is enabled", open.raw6, raw)
			}
			// The packet sockets: those of what hears frames, and no other.
			var packet []string
			for _, protocol := range []string{"arp-listen", "dhcp", "lldp"} {
				if runs(protocol) {
					packet = append(packet, hears[protocol]...)
				}
			}
			slices.Sort(packet)
			if !slices.Equal(open.packet, packet) {
				t.Errorf("packet sockets of the protocols %v, want %v: those of what is enabled", open.packet, packet)
			}
			if heard := r.Received["arp"] > 0; heard != runs("arp-listen") {
				t.Errorf("the ARP of p heard: %v, with arp-listen enabled: %v", heard, runs("arp-listen"))
			}
			// The UDP sockets: none unless a protocol that has one runs.
			if has := slices.ContainsFunc(udp, runs); has != (open.udp > 0) {
				t.Errorf("%d UDP sockets, at the ports %v, with a protocol that has one enabled: %v", open.udp, open.ports, has)
			}
			// The groups: those of mDNS, and LLDP's, of the link.
			for group, joins := range map[string]bool{
				"224.0.0.251": runs("mdns"), "ff02::fb": runs("mdns"),
				"01:80:c2:00:00:0e": runs("lldp"),
				// Never joined: SSDP and WS-Discovery hear the answers to their search, at the
				// port it left from, and LLMNR asks from a port of its own.
				"ff02::c": false, "224.0.0.252": false, "ff02::1:3": false,
			} {
				if joined := strings.Contains(open.groups, " "+group+"\n") || strings.Contains(open.groups, " "+group+" "); joined != joins {
					t.Errorf("the group %s joined: %v, want %v:\n%s", group, joined, joins, open.groups)
				}
			}
			// The port of mDNS, 5353, is its alone.
			if bound := slices.Contains(open.ports, "14E9"); bound != runs("mdns") {
				t.Errorf("the port of mDNS bound: %v, with mdns enabled: %v", bound, runs("mdns"))
			}
			// What the kernel's table had, and what was heard: found by those two alone.
			if found := r.has(p.mac, p.ipv4); found != (runs("arp") || runs("arp-listen")) {
				t.Errorf("p's IPv4 address found: %v, with %v", found, enabled)
			}
			// And the address solicited, by NDP alone.
			if found := r.has(q.mac, q.ipv6); found != runs("ndp") {
				t.Errorf("q's address, solicited, found: %v, with %v", found, enabled)
			}
			// This machine's own addresses are there whatever runs: the families listen.
			if found6, self6 := r.self(a.ipv6); !found6 || !self6 {
				t.Errorf("the worker's own IPv6 address: found %v, its own %v", found6, self6)
			}
			if found4, self4 := r.self(a.ipv4); !found4 || !self4 {
				t.Errorf("the worker's own IPv4 address: found %v, its own %v", found4, self4)
			}
			if row.check != nil {
				row.check(t, sent, open)
			}

			// The log says what runs, once, as the worker starts: in the order of all.
			stopClean(t, instance)
			var named []string
			for _, protocol := range all {
				if runs(protocol) {
					named = append(named, protocol)
				}
			}
			want := "protocols of the local discovery: none"
			if len(named) > 0 {
				want = "protocols of the local discovery: " + strings.Join(named, ", ")
			}
			if log := instance.log.String(); strings.Count(log, want+"\n") != 1 {
				t.Errorf("the log doesn't say %q, once:\n%s", want, log)
			}
		})
	}
}

// mDNS without the names kept finds hosts, and takes no name: a host that only announces itself,
// which nothing probes for, is found by what it says to the group, over both families, and it is
// not asked its name. Without mDNS, the same worker doesn't find it.
func TestLiveMDNSFindsHostsWithoutNames(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveMDNSFindsHostsWithoutNames")
		return
	}
	a, p := lan["a"], lan["p"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	// Listening only, by NDP and the neighbor table: nothing probes, so nothing finds p unless
	// it is heard.
	config := func(mdns bool) Config {
		return Config{Lifetime: time.Minute, Rediscover: 3 * time.Second, IPv6: listening, IPv4: listening,
			Protocols: Protocols{NDP: Protocol{Enabled: true}, ARP: Protocol{Enabled: true}, MDNS: MDNSProtocol{Enabled: mdns, Ask: true}}}
	}
	for _, mdns := range []bool{false, true} {
		for _, h := range lan {
			ip(t, "-n", h.namespace, "neigh", "flush", "all")
		}
		wire.reset()
		instance := startInstance(t, a.namespace, config(mdns))
		instance.report()
		responder := startAvahi(t, p.namespace, "printer-p", true)
		found := func() bool {
			r := instance.report()
			return r.has(p.mac, p.ipv6) && r.has(p.mac, p.ipv4)
		}
		if mdns {
			waitFor(t, 20*time.Second, "p, by what it announces over mDNS", found)
		}
		// Three rediscoveries: time to ask it its name, if it were asked.
		time.Sleep(10 * time.Second)
		r, sent := instance.report(), wire.from(a.mac)
		if !mdns && (r.has(p.mac, p.ipv6) || r.has(p.mac, p.ipv4)) {
			t.Errorf("p found without mDNS, by a worker that probes nothing: %v", r.Hosts)
		}
		if mdns && !found() {
			t.Errorf("p, found by mDNS, is gone: %v", r.Hosts)
		}
		if len(r.Names) != 0 {
			t.Errorf("names taken without the names kept: %+v", r.Names)
		}
		if sent["mdns"] != 0 || sent["mdns lookup"] != 0 {
			t.Errorf("mDNS sent, of families that are not active, and with no name to ask: %v", sent)
		}
		if heard := wire.from(p.mac); heard["mdns"] == 0 {
			t.Errorf("p announced nothing: %v", heard)
		}
		responder.stop()
		stopClean(t, instance)
	}
}

// The command takes its configuration from a file, and nothing of it from flags: the protocols
// of the file are those that run, which its log says, and a flag it had before the file is an
// error, with the usage, and nothing started.
func TestLiveCommandConfigFile(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(filepath.Dir(self), "ipv6disc")
	if os.Getenv(insideEnv) == "" {
		if _, err := os.Stat(binary); err != nil && os.Geteuid() == 0 {
			t.Fatalf("the command, built beside the test: go build -o ipv6disc ./cmd/ipv6disc: %v", err)
		}
		runOnLAN(t, "TestLiveCommandConfigFile")
		return
	}
	a, p := lan["a"], lan["p"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	inA := func(c *exec.Cmd) *exec.Cmd {
		return exec.Command("ip", append([]string{"netns", "exec", a.namespace}, c.Args...)...)
	}
	// refused runs a command that is to end by itself, at once: one that starts instead is
	// killed, and is told by its error.
	refused := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c := inA(exec.Command(binary, args...))
		c = exec.CommandContext(ctx, c.Args[0], c.Args[1:]...)
		c.WaitDelay = time.Second
		out, err := c.CombinedOutput()
		return string(out), err
	}

	// A flag from before: refused, as any there is none of.
	for _, old := range [][]string{{"-ipv4"}, {"-hostnames", "-live"}, {"-plugin", "router=linux:60s"}, {"-rediscover=3s"}} {
		out, err := refused(old...)
		name, _, _ := strings.Cut(old[0], "=")
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(out, "flag provided but not defined: "+name) || !strings.Contains(out, "-config_file") {
			t.Errorf("ipv6disc %s: %v\n%s", strings.Join(old, " "), err, out)
		}
	}
	// A file that can't be: its error, and nothing started.
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("protocols:\n  mdns: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := refused("-config_file", bad); err == nil || !strings.Contains(out, "protocols.mdns: true is not its settings: it is written as mdns, with enabled: true under it") {
		t.Errorf("a file that can't be: %v\n%s", err, out)
	}
	if sent := wire.from(a.mac); len(sent) != 0 {
		t.Errorf("a command that didn't start sent %v", sent)
	}

	// With a file: IPv4 too, and of IPv6 the ping alone, beside NDP.
	file := filepath.Join(t.TempDir(), "discovery.yaml")
	content := fmt.Sprintf("lifetime: 1m\nrediscover: 3s\nipv4:\n  enabled: true\nprotocols:\n  ssdp:\n    enabled: false\n  wsd:\n    enabled: false\n  arp-sweep:\n    enabled: false\nlog_level: info\n# p is %s\n", p.ipv4)
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	wire.reset()
	c := &command{t: t, name: "ipv6disc -config_file", cmd: inA(exec.Command(binary, "-config_file", file)), exited: make(chan struct{})}
	c.start()
	waitFor(t, 30*time.Second, "p's address, by the command", func() bool { return c.identified(p.mac, p.ipv6) })
	time.Sleep(7 * time.Second)
	c.terminate()
	sent := wire.from(a.mac)
	if sent["multicast ping"] == 0 || sent["ssdp"] != 0 || sent["wsd"] != 0 || sent["discard"] != 0 {
		t.Errorf("the command sent %v, want the ping, and neither SSDP, WS-Discovery nor a sweep, which its file turns off", sent)
	}
	c.mutex.Lock()
	log := strings.Join(c.lines, "\n")
	c.mutex.Unlock()
	if want := `"msg":"protocols of the local discovery: ndp, ping, arp, arp-listen"`; !strings.Contains(log, want) {
		t.Errorf("the log of the command doesn't say %s:\n%s", want, log)
	}
}

// The switches of a family are over those of its protocols: with every protocol enabled, a family
// that is off has none of its own on the wire, no socket of them and no group, and those of
// either family run over the other alone; and a family that listens without probing sends no
// probe, of any protocol.
func TestLiveFamilyGates(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveFamilyGates")
		return
	}
	a, p, q := lan["a"], lan["p"], lan["q"]
	all := []string{"ndp", "ping", "ssdp", "wsd", "mdns", "arp", "arp-sweep", "arp-listen", "dhcp", "lldp", "netbios", "llmnr", "dns"}
	// The probes, of each family: what only an active one sends.
	probes6, probes4 := []string{"multicast ping", "ssdp", "wsd"}, []string{"discard"}

	for _, row := range []struct {
		name       string
		ipv6, ipv4 Family
		// The protocols that run, as the log names them, and what of the rest is there.
		runs   string
		raw6   int
		packet []string
		// The probes sent, and those that are not.
		sent, unsent []string
	}{
		{name: "IPv6 off", ipv4: probing,
			runs: "mdns, arp, arp-sweep, arp-listen, dhcp, lldp, netbios, llmnr, dns", raw6: 0,
			packet: []string{"0800", "0806", "86dd", "88cc"},
			sent:   probes4, unsent: append([]string{"solicitation", "ping"}, probes6...)},
		{name: "IPv4 off", ipv6: probing,
			runs: "ndp, ping, ssdp, wsd, mdns, dhcp, lldp, llmnr, dns", raw6: 2,
			packet: []string{"0800", "86dd", "88cc"},
			sent:   probes6, unsent: append([]string{"netbios"}, probes4...)},
		{name: "listening only", ipv6: listening, ipv4: listening,
			runs: "ndp, ping, ssdp, wsd, mdns, arp, arp-listen, dhcp, lldp, netbios, llmnr, dns", raw6: 2,
			packet: []string{"0800", "0806", "86dd", "88cc"},
			unsent: append([]string{"mdns"}, append(probes6, probes4...)...)},
	} {
		t.Run(strings.ReplaceAll(row.name, " ", "_"), func(t *testing.T) {
			config := onlyProtocols(t, all...)
			config.IPv6, config.IPv4 = row.ipv6, row.ipv4
			if err := config.Validate(); err != nil {
				t.Fatal(err)
			}
			// A capture of the row's own: the ports mDNS was sent from are never forgotten.
			wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
			for _, h := range lan {
				ip(t, "-n", h.namespace, "neigh", "flush", "all")
			}
			exec.Command("ip", "netns", "exec", a.namespace, "ping", "-4", "-c1", "-W1", p.ipv4.String()).Run()
			time.Sleep(time.Second)
			wire.reset()
			instance := startInstance(t, a.namespace, config)
			instance.report()
			time.Sleep(2 * time.Second)
			if row.ipv4.Active {
				// The ARP is heard from the reading of the table that follows the first sweep.
				time.Sleep(8 * time.Second)
			}
			ip(t, "-n", p.namespace, "neigh", "flush", "all")
			exec.Command("ip", "netns", "exec", p.namespace, "ping", "-4", "-c1", "-W1", a.ipv4.String()).Run()
			for range 3 {
				instance.solicit(q.ipv6)
				time.Sleep(time.Second)
			}
			time.Sleep(4 * time.Second)

			sent, r, open := wire.from(a.mac), instance.report(), socketsOf(t, a.namespace)
			t.Logf("on the wire %v; sent %v, received %v; raw6 %d, udp %d at %v, packet %v", sent, r.Sent, r.Received, open.raw6, open.udp, open.ports, open.packet)
			for _, kind := range row.sent {
				if sent[kind] == 0 {
					t.Errorf("nothing of %q on the wire, of a family that probes: %v", kind, sent)
				}
			}
			for _, kind := range row.unsent {
				if sent[kind] != 0 {
					t.Errorf("%d of %q on the wire, of a family that is off, or doesn't probe: %v", sent[kind], kind, sent)
				}
			}
			if open.raw6 != row.raw6 {
				t.Errorf("%d raw sockets of IPv6, want %d", open.raw6, row.raw6)
			}
			if !slices.Equal(open.packet, row.packet) {
				t.Errorf("packet sockets of the protocols %v, want %v", open.packet, row.packet)
			}
			// mDNS, of either family: over those that listen, and asking the group of those that probe.
			for group, family := range map[string]Family{"224.0.0.251": row.ipv4, "ff02::fb": row.ipv6} {
				joins := family.Enabled && family.Listen
				if joined := strings.Contains(open.groups, " "+group+"\n") || strings.Contains(open.groups, " "+group+" "); joined != joins {
					t.Errorf("the group %s joined: %v, want %v:\n%s", group, joined, joins, open.groups)
				}
				asks := joins && family.Active
				if asked := wire.mdnsPort(a.mac, group == "224.0.0.251") != 0; asked != asks {
					t.Errorf("the group %s asked: %v, want %v", group, asked, asks)
				}
			}
			// The hosts of a family, and this machine's own addresses of it: only of one that is on.
			if found := r.has(p.mac, p.ipv4); found != row.ipv4.Enabled {
				t.Errorf("p's IPv4 address found: %v, with IPv4 %+v", found, row.ipv4)
			}
			if heard := r.Received["arp"] > 0; heard != row.ipv4.Enabled {
				t.Errorf("the ARP of p heard: %v, with IPv4 %+v", heard, row.ipv4)
			}
			if found := r.has(q.mac, q.ipv6); found != row.ipv6.Enabled {
				t.Errorf("q's address, solicited, found: %v, with IPv6 %+v", found, row.ipv6)
			}
			if found, _ := r.self(a.ipv6); found != row.ipv6.Enabled {
				t.Errorf("the worker's own IPv6 address found: %v, with IPv6 %+v", found, row.ipv6)
			}
			if found, _ := r.self(a.ipv4); found != row.ipv4.Enabled {
				t.Errorf("the worker's own IPv4 address found: %v, with IPv4 %+v", found, row.ipv4)
			}

			stopClean(t, instance)
			if log, want := instance.log.String(), "protocols of the local discovery: "+row.runs+"\n"; strings.Count(log, want) != 1 {
				t.Errorf("the log doesn't say %q, once:\n%s", want, log)
			}
		})
	}
}

// The sweep without the neighbor table, by the ARP heard alone: the hosts that answer it are told
// by their answers, heard from before it is sent, as nothing reads them afterwards. A quiet host
// is found at the first sweep, not at the one a rediscovery later.
func TestLiveSweepHeardWithoutTable(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveSweepHeardWithoutTable")
		return
	}
	a, b, q := lan["a"], lan["b"], lan["q"]
	for _, h := range lan {
		ip(t, "-n", h.namespace, "neigh", "flush", "all")
	}
	config := onlyProtocols(t, "arp-listen", "arp-sweep")
	config.IPv6, config.Hostnames, config.Rediscover = Family{}, Hostnames{}, 10*time.Minute
	config.Protocols.SSDP.Names, config.Protocols.WSD.Names = false, false
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	instance := startInstance(t, a.namespace, config)
	waitFor(t, 15*time.Second, "the hosts that answer the first sweep, by the ARP heard", func() bool {
		r := instance.report()
		return r.has(q.mac, q.ipv4) && r.has(b.mac, b.ipv4)
	})
	if open := socketsOf(t, a.namespace); !slices.Equal(open.packet, []string{"0806"}) {
		t.Errorf("packet sockets of the protocols %v, want that of ARP alone", open.packet)
	}
	stopClean(t, instance)
}

// The command without a configuration, and with one that says nothing, does what it did before
// it had a file: IPv6, by NDP, the ping, SSDP and WS-Discovery, each probe as many times, and
// nothing of IPv4, nor of what tells names. With IPv4 enabled, and no more said, the neighbor
// table, the sweep and the ARP heard too.
func TestLiveCommandDefaults(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(filepath.Dir(self), "ipv6disc")
	if os.Getenv(insideEnv) == "" {
		if _, err := os.Stat(binary); err != nil && os.Geteuid() == 0 {
			t.Fatalf("the command, built beside the test: go build -o ipv6disc ./cmd/ipv6disc: %v", err)
		}
		runOnLAN(t, "TestLiveCommandDefaults")
		return
	}
	a, p := lan["a"], lan["p"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	// What only the names, mDNS and IPv4 send: none of it by default.
	others := []string{"mdns", "mdns lookup", "discard", "netbios", "llmnr", "dns", "dhcp", "tcp", "wsd resolve", "udp", "lldp"}
	probes := []string{"multicast ping", "ssdp", "wsd"}

	run := func(name string, config *string) (map[string]int, *command, string) {
		t.Helper()
		var args []string
		if config != nil {
			file := filepath.Join(t.TempDir(), "discovery.yaml")
			if err := os.WriteFile(file, []byte(*config), 0o600); err != nil {
				t.Fatal(err)
			}
			args = []string{"-config_file", file}
		}
		for _, h := range lan {
			ip(t, "-n", h.namespace, "neigh", "flush", "all")
		}
		time.Sleep(time.Second)
		wire.reset()
		c := &command{t: t, name: "ipv6disc, " + name, exited: make(chan struct{}),
			cmd: exec.Command("ip", append([]string{"netns", "exec", a.namespace, binary}, args...)...)}
		c.start()
		waitFor(t, 30*time.Second, "p's address, by the command, "+name, func() bool { return c.identified(p.mac, p.ipv6) })
		// The sweep, when there is one, and the reading of the table after it.
		time.Sleep(12 * time.Second)
		c.terminate()
		sent := wire.from(a.mac)
		c.mutex.Lock()
		log := strings.Join(c.lines, "\n")
		c.mutex.Unlock()
		t.Logf("%s: on the wire %v", name, sent)
		return sent, c, log
	}

	var first map[string]int
	for _, tt := range []struct {
		name   string
		config *string
	}{{"without a file", nil}, {"with an empty file", new(string)}, {"with a file of comments", ptrTo("# nothing\n---\n")}} {
		sent, c, log := run(tt.name, tt.config)
		for _, kind := range probes {
			if sent[kind] == 0 {
				t.Errorf("%s: nothing of %q on the wire: %v", tt.name, kind, sent)
			}
		}
		for _, kind := range others {
			if sent[kind] != 0 {
				t.Errorf("%s: %d of %q on the wire: %v", tt.name, sent[kind], kind, sent)
			}
		}
		for _, found := range c.hosts() {
			if found.ip.Is4() {
				t.Errorf("%s: identified %s at %s, of IPv4", tt.name, found.ip, found.mac)
			}
		}
		if want := `"msg":"protocols of the local discovery: ndp, ping, ssdp, wsd"`; !strings.Contains(log, want) {
			t.Errorf("%s: the log doesn't say %s:\n%s", tt.name, want, log)
		}
		// One probe of each as it starts, and no other in the 80 minutes before the next.
		if first == nil {
			first = sent
		}
		for _, kind := range probes {
			if sent[kind] != first[kind] {
				t.Errorf("%s: %d of %q, and %d without a file", tt.name, sent[kind], kind, first[kind])
			}
		}
	}

	// IPv4 enabled, and no more: as -ipv4 was.
	sent, c, log := run("with IPv4 enabled", ptrTo("ipv4:\n  enabled: true\n"))
	if sent["discard"] == 0 || sent["arp"] == 0 || !c.identified(p.mac, p.ipv4) {
		t.Errorf("with IPv4 enabled: no sweep, or p not found by it: %v, %v", sent, c.hosts())
	}
	for _, kind := range probes {
		if sent[kind] != first[kind] {
			t.Errorf("with IPv4 enabled: %d of %q, and %d without a file", sent[kind], kind, first[kind])
		}
	}
	for _, kind := range others {
		if kind != "discard" && sent[kind] != 0 {
			t.Errorf("with IPv4 enabled: %d of %q on the wire: %v", sent[kind], kind, sent)
		}
	}
	if want := `"msg":"protocols of the local discovery: ndp, ping, ssdp, wsd, arp, arp-sweep, arp-listen"`; !strings.Contains(log, want) {
		t.Errorf("with IPv4 enabled: the log doesn't say %s:\n%s", want, log)
	}
}

func ptrTo[T any](v T) *T { return &v }
