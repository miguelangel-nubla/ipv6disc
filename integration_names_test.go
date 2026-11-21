//go:build linux && integration

package ipv6disc

// The names of the hosts over a real link, told by a real responder: avahi-daemon, which the
// tests run in the namespaces of the hosts, each with its own name. It needs no D-Bus, but a
// directory for its PID file, which each has in a mount namespace of its own.

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/mdns"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const askEnv = "IPV6DISC_TEST_ASK"

// askName asks the host at target its name, from a namespace, as any host of the link can: by a
// question to its port of mDNS alone. It returns the name as the answer has it, or "" without an
// answer: the test binary again, in that namespace.
func askName(t *testing.T, namespace string, target netip.Addr) string {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", namespace, os.Args[0], "-test.run=^TestAskName$")
	cmd.Env = append(os.Environ(), askEnv+"="+target.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("asking %s its name from %s: %v\n%s", target, namespace, err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if name, ok := strings.CutPrefix(line, "NAME "); ok {
			return name
		}
	}
	return ""
}

// TestAskName is no test, but what askName runs in a namespace.
func TestAskName(t *testing.T) {
	target, err := netip.ParseAddr(os.Getenv(askEnv))
	if err != nil {
		t.Skip("run by askName, in a namespace")
	}
	iface, err := net.InterfaceByName("lan")
	if err != nil {
		t.Fatal(err)
	}
	answers := make(chan string, 1)
	conn, err := mdns.Listen(iface, mdns.Options{IPv4: true, IPv6: true}, mdns.Handler{
		Answered: func(_ netip.Addr, name string) {
			select {
			case answers <- name:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.AskName(target); err != nil {
		t.Fatal(err)
	}
	select {
	case name := <-answers:
		fmt.Printf("NAME %s\n", name)
	case <-time.After(2 * time.Second):
	}
}

const sayEnv = "IPV6DISC_TEST_SAY"

// sayName has the host of a namespace say that name has from, its own address: a response of
// mDNS with that record alone, from its port of mDNS at that address, sent to wherever: the
// group, as a responder announces, or a port of another host. The test binary again, in that
// namespace.
func sayName(t *testing.T, namespace string, from netip.Addr, name string, to netip.AddrPort) {
	t.Helper()
	sayNameOf(t, namespace, from, name, from, to)
}

// sayNameOf is sayName of a record of another address than the sender's, as a proxy sends.
func sayNameOf(t *testing.T, namespace string, from netip.Addr, name string, of netip.Addr, to netip.AddrPort) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", namespace, os.Args[0], "-test.run=^TestSayName$")
	cmd.Env = append(os.Environ(), sayEnv+"="+from.String()+" "+name+" "+to.String()+" "+of.String())
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "SAID") {
		t.Fatalf("saying %s from %s to %s: %v\n%s", name, from, to, err, out)
	}
}

// TestSayName is no test, but what sayName runs in a namespace.
func TestSayName(t *testing.T) {
	fields := strings.Fields(os.Getenv(sayEnv))
	if len(fields) != 4 {
		t.Skip("run by sayName, in a namespace")
	}
	from, to, of := netip.MustParseAddr(fields[0]), netip.MustParseAddrPort(fields[2]), netip.MustParseAddr(fields[3])
	name, err := dnsmessage.NewName(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	// With the ID of what a responder sends unasked: zero.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	header := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 120}
	network := "udp6"
	if from.Is4() {
		network = "udp4"
	}
	if of.Is4() {
		err = b.AResource(header, dnsmessage.AResource{A: of.As4()})
	} else {
		err = b.AAAAResource(header, dnsmessage.AAAAResource{AAAA: of.As16()})
	}
	if err != nil {
		t.Fatal(err)
	}
	message, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(from, mdns.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// As mDNS is sent.
	if from.Is4() {
		p := ipv4.NewPacketConn(conn)
		p.SetTTL(255)
		p.SetMulticastTTL(255)
	} else {
		p := ipv6.NewPacketConn(conn)
		p.SetHopLimit(255)
		p.SetMulticastHopLimit(255)
	}
	if _, err := conn.WriteToUDPAddrPort(message, to); err != nil {
		t.Fatal(err)
	}
	fmt.Println("SAID")
}

// avahi is an avahi-daemon running in a namespace.
type avahi struct {
	t   *testing.T
	cmd *exec.Cmd
	log *lockedBuffer
}

// lockedBuffer is what a process writes while the test reads it.
type lockedBuffer struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.String()
}

// startAvahi runs avahi-daemon in a host's namespace, on its interface, with that host name. With
// service it has a service, which is what makes a responder answer the query for the services of
// the link. It returns once avahi has announced its name.
func startAvahi(t *testing.T, namespace, hostName string, service bool) *avahi {
	t.Helper()
	if _, err := exec.LookPath("avahi-daemon"); err != nil {
		t.Skip("needs avahi-daemon")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "avahi-daemon.conf")
	if err := os.WriteFile(config, fmt.Appendf(nil, "[server]\nhost-name=%s\nuse-ipv4=yes\nuse-ipv6=yes\nenable-dbus=no\nallow-interfaces=lan\n[publish]\npublish-workstation=no\n", hostName), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"/run/avahi-daemon", "/etc/avahi/services"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Its PID file and its services are its own: every avahi of the machine has them at the
	// same paths.
	script := "mount -t tmpfs tmpfs /run/avahi-daemon && chown avahi:avahi /run/avahi-daemon && mount -t tmpfs tmpfs /etc/avahi/services"
	if service {
		script += ` && printf '<service-group><name>test</name><service><type>_ipv6disc-test._tcp</type><port>9</port></service></service-group>' > /etc/avahi/services/test.service`
	}
	script += " && exec avahi-daemon -f " + config + " --debug"
	a := &avahi{t: t, cmd: exec.Command("ip", "netns", "exec", namespace, "unshare", "-m", "sh", "-c", script), log: &lockedBuffer{}}
	a.cmd.Stdout, a.cmd.Stderr = a.log, a.log
	if err := a.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.stop)
	// Its records are its own once it probed for them, and announced them.
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(a.log.String(), "Server startup complete. Host name is "+hostName+".local") {
		if time.Now().After(deadline) {
			t.Fatalf("avahi-daemon in %s did not start:\n%s", namespace, a.log.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	return a
}

// stop ends it, as a host that shuts down: it says goodbye.
func (a *avahi) stop() {
	if a.cmd.ProcessState != nil {
		return
	}
	a.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { a.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		a.cmd.Process.Kill()
		<-done
	}
}

// namesConfig is a worker that learns names by mDNS, which is asked too, over the families given,
// with short lifetimes: beside the protocols that find hosts by default.
func namesConfig(ipv6, ipv4 Family) Config {
	return namesBy(ipv6, ipv4, NameMDNS)
}

const namesLifetime = 20 * time.Second

var (
	probing   = Family{Enabled: true, Listen: true, Active: true}
	listening = Family{Enabled: true, Listen: true}
)

// A host found by another protocol, which announced its name long before and says nothing of
// itself now, is named by asking it: the reverse name of its address, over IPv6 alone and over
// IPv4 alone. The query for the services goes to the group at every rediscovery, and is counted:
// a host that answers no ping is found by its answer to it alone, and then named the same. A
// host that has no responder is asked its name once in a rediscovery at most, and has none.
func TestLiveNamesAsked(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveNamesAsked")
		return
	}
	a, b, p, q := lan["a"], lan["b"], lan["p"], lan["q"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	startAvahi(t, p.namespace, "printer-p", true)
	// q answers no multicast ping, and sends nothing of itself: over IPv6, only its answer to
	// the query for the services tells it is there.
	startAvahi(t, q.namespace, "quiet-q", true)
	// Until their announcements are over, the last of which comes seconds after the others:
	// nothing more comes from them unasked.
	time.Sleep(10 * time.Second)

	for family, config := range map[string]Config{
		"IPv6": namesConfig(probing, Family{}),
		"IPv4": namesConfig(Family{}, probing),
	} {
		wire.reset()
		instance := startInstance(t, a.namespace, config)
		started := time.Now()
		waitFor(t, 30*time.Second, "the name of p, asked over "+family, func() bool { return instance.report().named(p.mac, "printer-p") })
		waitFor(t, 30*time.Second, "q found by its answer to the query for the services, and named, over "+family, func() bool {
			r := instance.report()
			return r.named(q.mac, "quiet-q") && (family == "IPv4" && r.has(q.mac, q.ipv4) || family == "IPv6" && r.has(q.mac, q.ipv6))
		})
		r := instance.report()
		if n := r.Names[p.mac]; len(n) != 1 || !slices.Equal(n[0].Sources, []string{"mdns"}) {
			t.Errorf("%s: the names of p: %+v", family, n)
		}
		if family == "IPv6" && !r.has(p.mac, p.ipv6) || family == "IPv4" && !r.has(p.mac, p.ipv4) {
			t.Errorf("%s: p's address isn't known: %+v", family, r.Hosts[p.mac])
		}

		// Three rediscoveries more: b, which has no responder, is asked in each, and not more.
		time.Sleep(10 * time.Second)
		elapsed := time.Since(started)
		r = instance.report()
		// What the worker counts is what the wire has of it: at a time it sends nothing.
		var sent map[string]int
		for range 10 {
			sent = wire.from(a.mac)
			time.Sleep(300 * time.Millisecond)
			r = instance.report()
			if after := wire.from(a.mac); after["mdns"] == sent["mdns"] && after["mdns lookup"] == sent["mdns lookup"] {
				break
			}
		}
		rediscoveries := int(elapsed/config.Rediscover) + 2
		if sent["mdns"] < 2 || sent["mdns"] > rediscoveries {
			t.Errorf("%s: %d queries to the group in %s, want one in each rediscovery of %s", family, sent["mdns"], elapsed.Round(time.Second), config.Rediscover)
		}
		// To p and to q, which answered, once, or twice if the first went where they don't, and
		// once more when their name was about to expire; and to b once in each rediscovery, which
		// doesn't.
		if sent["mdns lookup"] < 4 || sent["mdns lookup"] > 6+rediscoveries {
			t.Errorf("%s: %d questions to a host in %s, want one to each of p and q, and one to b in each rediscovery", family, sent["mdns lookup"], elapsed.Round(time.Second))
		}
		if r.Sent["mdns"] != uint64(sent["mdns"]+sent["mdns lookup"]) || r.Received["mdns"] == 0 {
			t.Errorf("%s: the worker counts %d sent and %d taken, the wire has %d from it", family, r.Sent["mdns"], r.Received["mdns"], sent["mdns"]+sent["mdns lookup"])
		}
		if len(r.Hosts[b.mac]) == 0 || len(r.Names[b.mac]) != 0 || len(r.Names[a.mac]) != 0 {
			t.Errorf("%s: b, which has no responder, has the addresses %+v and the names %+v; the worker's machine the names %+v", family, r.Hosts[b.mac], r.Names[b.mac], r.Names[a.mac])
		}
		t.Logf("%s: p named %+v; a sent %v in %s", family, r.Names[p.mac], sent, elapsed.Round(time.Second))
		instance.stop()
	}
}

// A host that starts is found by its mDNS alone, with nothing probed, and named by what it
// announces, over IPv4 and IPv6: its addresses are registered at its MAC by the discovery, which
// is asked for them. Renamed, it has its new name as soon as it announces it, without being
// asked, and loses the old one a names' lifetime after it was last said. Its name then stays,
// asked again before it expires.
func TestLiveNamesAnnounced(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveNamesAnnounced")
		return
	}
	a, p := lan["a"], lan["p"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	instance := startInstance(t, a.namespace, namesConfig(listening, listening))
	defer instance.stop()
	waitFor(t, 30*time.Second, "the worker's own addresses", func() bool {
		found6, _ := instance.report().self(a.ipv6)
		found4, _ := instance.report().self(a.ipv4)
		return found6 && found4
	})
	time.Sleep(2 * time.Second)
	if r := instance.report(); len(r.Hosts[p.mac]) != 0 {
		t.Fatalf("p found before it said anything: %+v", r.Hosts[p.mac])
	}

	first := startAvahi(t, p.namespace, "printer-p", false)
	waitFor(t, 20*time.Second, "p found and named by what it announced", func() bool {
		r := instance.report()
		return r.named(p.mac, "printer-p") && r.has(p.mac, p.ipv6) && r.has(p.mac, p.ipv4)
	})
	if sent := wire.from(a.mac); sent["mdns"] != 0 {
		t.Errorf("%d queries to the group, though nothing probes", sent["mdns"])
	}
	// Its name was last said now: by its announcements, or by its answer.
	time.Sleep(4 * time.Second)

	first.stop()
	wire.reset()
	renamed := time.Now()
	startAvahi(t, p.namespace, "scanner-p", false)
	waitFor(t, 8*time.Second, "the new name of p, as it announced it", func() bool { return instance.report().named(p.mac, "scanner-p") })
	if sent := wire.from(a.mac); sent["mdns lookup"] != 0 {
		t.Errorf("p was asked its name %d times, though it had one that stays: the new one must come from its announcement", sent["mdns lookup"])
	}
	r := instance.report()
	old := slices.IndexFunc(r.Names[p.mac], func(n reportName) bool { return n.Name == "printer-p" })
	if old < 0 {
		t.Fatalf("the old name went with the new one, %s after the host was renamed: %+v", time.Since(renamed).Round(time.Second), r.Names[p.mac])
	}
	// When the old name goes: its lifetime after it was last said, which nothing does now.
	oldLeft := time.Since(renamed) + r.Names[p.mac][old].Remaining

	// The old name goes a lifetime after it was last said, which was before the renaming; the
	// new one is there at every look, never close to its end, through two lifetimes.
	var oldGone time.Duration
	shortest := namesLifetime
	for time.Since(renamed) < 2*namesLifetime+5*time.Second {
		r := instance.report()
		if oldGone == 0 && !r.named(p.mac, "printer-p") {
			oldGone = time.Since(renamed)
		}
		if oldGone != 0 && r.named(p.mac, "printer-p") {
			t.Fatalf("the old name is back, %s after the host was renamed", time.Since(renamed).Round(time.Second))
		}
		i := slices.IndexFunc(r.Names[p.mac], func(n reportName) bool { return n.Name == "scanner-p" })
		if i < 0 {
			t.Fatalf("the new name is gone, %s after the host was renamed, though the host is there", time.Since(renamed).Round(time.Second))
		}
		shortest = min(shortest, r.Names[p.mac][i].Remaining)
		time.Sleep(200 * time.Millisecond)
	}
	if oldGone == 0 || oldGone > oldLeft+2*time.Second || oldGone < oldLeft-2*time.Second || oldLeft > namesLifetime {
		t.Errorf("the old name went %s after the host was renamed, want after %s: the names' lifetime of %s from when it was last said", oldGone.Round(100*time.Millisecond), oldLeft.Round(100*time.Millisecond), namesLifetime)
	}
	if shortest < time.Second {
		t.Errorf("the new name came within %s of expiring: it is asked again before", shortest.Round(10*time.Millisecond))
	}
	sent := wire.from(a.mac)
	if sent["mdns lookup"] == 0 {
		t.Error("p was never asked its name again, in two lifetimes of it")
	}
	t.Logf("the old name went after %s; the new one always had %s left at least; a sent %v", oldGone.Round(100*time.Millisecond), shortest.Round(100*time.Millisecond), sent)

	// The name that expired was taken out of the state, and told: not only left out of what it
	// gives.
	instance.stop()
	if log := instance.log.String(); !strings.Contains(log, `host name expired	{"name": "printer-p", "mac": "`+p.mac+`"}`) || strings.Contains(log, `host name expired	{"name": "scanner-p"`) {
		t.Errorf("the log of the worker has no expiration of the old name alone:\n%s", log)
	}
}

// With mDNS off: beside a responder that announces itself and answers, a worker that probes over
// both families sends nothing to the port of mDNS, joins no group of it, and has no name.
func TestLiveNamesOff(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveNamesOff")
		return
	}
	a, p := lan["a"], lan["p"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	// The protocols that find hosts, and none of the names.
	config := namesBy(probing, probing)
	instance := startInstance(t, a.namespace, config)
	defer instance.stop()
	startAvahi(t, p.namespace, "printer-p", true)
	waitFor(t, 30*time.Second, "p's addresses", func() bool {
		r := instance.report()
		return r.has(p.mac, p.ipv6) && r.has(p.mac, p.ipv4)
	})
	// Four rediscoveries.
	time.Sleep(12 * time.Second)

	r := instance.report()
	if len(r.Names) != 0 {
		t.Errorf("names without asking for them: %+v", r.Names)
	}
	sent := wire.from(a.mac)
	if sent["mdns"] != 0 || sent["mdns lookup"] != 0 || r.Sent["mdns"] != 0 {
		t.Errorf("sent to the port of mDNS with the protocols of names off: %v", sent)
	}
	if sent["multicast ping"] == 0 {
		t.Errorf("the capture saw no probe of the worker at all: %v", sent)
	}
	// The responder was there to hear.
	if heard := wire.from(p.mac); heard["mdns"] == 0 {
		t.Errorf("p announced nothing: %v", heard)
	}
	groups, err := exec.Command("ip", "netns", "exec", a.namespace, "ip", "maddr", "show", "dev", "lan").CombinedOutput()
	if err != nil || strings.Contains(string(groups), "224.0.0.251") || strings.Contains(string(groups), "ff02::fb") {
		t.Errorf("the groups of mDNS joined with the protocols of names off: %v\n%s", err, groups)
	}
}

// A worker beside the responder of its own machine, which has the port of mDNS, shares it:
// whichever started first, both listen, the worker hears what the hosts of the link announce,
// and the responder still answers.
func TestLiveNamesBesideAResponder(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveNamesBesideAResponder")
		return
	}
	a, b, p := lan["a"], lan["b"], lan["p"]
	// The responder first, on a's machine; the worker first, on b's.
	startAvahi(t, a.namespace, "machine-a", false)
	instances := map[string]*remoteInstance{
		"a": startInstance(t, a.namespace, namesConfig(listening, listening)),
		"b": startInstance(t, b.namespace, namesConfig(listening, listening)),
	}
	for name, instance := range instances {
		defer instance.stop()
		waitFor(t, 30*time.Second, "the own addresses of the worker on "+name, func() bool {
			found6, _ := instance.report().self(lan[name].ipv6)
			found4, _ := instance.report().self(lan[name].ipv4)
			return found6 && found4
		})
	}
	// The worker on b has the port by now.
	time.Sleep(2 * time.Second)
	responderB := startAvahi(t, b.namespace, "machine-b", false)

	// What p announces to the group reaches each worker, beside its machine's responder: only
	// what the group hears names it at once, as nothing probes.
	startAvahi(t, p.namespace, "printer-p", false)
	for name, instance := range instances {
		waitFor(t, 20*time.Second, "p named by the worker on "+name+", beside its machine's responder", func() bool {
			r := instance.report()
			return r.named(p.mac, "printer-p") && r.has(p.mac, p.ipv4)
		})
	}
	// Each worker names the other machine, by its responder.
	waitFor(t, 30*time.Second, "the responders named by the worker of the other machine", func() bool {
		return instances["a"].report().named(b.mac, "machine-b") && instances["b"].report().named(a.mac, "machine-a")
	})
	// And what is sent to a machine's port of mDNS alone is still its responder's, every time:
	// the worker, which has the port too, takes none of it.
	for name, want := range map[string]string{"a": "machine-a.local.", "b": "machine-b.local."} {
		for _, target := range []netip.Addr{lan[name].ipv4, lan[name].ipv6} {
			for i := range 5 {
				if got := askName(t, lan["q"].namespace, target); got != want {
					t.Errorf("the responder of %s, asked its name at %s beside the worker, the time %d: %q, want %q", name, target, i+1, got, want)
				}
			}
		}
	}
	// A machine's own responder doesn't name it: it is no host to ask, nor to hear.
	for name, instance := range instances {
		if names := instance.report().Names[lan[name].mac]; len(names) != 0 {
			t.Errorf("the worker on %s named its own machine: %+v", name, names)
		}
	}
	if log := responderB.log.String(); strings.Contains(log, "failed") || strings.Contains(log, "Failed") {
		t.Errorf("the responder that started after the worker, on b:\n%s", log)
	}
}

// The port a worker asks from is its own, and no group's: anyone can send to it, from anywhere a
// packet reaches the machine, with whatever source. So only what answers a question that waits
// is taken there. A host that learned the port, as every host of the link does by the query for
// the services, and sends its name there unasked, as it could send any name from any address, is
// not named by it; the same message sent to the group, where only the link is heard, names it.
func TestLiveNamesOwnPort(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveNamesOwnPort")
		return
	}
	a, b := lan["a"], lan["b"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	instance := startInstance(t, a.namespace, namesConfig(probing, probing))
	defer instance.stop()
	waitFor(t, 30*time.Second, "b found over both families, and the worker's ports of mDNS seen on the wire", func() bool {
		r := instance.report()
		return r.has(b.mac, b.ipv4) && r.has(b.mac, b.ipv6) && wire.mdnsPort(a.mac, true) != 0 && wire.mdnsPort(a.mac, false) != 0
	})
	ports := map[bool]uint16{true: wire.mdnsPort(a.mac, true), false: wire.mdnsPort(a.mac, false)}
	if ports[true] == mdns.Port || ports[false] == mdns.Port {
		t.Fatalf("the worker asks from the port of mDNS itself: %v", ports)
	}

	// Through two rediscoveries: while a query for the services waits for its answers, and not.
	for range 8 {
		sayName(t, b.namespace, b.ipv4, "unasked-4.local.", netip.AddrPortFrom(a.ipv4, ports[true]))
		sayName(t, b.namespace, b.ipv6, "unasked-6.local.", netip.AddrPortFrom(a.ipv6, ports[false]))
		time.Sleep(700 * time.Millisecond)
	}
	if now := (map[bool]uint16{true: wire.mdnsPort(a.mac, true), false: wire.mdnsPort(a.mac, false)}); now[true] != ports[true] || now[false] != ports[false] {
		t.Fatalf("the worker's ports changed, from %v to %v: what was sent went nowhere", ports, now)
	}
	// The same, to the groups: what a host announces there is heard, so the worker was
	// listening, and b is a host it would name.
	sayName(t, b.namespace, b.ipv4, "announced-4.local.", netip.MustParseAddrPort("224.0.0.251:5353"))
	sayName(t, b.namespace, b.ipv6, "announced-6.local.", netip.MustParseAddrPort("[ff02::fb%lan]:5353"))
	waitFor(t, 10*time.Second, "b named by what it sent to the groups, over each family", func() bool {
		r := instance.report()
		return r.named(b.mac, "announced-4") && r.named(b.mac, "announced-6")
	})
	r := instance.report()
	if r.named(b.mac, "unasked-4") || r.named(b.mac, "unasked-6") || len(r.Names[b.mac]) != 2 {
		t.Errorf("b named by what it sent to the worker's own port, unasked: %+v", r.Names[b.mac])
	}
}
