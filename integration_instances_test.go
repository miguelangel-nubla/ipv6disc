//go:build linux && integration

package ipv6disc

// Several instances at once, over real links: two on one machine, as two workers of a process, as
// two processes and as two commands, and two on two machines of one link, each hearing the other's
// probes. An instance that isn't in the test's own process is the test binary again, TestInstance,
// which the test tells what to solicit and asks what it knows.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
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

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	instanceEnv  = "IPV6DISC_TEST_INSTANCE"
	respondEnv   = "IPV6DISC_TEST_RESPOND"
	reportPrefix = "REPORT "
)

// report is what an instance knows and did, as the test asks of one in its process or another's.
type report struct {
	// The addresses of each MAC.
	Hosts map[string][]reportAddr
	// The packets each protocol sent and took, over the interfaces: ndp, ping, ssdp, wsd, arp,
	// which only hears, and those of the naming layer, as mdns.
	Sent, Received map[string]uint64
	// The names of each MAC.
	Names map[string][]reportName
}

type reportName struct {
	Name    string
	Sources []string
	// How long it stays yet.
	Remaining time.Duration
}

// named tells whether mac has that name.
func (r report) named(mac, name string) bool {
	return slices.ContainsFunc(r.Names[mac], func(n reportName) bool { return n.Name == name })
}

type reportAddr struct {
	IP         netip.Addr
	Self       bool
	Interfaces []string
	// How it was seen, each as Record.String says it.
	Records []string
}

func snapshot(w *Worker) report {
	r := report{Hosts: make(map[string][]reportAddr), Sent: make(map[string]uint64), Received: make(map[string]uint64), Names: make(map[string][]reportName)}
	for mac, names := range w.AllNames() {
		for _, n := range names {
			r.Names[mac] = append(r.Names[mac], reportName{n.Name, n.Sources, time.Until(n.Expiration)})
		}
	}
	for mac, collection := range w.GetAll() {
		for _, a := range collection.Get() {
			var records []string
			for _, rec := range a.Records() {
				records = append(records, rec.String())
			}
			r.Hosts[mac] = append(r.Hosts[mac], reportAddr{IP: a.WithZone(""), Self: a.Self(), Interfaces: a.Interfaces(), Records: records})
		}
	}
	w.pcMutex.RLock()
	defer w.pcMutex.RUnlock()
	count := func(name string, stats map[string]any) {
		// What only hears has nothing sent.
		sent, _ := stats["sent"].(uint64)
		r.Sent[name] += sent
		r.Received[name] += stats["recv"].(uint64)
	}
	for _, processes := range w.protocolConns {
		for _, protocol := range processes.Protocols {
			count(protocol.Name, protocol.Worker.Stats())
		}
	}
	for _, processes := range w.nameConns {
		for _, protocol := range processes.Protocols {
			count(protocol.Name, protocol.Worker.Stats())
		}
	}
	for _, protocol := range w.nameGlobal {
		count(protocol.Name, protocol.Worker.Stats())
	}
	for _, listener := range w.arpListeners {
		count("arp", listener.Stats())
	}
	return r
}

// has tells whether ip is known at mac.
func (r report) has(mac string, ip netip.Addr) bool {
	return slices.ContainsFunc(r.Hosts[mac], func(a reportAddr) bool { return a.IP == ip })
}

// self tells whether ip is known, at any MAC, and whether as this machine's.
func (r report) self(ip netip.Addr) (found, self bool) {
	for _, addrs := range r.Hosts {
		for _, a := range addrs {
			if a.IP == ip {
				return true, a.Self
			}
		}
	}
	return false, false
}

// instance is a worker running, here or in another process.
type instance interface {
	report() report
	solicit(target netip.Addr)
	// solicitIPv4 doesn't wait for the answers.
	solicitIPv4(mac string, prefix netip.Prefix)
	// stop waits for it to end, its listeners closed.
	stop()
}

type localInstance struct {
	t      *testing.T
	w      *Worker
	ctx    context.Context
	cancel context.CancelFunc
}

func startLocal(t *testing.T, config Config) instance {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	i := &localInstance{t: t, w: NewWorker(zaptest.NewLogger(t, zaptest.Level(zap.InfoLevel)).Sugar(), config), ctx: ctx, cancel: cancel}
	if err := i.w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return i
}

func (i *localInstance) report() report { return snapshot(i.w) }

func (i *localInstance) solicit(target netip.Addr) {
	if sent, err := i.w.Solicit(target); err != nil || sent == 0 {
		i.t.Logf("solicit: sent %d, %v", sent, err)
	}
}

func (i *localInstance) solicitIPv4(mac string, prefix netip.Prefix) {
	go func() {
		if _, err := i.w.SolicitIPv4(i.ctx, []IPv4Target{{MAC: mustMAC(mac), Prefixes: []netip.Prefix{prefix}}}); err != nil && i.ctx.Err() == nil {
			i.t.Errorf("soliciting %s in %s: %v", mac, prefix, err)
		}
	}()
}

func (i *localInstance) stop() {
	i.t.Helper()
	i.cancel()
	stopped := make(chan struct{})
	go func() { i.w.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		i.t.Fatal("the worker did not stop")
	}
	if prefixes := i.w.Prefixes(); len(prefixes) != 0 {
		i.t.Errorf("still listening on %v after stopping", prefixes)
	}
	i.w.State.Close()
}

// remoteInstance is TestInstance in another process: it reads what to do on its input, a line each,
// and writes its report on its output, again and again.
type remoteInstance struct {
	t      *testing.T
	name   string
	cmd    *exec.Cmd
	input  io.WriteCloser
	log    bytes.Buffer
	exited chan struct{}

	mutex    sync.Mutex
	last     report
	reported chan struct{}
	stopped  bool
}

// startInstance runs a worker in another process, in the namespace given, or without one in the
// test's own. It returns before the worker started: the first report waits for it.
func startInstance(t *testing.T, namespace string, config Config) *remoteInstance {
	t.Helper()
	return startInstanceAs(t, namespace, config)
}

// startInstanceAs is startInstance, of a worker run by the command given, which runs the one
// that follows it: as one that takes a privilege from it.
func startInstanceAs(t *testing.T, namespace string, config Config, by ...string) *remoteInstance {
	t.Helper()
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	args := append(by, os.Args[0], "-test.run=^TestInstance$", "-test.timeout=10m")
	name := "the other process"
	if namespace != "" {
		args = append([]string{"ip", "netns", "exec", namespace}, args...)
		name = namespace
	}
	i := &remoteInstance{t: t, name: name, cmd: exec.Command(args[0], args[1:]...), exited: make(chan struct{}), reported: make(chan struct{})}
	i.cmd.Env = append(os.Environ(), instanceEnv+"="+string(encoded))
	i.cmd.Stderr = &i.log
	if i.input, err = i.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	output, err := i.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := i.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(i.exited)
		first := true
		lines := bufio.NewScanner(output)
		lines.Buffer(nil, 1<<20)
		for lines.Scan() {
			encoded, ok := strings.CutPrefix(lines.Text(), reportPrefix)
			if !ok {
				continue
			}
			var r report
			if err := json.Unmarshal([]byte(encoded), &r); err != nil {
				continue
			}
			i.mutex.Lock()
			i.last = r
			i.mutex.Unlock()
			if first {
				first = false
				close(i.reported)
			}
		}
	}()
	// Without its input, it ends by itself.
	t.Cleanup(func() {
		i.input.Close()
		select {
		case <-i.exited:
		case <-time.After(10 * time.Second):
			i.cmd.Process.Kill()
		}
	})
	return i
}

func (i *remoteInstance) report() report {
	i.t.Helper()
	select {
	case <-i.reported:
	case <-i.exited:
		select {
		case <-i.reported:
		default:
			i.t.Fatalf("the worker in %s ended without a report:\n%s", i.name, i.log.String())
		}
	case <-time.After(30 * time.Second):
		i.t.Fatalf("no report from the worker in %s:\n%s", i.name, i.log.String())
	}
	i.mutex.Lock()
	defer i.mutex.Unlock()
	return i.last
}

func (i *remoteInstance) tell(line string) {
	if _, err := io.WriteString(i.input, line+"\n"); err != nil {
		i.t.Errorf("telling the worker in %s to %s: %v", i.name, line, err)
	}
}

func (i *remoteInstance) solicit(target netip.Addr) { i.tell("solicit " + target.String()) }

func (i *remoteInstance) solicitIPv4(mac string, prefix netip.Prefix) {
	i.tell("solicit4 " + mac + " " + prefix.String())
}

func (i *remoteInstance) stop() {
	i.t.Helper()
	if i.stopped {
		return
	}
	i.stopped = true
	i.tell("stop")
	select {
	case <-i.exited:
	case <-time.After(20 * time.Second):
		i.cmd.Process.Kill()
		i.t.Fatalf("the worker in %s did not stop:\n%s", i.name, i.log.String())
	}
	if err := i.cmd.Wait(); err != nil {
		i.t.Errorf("the worker in %s failed: %v\n%s", i.name, err, i.log.String())
	}
}

// TestInstance is no test, but the worker startInstance runs in another process.
func TestInstance(t *testing.T) {
	encoded := os.Getenv(instanceEnv)
	if encoded == "" {
		t.Skip("run by startInstance, as another process")
	}
	var config Config
	if err := json.Unmarshal([]byte(encoded), &config); err != nil {
		t.Fatal(err)
	}
	logger := zap.New(zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()), zapcore.Lock(os.Stderr), zap.InfoLevel))
	w := NewWorker(logger.Sugar(), config)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}

	var output sync.Mutex
	tell := func() {
		encoded, _ := json.Marshal(snapshot(w))
		output.Lock()
		defer output.Unlock()
		fmt.Printf("%s%s\n", reportPrefix, encoded)
	}
	go func() {
		for ctx.Err() == nil {
			tell()
			time.Sleep(200 * time.Millisecond)
		}
	}()

	// Until told to stop, or the test that started it is gone.
	lines := bufio.NewScanner(os.Stdin)
	for lines.Scan() {
		words := strings.Fields(lines.Text())
		switch {
		case len(words) == 2 && words[0] == "solicit":
			if sent, err := w.Solicit(netip.MustParseAddr(words[1])); err != nil || sent == 0 {
				logger.Sugar().Infof("solicit: sent %d, %v", sent, err)
			}
		case len(words) == 3 && words[0] == "solicit4":
			go func() {
				target := IPv4Target{MAC: mustMAC(words[1]), Prefixes: []netip.Prefix{netip.MustParsePrefix(words[2])}}
				if _, err := w.SolicitIPv4(ctx, []IPv4Target{target}); err != nil && ctx.Err() == nil {
					t.Errorf("soliciting %s: %v", words[1], err)
				}
			}()
		}
		if len(words) == 1 && words[0] == "stop" {
			break
		}
	}
	cancel()
	w.Wait()
	if prefixes := w.Prefixes(); len(prefixes) != 0 {
		t.Errorf("still listening on %v after stopping", prefixes)
	}
	w.State.Close()
}

// One machine with two links to the peer: the one of the other tests, and lan2, which an instance
// can leave out. The peer answers SSDP and WS-Discovery searches too, each to the port that asked.
const (
	peer2MAC = "02:00:00:00:00:22"
)

var (
	worker2Addr = netip.MustParseAddr("fd00:6:4::1")
	peer2Addr   = netip.MustParseAddr("fd00:6:4::2")
	quiet2Addr  = netip.MustParseAddr("fd00:6:1::98")
	lateAddr    = netip.MustParseAddr("fd00:6:1::77")
)

func runOnOneHost(t *testing.T, name string) {
	makeLink(t)
	ip(t, "link", "add", "lan2", "netns", workerNamespace, "type", "veth", "peer", "name", "plan2", "netns", peerNamespace)
	ip(t, "-n", peerNamespace, "link", "set", "plan2", "address", peer2MAC)
	ip(t, "-n", workerNamespace, "link", "set", "lan2", "up")
	ip(t, "-n", peerNamespace, "link", "set", "plan2", "up")
	ip(t, "-n", workerNamespace, "addr", "add", worker2Addr.String()+"/64", "dev", "lan2", "nodad")
	ip(t, "-n", peerNamespace, "addr", "add", peer2Addr.String()+"/64", "dev", "plan2", "nodad")
	// An address the peer gets later is advertised, unsolicited.
	ip(t, "netns", "exec", peerNamespace, "sysctl", "-qw", "net.ipv6.conf.veth-peer.ndisc_notify=1")

	respond := exec.Command("ip", "netns", "exec", peerNamespace, os.Args[0], "-test.run=^TestRespond$")
	respond.Env = append(os.Environ(), respondEnv+"=veth-peer")
	var log bytes.Buffer
	respond.Stdout, respond.Stderr = &log, &log
	if err := respond.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		respond.Process.Kill()
		if err := respond.Wait(); err != nil && !strings.Contains(err.Error(), "killed") {
			t.Errorf("the peer's SSDP and WS-Discovery answers: %v\n%s", err, log.String())
		}
	})

	runInside(t, workerNamespace, name)
}

// TestRespond is no test, but the SSDP and WS-Discovery devices of the peer, which runOnOneHost
// runs in its namespace: whatever comes to their ports, on the group or not, is answered to the
// address and port it came from, as a device answers a search.
func TestRespond(t *testing.T) {
	name := os.Getenv(respondEnv)
	if name == "" {
		t.Skip("run by runOnOneHost, in the peer's namespace")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{1900, 3702} {
		conn, err := net.ListenPacket("udp6", fmt.Sprintf("[::]:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		if err := ipv6.NewPacketConn(conn).JoinGroup(iface, &net.UDPAddr{IP: net.ParseIP("ff02::c")}); err != nil {
			t.Fatal(err)
		}
		go func() {
			buf := make([]byte, 4096)
			for {
				_, from, err := conn.ReadFrom(buf)
				if err != nil {
					return
				}
				conn.WriteTo([]byte("HTTP/1.1 200 OK\r\n\r\n"), from)
			}
		}()
	}
	select {} // until killed
}

// Two workers of one process, as a program that uses the library can have: each with its own
// configuration, on the same interface, at the same time.
func TestLiveTwoWorkersOneProcess(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnOneHost(t, "TestLiveTwoWorkersOneProcess")
		return
	}
	twoOnOneHost(t, startLocal, startLocal)
}

// Two processes on one machine, each with its worker: their sockets are of the same addresses.
func TestLiveTwoWorkersTwoProcesses(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnOneHost(t, "TestLiveTwoWorkersTwoProcesses")
		return
	}
	twoOnOneHost(t, startLocal, func(t *testing.T, config Config) instance { return startInstance(t, "", config) })
}

// twoOnOneHost has two instances discover the same peer over the same interface at the same time,
// each as its configuration says and as if alone: none takes the other's packets, and the one left
// when the other stops goes on.
func twoOnOneHost(t *testing.T, startFirst, startSecond func(*testing.T, Config) instance) {
	every := Family{Enabled: true, Listen: true, Active: true}
	// The second sweeps, and so the machine's neighbor table has the peer's IPv4 address, just
	// confirmed, when the first starts: one that listened for IPv4 would read it there at once.
	second := startSecond(t, Config{Protocols: findingProtocols(), Lifetime: 9 * time.Second, Rediscover: 3 * time.Second,
		IPv6: every, IPv4: Family{Enabled: true, Listen: true, Active: true, Lifetime: 2 * time.Minute}})
	waitFor(t, 30*time.Second, "the peer's IPv4 address, by the second", func() bool { return second.report().has(peerMAC, peerIPv4) })
	// The first takes IPv4 addresses, but only those it solicits, and leaves lan2 out.
	first := startFirst(t, Config{Protocols: findingProtocols(), Lifetime: 6 * time.Second, Rediscover: 2 * time.Second,
		IPv6: every, IPv4: Family{Enabled: true}, ExcludeInterfaces: []string{"lan2"}})
	instances := []struct {
		name string
		instance
	}{{"the first", first}, {"the second", second}}

	for _, i := range instances {
		waitFor(t, 30*time.Second, "the peer's address, by "+i.name, func() bool { return i.report().has(peerMAC, peerAddr) })
		// Its own answers, of each protocol: the peer's devices answer the port that asked, and
		// every ICMPv6 socket of the machine hears what comes to its address.
		for _, protocol := range []string{"ndp", "ping", "ssdp", "wsd"} {
			waitFor(t, 30*time.Second, "an answer to "+i.name+" over "+protocol, func() bool { return i.report().Received[protocol] > 0 })
		}
	}
	waitFor(t, 30*time.Second, "the peer's address on lan2, by the second", func() bool { return second.report().has(peer2MAC, peer2Addr) })

	// Each has the addresses of the interfaces it runs on as this machine's, and no others.
	own := func(i instance, ip netip.Addr) bool {
		found, self := i.report().self(ip)
		return found && self
	}
	waitFor(t, 30*time.Second, "the first's own address", func() bool { return own(first, workerAddr) })
	waitFor(t, 30*time.Second, "the second's own addresses", func() bool {
		return own(second, workerAddr) && own(second, workerIPv4) && own(second, worker2Addr)
	})
	if _, peerSelf := second.report().self(peerAddr); peerSelf {
		t.Error("the peer's address said this machine's")
	}

	// The first as it would be alone: nothing of lan2, and no IPv4 address, though the machine's
	// neighbor table has the peer's since the second swept.
	alone := func() {
		t.Helper()
		for mac, addrs := range first.report().Hosts {
			for _, a := range addrs {
				if a.IP.Is4() || slices.Contains(a.Interfaces, "lan2") || mac == peer2MAC {
					t.Errorf("the first has %s at %s on %v: it leaves lan2 out, and doesn't listen for IPv4", a.IP, mac, a.Interfaces)
				}
			}
		}
	}
	alone()

	// A quiet address: neither finds it, until one solicits it. The answer comes to the machine's
	// address, so both hear it.
	ip(t, "-n", peerNamespace, "addr", "add", quietAddr.String()+"/64", "dev", "veth-peer", "nodad", "preferred_lft", "0")
	time.Sleep(3 * time.Second)
	for _, i := range instances {
		if i.report().has(peerMAC, quietAddr) {
			t.Fatalf("%s found by %s without soliciting it", quietAddr, i.name)
		}
	}
	told := make(map[string]uint64)
	for _, i := range instances {
		waitFor(t, 15*time.Second, "the solicited address, by "+i.name, func() bool {
			told[i.name]++
			i.solicit(quietAddr)
			return i.report().has(peerMAC, quietAddr)
		})
	}
	alone()

	// Both ask the peer for its IPv4 addresses by ARP at once: each reads its answers.
	for _, i := range instances {
		i.solicitIPv4(peerMAC, netip.MustParsePrefix("10.66.1.0/24"))
	}
	waitFor(t, 15*time.Second, "the peer's IPv4 address, solicited by the first", func() bool { return first.report().has(peerMAC, peerIPv4) })

	// Neither solicits but for an answer one of its sockets took, or as told. The answers to the
	// other's pings are among them: they come to the machine's address, which is of both, and each
	// asks their MAC, as of the answers to any ping from the machine. An answer to a solicitation
	// asks nothing more, so it ends there.
	for _, i := range instances {
		r := i.report()
		answers := r.Received["ping"] + r.Received["ssdp"] + r.Received["wsd"]
		t.Logf("%s: sent %v, took %v", i.name, r.Sent, r.Received)
		if r.Sent["ndp"] > answers+told[i.name] {
			t.Errorf("%s sent %d solicitations, for %d answers to probes and %d it was told to send", i.name, r.Sent["ndp"], answers, told[i.name])
		}
	}

	// An address that goes expires on both, each within its own lifetime: neither keeps it for the
	// other's asking, nor for what the other's pings bring. The peer's others stay.
	lifetimes := map[string]time.Duration{"the first": 6 * time.Second, "the second": 9 * time.Second}
	ip(t, "-n", peerNamespace, "addr", "del", quietAddr.String()+"/64", "dev", "veth-peer")
	left := time.Now()
	gone := map[string]bool{}
	waitFor(t, 30*time.Second, "the removed address to expire on both", func() bool {
		for _, i := range instances {
			if !gone[i.name] && !i.report().has(peerMAC, quietAddr) {
				gone[i.name] = true
				took := time.Since(left)
				t.Logf("%s expired on %s %s after it was removed", quietAddr, i.name, took.Round(100*time.Millisecond))
				if took > lifetimes[i.name]+3*time.Second {
					t.Errorf("%s took %s to expire on %s, of a lifetime of %s", quietAddr, took, i.name, lifetimes[i.name])
				}
			}
		}
		return len(gone) == len(instances)
	})
	for _, i := range instances {
		if !i.report().has(peerMAC, peerAddr) {
			t.Errorf("the peer's address expired on %s too, though it answers", i.name)
		}
	}

	// One stops: the other goes on, alone. What it knows stays past its lifetime, as the hosts
	// still answer it, it finds what is new, and what goes expires.
	first.stop()
	stopped := time.Now()
	ip(t, "-n", peerNamespace, "addr", "add", quiet2Addr.String()+"/64", "dev", "veth-peer", "nodad", "preferred_lft", "0")
	waitFor(t, 15*time.Second, "an address solicited after the first stopped", func() bool {
		second.solicit(quiet2Addr)
		return second.report().has(peerMAC, quiet2Addr)
	})
	ip(t, "-n", peerNamespace, "addr", "del", quiet2Addr.String()+"/64", "dev", "veth-peer")
	waitFor(t, 30*time.Second, "the removed address to expire", func() bool { return !second.report().has(peerMAC, quiet2Addr) })
	if wait := 12*time.Second - time.Since(stopped); wait > 0 {
		time.Sleep(wait)
	}
	r := second.report()
	for _, known := range []struct {
		mac string
		ip  netip.Addr
	}{{peerMAC, peerAddr}, {peerMAC, peerIPv4}, {peer2MAC, peer2Addr}} {
		if !r.has(known.mac, known.ip) {
			t.Errorf("%s expired once the first stopped, though its host answers", known.ip)
		}
	}
	if !own(second, workerAddr) || !own(second, workerIPv4) || !own(second, worker2Addr) {
		t.Errorf("the second lost its own addresses once the first stopped: %v", r.Hosts)
	}
	second.stop()
}

// Two commands on one machine, with different flags.
func TestLiveTwoCommands(t *testing.T) {
	// Beside the test binary, wherever it is run from.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(filepath.Dir(self), "ipv6disc")
	if os.Getenv(insideEnv) == "" {
		if _, err := os.Stat(binary); err != nil && os.Geteuid() == 0 {
			t.Fatalf("the command, built beside the test: go build -o ipv6disc ./cmd/ipv6disc: %v", err)
		}
		runOnOneHost(t, "TestLiveTwoCommands")
		return
	}
	iface, err := net.InterfaceByName("veth-worker")
	if err != nil {
		t.Fatal(err)
	}
	workerMAC := iface.HardwareAddr.String()

	// One of IPv6 alone, on every interface; one of both families, without lan2: each by its
	// configuration file.
	first := startCommand(t, binary, "lifetime: 6s\nrediscover: 2s\n")
	second := startCommand(t, binary, "lifetime: 9s\nrediscover: 3s\nexclude_interfaces:\n  - lan2\nipv4:\n  enabled: true\n  lifetime: 2m\n")

	for _, c := range []*command{first, second} {
		waitFor(t, 30*time.Second, "the peer's address, by "+c.name, func() bool { return c.identified(peerMAC, peerAddr) })
		waitFor(t, 30*time.Second, "its own address, by "+c.name, func() bool { return c.identified(workerMAC, workerAddr) })
	}
	waitFor(t, 30*time.Second, "the peer's address on lan2, by the first", func() bool { return first.identified(peer2MAC, peer2Addr) })
	waitFor(t, 30*time.Second, "the peer's IPv4 address, by the second", func() bool { return second.identified(peerMAC, peerIPv4) })
	waitFor(t, 30*time.Second, "its own IPv4 address, by the second", func() bool { return second.identified(workerMAC, workerIPv4) })

	// The first stops, as by docker stop, and the second goes on: it hears what is new.
	first.terminate()
	ip(t, "-n", peerNamespace, "addr", "add", lateAddr.String()+"/64", "dev", "veth-peer")
	waitFor(t, 30*time.Second, "an address advertised after the first stopped", func() bool { return second.identified(peerMAC, lateAddr) })
	second.terminate()

	for _, found := range first.hosts() {
		if found.ip.Is4() {
			t.Errorf("the first, of IPv6 alone, identified %s at %s", found.ip, found.mac)
		}
	}
	for _, found := range second.hosts() {
		if found.mac == peer2MAC || found.ip == peer2Addr || found.ip == worker2Addr {
			t.Errorf("the second, without lan2, identified %s at %s", found.ip, found.mac)
		}
	}
}

// command is the ipv6disc command running, and the hosts its log says it identified.
type command struct {
	t      *testing.T
	name   string
	cmd    *exec.Cmd
	errors bytes.Buffer
	exited chan struct{}

	mutex sync.Mutex
	found []host
	lines []string
}

type host struct {
	mac string
	ip  netip.Addr
}

// startCommand runs the command with the configuration given, in a file, and any flags after it.
func startCommand(t *testing.T, binary, config string, flags ...string) *command {
	t.Helper()
	file := filepath.Join(t.TempDir(), "discovery.yaml")
	if err := os.WriteFile(file, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	flags = append([]string{"--config", file}, flags...)
	c := &command{t: t, name: "ipv6disc with " + strings.Join(strings.Fields(config), " "), cmd: exec.Command(binary, flags...), exited: make(chan struct{})}
	c.start()
	return c
}

// start runs the command, and reads its log.
func (c *command) start() {
	t := c.t
	t.Helper()
	c.cmd.Stderr = &c.errors
	output, err := c.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.cmd.Process.Kill() })
	go func() {
		defer close(c.exited)
		lines := bufio.NewScanner(output)
		for lines.Scan() {
			var entry struct {
				Msg, IP, MAC string
			}
			c.mutex.Lock()
			c.lines = append(c.lines, lines.Text())
			if json.Unmarshal(lines.Bytes(), &entry) == nil && entry.Msg == "host identified" {
				if ip, err := netip.ParseAddr(entry.IP); err == nil {
					c.found = append(c.found, host{entry.MAC, ip})
				}
			}
			c.mutex.Unlock()
		}
	}()
}

func (c *command) hosts() []host {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return slices.Clone(c.found)
}

func (c *command) identified(mac string, ip netip.Addr) bool {
	return slices.Contains(c.hosts(), host{mac, ip})
}

// terminate ends the command as a signal does, and waits for it: it stops by itself, with no error.
func (c *command) terminate() {
	c.t.Helper()
	c.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-c.exited:
	case <-time.After(15 * time.Second):
		c.t.Fatalf("%s did not stop:\n%s", c.name, c.errors.String())
	}
	err := c.cmd.Wait()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if err != nil || c.errors.Len() > 0 {
		c.t.Errorf("%s: %v\n%s\n%s", c.name, err, c.errors.String(), strings.Join(c.lines, "\n"))
	}
}

// Two machines with an instance each, a and b, on one link with a plain host, p, and a quiet one,
// q: a bridge, in a namespace of its own, where the test runs and hears every frame of each.
// q doesn't answer the multicast ping, so only a solicitation finds its IPv6 address, which has the
// solicited-node group of b's: b hears every solicitation for it.
type lanHost struct {
	namespace, mac string
	ipv6, ipv4     netip.Addr
}

const lanNamespace = "ipv6disc-test-lan"

var lan = map[string]lanHost{
	"a": {"ipv6disc-test-a", "02:00:00:00:05:0a", netip.MustParseAddr("fd00:6:5::a"), netip.MustParseAddr("10.66.5.10")},
	"b": {"ipv6disc-test-b", "02:00:00:00:05:0b", netip.MustParseAddr("fd00:6:5::b"), netip.MustParseAddr("10.66.5.11")},
	"p": {"ipv6disc-test-p", "02:00:00:00:05:02", netip.MustParseAddr("fd00:6:5::2"), netip.MustParseAddr("10.66.5.2")},
	"q": {"ipv6disc-test-q", "02:00:00:00:05:99", netip.MustParseAddr("fd00:6:5::1:0:b"), netip.MustParseAddr("10.66.5.9")},
}

// runOnLAN makes the machines and their link, and runs the test in the bridge's namespace.
func runOnLAN(t *testing.T, name string) {
	if os.Geteuid() != 0 {
		t.Skip("needs root, to make network namespaces")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2")
	}
	namespace := func(ns string, disableIPv6 int) {
		exec.Command("ip", "netns", "del", ns).Run() // from a run that didn't clean up
		ip(t, "netns", "add", ns)
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
		for _, setting := range []string{"all", "default"} {
			ip(t, "netns", "exec", ns, "sysctl", "-qw", fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6=%d", setting, disableIPv6))
		}
		ip(t, "-n", ns, "link", "set", "lo", "up")
	}
	// The bridge is no host: it has no address, and only forwards.
	namespace(lanNamespace, 1)
	ip(t, "-n", lanNamespace, "link", "add", "br0", "type", "bridge", "mcast_snooping", "0")
	ip(t, "-n", lanNamespace, "link", "set", "br0", "up")
	for name, h := range lan {
		namespace(h.namespace, 0)
		ip(t, "link", "add", "lan", "netns", h.namespace, "address", h.mac, "type", "veth", "peer", "name", "port-"+name, "netns", lanNamespace)
		ip(t, "-n", lanNamespace, "link", "set", "port-"+name, "master", "br0")
		ip(t, "-n", lanNamespace, "link", "set", "port-"+name, "up")
		ip(t, "-n", h.namespace, "link", "set", "lan", "up")
		ip(t, "-n", h.namespace, "addr", "add", h.ipv6.String()+"/64", "dev", "lan", "nodad")
		ip(t, "-n", h.namespace, "addr", "add", h.ipv4.String()+"/26", "dev", "lan")
	}
	ip(t, "netns", "exec", lan["q"].namespace, "sysctl", "-qw", "net.ipv6.icmp.echo_ignore_multicast=1")

	runInside(t, lanNamespace, name)
}

// Two instances on one link, each on its machine, hear each other's probes. Each still finds the
// hosts as they are, the other's machine as any host, and nothing at a MAC that isn't its own;
// neither probes more for the other's probes; and a host that leaves expires on both.
func TestLiveTwoHosts(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveTwoHosts")
		return
	}
	every := Family{Enabled: true, Listen: true, Active: true}
	// The IPv4 lifetime is longer than the minute between two readings of the neighbor table.
	configs := map[string]Config{
		"a": {Protocols: findingProtocols(), Lifetime: 9 * time.Second, Rediscover: 3 * time.Second, IPv6: every, IPv4: Family{Enabled: true, Listen: true, Active: true, Lifetime: ipv4Lifetime}},
		"b": {Protocols: findingProtocols(), Lifetime: 12 * time.Second, Rediscover: 4 * time.Second, IPv6: every, IPv4: Family{Enabled: true, Listen: true, Active: true, Lifetime: ipv4Lifetime}},
	}
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")

	// What each sends in the same time from its start, alone and then with the other: on the
	// wire, its kernel's packets too, and by its own count.
	const window = 13 * time.Second
	type sent struct {
		wire  map[string]int
		count map[string]uint64
	}
	measure := func(names ...string) (map[string]sent, map[string]*remoteInstance) {
		for _, h := range lan {
			ip(t, "-n", h.namespace, "neigh", "flush", "all")
		}
		time.Sleep(time.Second)
		wire.reset()
		instances := make(map[string]*remoteInstance)
		for _, name := range names {
			instances[name] = startInstance(t, lan[name].namespace, configs[name])
		}
		time.Sleep(window)
		result := make(map[string]sent)
		for _, name := range names {
			result[name] = sent{wire.from(lan[name].mac), instances[name].report().Sent}
		}
		return result, instances
	}
	alone := make(map[string]sent)
	for _, name := range []string{"a", "b"} {
		result, instances := measure(name)
		alone[name] = result[name]
		instances[name].stop()
	}
	together, instances := measure("a", "b")
	a, b := instances["a"], instances["b"]
	started := time.Now().Add(-window)

	// From here on, nothing is ever at a MAC that isn't its own, nor this machine's but its own.
	wrong := watchHosts(t, instances)
	defer wrong.check()

	for _, name := range []string{"a", "b"} {
		rounds := int(window/configs[name].Rediscover) + 1
		t.Logf("%s, %d rounds in %s:\n    alone:    on the wire %v, by its count %v\n    together: on the wire %v, by its count %v",
			name, rounds, window, alone[name].wire, alone[name].count, together[name].wire, together[name].count)
		// A round more or less, by the time of the measure: a probe of each protocol, and a
		// solicitation for each host that answers the ping, the other's machine and p. On the
		// wire, also what the kernel asks to answer the other, and its retries.
		for _, protocol := range []string{"ping", "ssdp", "wsd", "ndp"} {
			slack := uint64(1)
			if protocol == "ndp" {
				slack = 2
			}
			if alone[name].count[protocol] == 0 {
				t.Errorf("%s alone sent nothing over %s", name, protocol)
			}
			if with, without := together[name].count[protocol], alone[name].count[protocol]; with > without+slack || with+slack < without {
				t.Errorf("%s sent %d over %s with the other running, %d alone", name, with, protocol, without)
			}
		}
		for kind, slack := range map[string]int{"multicast ping": 1, "ping": 2, "solicitation": 6, "ssdp": 1, "wsd": 1, "arp": 20} {
			if with, without := together[name].wire[kind], alone[name].wire[kind]; with > without+slack || with+slack < without {
				t.Errorf("%s sent %d of %s on the wire with the other running, %d alone", name, with, kind, without)
			}
		}
		if alone[name].wire["multicast ping"] < rounds-1 || alone[name].wire["solicitation"] < 2*(rounds-1) || alone[name].wire["arp"] == 0 {
			t.Errorf("%s alone, on the wire: %v, in %d rounds", name, alone[name].wire, rounds)
		}
	}

	// Each finds the plain host and the other's machine, with their real MACs, and its own
	// addresses as its own; q's IPv4 address by the sweep, and its IPv6 one not at all.
	for name, i := range instances {
		other := lan[map[string]string{"a": "b", "b": "a"}[name]]
		for _, h := range []lanHost{lan["p"], other} {
			waitFor(t, 30*time.Second, fmt.Sprintf("%s, by %s", h.ipv6, name), func() bool { return i.report().has(h.mac, h.ipv6) })
			waitFor(t, 30*time.Second, fmt.Sprintf("%s, by %s", h.ipv4, name), func() bool { return i.report().has(h.mac, h.ipv4) })
		}
		waitFor(t, 30*time.Second, "q's IPv4 address, by "+name, func() bool { return i.report().has(lan["q"].mac, lan["q"].ipv4) })
		waitFor(t, 30*time.Second, "its own addresses, by "+name, func() bool {
			found6, self6 := i.report().self(lan[name].ipv6)
			found4, self4 := i.report().self(lan[name].ipv4)
			return found6 && self6 && found4 && self4
		})
		if found, _ := i.report().self(lan["q"].ipv6); found {
			t.Fatalf("%s found by %s without soliciting it", lan["q"].ipv6, name)
		}
	}

	// a solicits q: b, of the same solicited-node group, hears it, and it tells b nothing of q.
	heard := b.report().Received["ndp"]
	q := lan["q"]
	told := make(map[string]int)
	waitFor(t, 15*time.Second, "q's address, solicited by a", func() bool {
		told["a"]++
		a.solicit(q.ipv6)
		return a.report().has(q.mac, q.ipv6)
	})
	time.Sleep(time.Second)
	if found, _ := b.report().self(q.ipv6); found {
		t.Errorf("b has %s, which only a solicited: %v", q.ipv6, b.report().Hosts)
	}
	// It did hear it: the link gives each the other's solicitations.
	if took := b.report().Received["ndp"] - heard; took == 0 {
		t.Errorf("b took no NDP message while a solicited q: it doesn't hear a's solicitations")
	} else {
		t.Logf("b took %d NDP messages while a solicited q", took)
	}
	waitFor(t, 15*time.Second, "q's address, solicited by b", func() bool {
		told["b"]++
		b.solicit(q.ipv6)
		return b.report().has(q.mac, q.ipv6)
	})
	// It stays on both past its lifetime, as it answers the ping before it expires.
	time.Sleep(configs["b"].Lifetime + 2*time.Second)
	for name, i := range instances {
		if !i.report().has(q.mac, q.ipv6) {
			t.Errorf("%s expired on %s, though q answers", q.ipv6, name)
		}
	}

	// q leaves: its addresses expire on both, each within its lifetime, and the others stay. a
	// goes on asking for it meanwhile, and b hears every solicitation: what nothing answers keeps
	// it on neither.
	ip(t, "link", "set", "port-q", "down")
	left := time.Now()
	gone := map[string]bool{}
	heard, asked := b.report().Received["ndp"], uint64(0)
	waitFor(t, 30*time.Second, "q's IPv6 address to expire on both", func() bool {
		told["a"]++
		asked++
		a.solicit(q.ipv6)
		for name, i := range instances {
			if !gone[name] && !i.report().has(q.mac, q.ipv6) {
				gone[name] = true
				took := time.Since(left)
				t.Logf("%s expired on %s %s after q left", q.ipv6, name, took.Round(100*time.Millisecond))
				if took > configs[name].Lifetime+3*time.Second {
					t.Errorf("%s took %s to expire on %s, of a lifetime of %s", q.ipv6, took, name, configs[name].Lifetime)
				}
			}
		}
		return len(gone) == len(instances)
	})
	if took := b.report().Received["ndp"] - heard; took < asked/2 {
		t.Errorf("b took %d NDP messages while a solicited q, which had left, %d times: it doesn't hear them", took, asked)
	}
	// Its IPv4 address is of the neighbor table, read every minute, once the kernel has checked
	// what a sweep found: it is gone a lifetime after the kernel last confirmed q, before it left.
	waitFor(t, time.Until(left.Add(ipv4Lifetime+5*time.Second)), "q's IPv4 address to expire on both", func() bool {
		return !a.report().has(q.mac, q.ipv4) && !b.report().has(q.mac, q.ipv4)
	})
	t.Logf("%s expired on both %s after q left, %s after they started", q.ipv4, time.Since(left).Round(time.Second), time.Since(started).Round(time.Second))
	for name, i := range instances {
		r := i.report()
		other := lan[map[string]string{"a": "b", "b": "a"}[name]]
		for _, h := range []lanHost{lan["p"], other} {
			if !r.has(h.mac, h.ipv6) || !r.has(h.mac, h.ipv4) {
				t.Errorf("%s lost %s or %s, of a host that is there: %v", name, h.ipv6, h.ipv4, r.Hosts)
			}
		}
	}

	// Over the whole of it, as in its first seconds: each sent its probes when they were due, and
	// no more, whatever it heard of the other meanwhile, of the pings before an address expires
	// and of a host that left. A solicitation follows each answer to a ping, of the two hosts that
	// answer the multicast one and of an address about to expire, the kernel asks too, and there
	// are those the test told it to send; the sweep is once a minute.
	elapsed := time.Since(started)
	for _, name := range []string{"a", "b"} {
		sent := wire.from(lan[name].mac)
		rounds := int(elapsed/configs[name].Rediscover) + 1
		sweeps := int(elapsed/interfaceCheckInterval) + 1
		t.Logf("%s, %d rounds and %d sweeps in %s: on the wire %v", name, rounds, sweeps, elapsed.Round(time.Second), sent)
		for _, kind := range []string{"multicast ping", "ssdp", "wsd"} {
			if sent[kind] > rounds+1 || sent[kind] < rounds-2 {
				t.Errorf("%s sent %d of %s on the wire in %d rounds", name, sent[kind], kind, rounds)
			}
		}
		if most := 3*rounds + 10 + told[name]; sent["solicitation"] > most {
			t.Errorf("%s sent %d solicitations on the wire in %d rounds: %d at most", name, sent["solicitation"], rounds, most)
		}
		if most := sweeps*alone[name].wire["arp"] + 40; sent["arp"] > most {
			t.Errorf("%s sent %d ARP requests on the wire in %d sweeps: %d at most", name, sent["arp"], sweeps, most)
		}
	}

	// One stops: the other's machine is still a host to it, as its kernel answers.
	a.stop()
	time.Sleep(configs["b"].Lifetime + 2*time.Second)
	if r := b.report(); !r.has(lan["a"].mac, lan["a"].ipv6) || !r.has(lan["p"].mac, lan["p"].ipv6) {
		t.Errorf("b lost a's machine or p once a's instance stopped: %v", r.Hosts)
	}
	b.stop()
}

// ipv4Lifetime is the IPv4 lifetime of TestLiveTwoHosts.
const ipv4Lifetime = 70 * time.Second

// hostWatch looks at what the instances know, again and again, for what is wrong.
type hostWatch struct {
	t     *testing.T
	stop  chan struct{}
	done  chan struct{}
	mutex sync.Mutex
	wrong map[string]bool
}

// watchHosts checks until check that each instance has every address at the MAC of its host, and
// as this machine's those of its own only. A link-local address is of the MAC it is made from.
func watchHosts(t *testing.T, instances map[string]*remoteInstance) *hostWatch {
	owner := make(map[netip.Addr]string)
	for _, h := range lan {
		owner[h.ipv6], owner[h.ipv4] = h.mac, h.mac
		owner[linkLocal(mustMAC(h.mac))] = h.mac
	}
	w := &hostWatch{t: t, stop: make(chan struct{}), done: make(chan struct{}), wrong: make(map[string]bool)}
	go func() {
		defer close(w.done)
		for {
			for name, i := range instances {
				for mac, addrs := range i.report().Hosts {
					for _, a := range addrs {
						w.mutex.Lock()
						if owner[a.IP] != mac {
							w.wrong[fmt.Sprintf("%s has %s at %s: it is of %q", name, a.IP, mac, owner[a.IP])] = true
						}
						if a.Self != (mac == lan[name].mac) {
							w.wrong[fmt.Sprintf("%s has %s at %s as this machine's: %v", name, a.IP, mac, a.Self)] = true
						}
						w.mutex.Unlock()
					}
				}
			}
			select {
			case <-w.stop:
				return
			case <-time.After(250 * time.Millisecond):
			}
		}
	}()
	return w
}

func (w *hostWatch) check() {
	close(w.stop)
	<-w.done
	for _, wrong := range slices.Sorted(maps.Keys(w.wrong)) {
		w.t.Error(wrong)
	}
}

// linkLocal is the link-local address a kernel makes from a MAC, by EUI-64.
func linkLocal(mac net.HardwareAddr) netip.Addr {
	return netip.AddrFrom16([16]byte{0xfe, 0x80, 8: mac[0] ^ 2, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]})
}

// capture counts the probes each MAC sends, of the frames that come in to the bridge's ports.
type capture struct {
	mutex  sync.Mutex
	counts map[string]map[string]int
	// The port each MAC last sent a query to the group of mDNS from, of each family.
	mdnsPorts map[string]map[bool]uint16
	// The UDP port each MAC last sent each kind of probe from.
	ports map[string]map[string]uint16
}

// port returns the UDP port mac last sent a probe of that kind from: zero if it sent none. Not
// reset.
func (c *capture) port(mac, kind string) uint16 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.ports[mac][kind]
}

// mdnsPort returns the port mac last sent a query to the group of mDNS from, over IPv4 or IPv6:
// zero if it sent none. Not reset.
func (c *capture) mdnsPort(mac string, ipv4 bool) uint16 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.mdnsPorts[mac][ipv4]
}

func (c *capture) reset() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.counts = make(map[string]map[string]int)
}

// from returns how many of each kind of probe mac sent since reset.
func (c *capture) from(mac string) map[string]int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return maps.Clone(c.counts[mac])
}

func startCapture(t *testing.T, ports ...string) *capture {
	t.Helper()
	indexes := make(map[int]bool)
	for _, port := range ports {
		iface, err := net.InterfaceByName(port)
		if err != nil {
			t.Fatal(err)
		}
		indexes[iface.Index] = true
	}
	var protocol [2]byte
	binary.BigEndian.PutUint16(protocol[:], unix.ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(binary.NativeEndian.Uint16(protocol[:])))
	if err != nil {
		t.Fatal(err)
	}
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 8<<20)
	// Reads wake up to see whether to stop.
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100_000}); err != nil {
		t.Fatal(err)
	}
	c := &capture{counts: make(map[string]map[string]int), mdnsPorts: make(map[string]map[bool]uint16), ports: make(map[string]map[string]uint16)}
	stop, done := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(stop); <-done; unix.Close(fd) })
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, from, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				continue
			}
			// As it comes in to a port, not as the bridge sends it on to the others.
			ll, ok := from.(*unix.SockaddrLinklayer)
			if !ok || ll.Pkttype == unix.PACKET_OUTGOING || !indexes[ll.Ifindex] {
				continue
			}
			if mac, kind := probeOf(buf[:n]); kind != "" {
				c.mutex.Lock()
				if c.counts[mac] == nil {
					c.counts[mac] = make(map[string]int)
				}
				c.counts[mac][kind]++
				if port := udpSource(buf[:n]); port != 0 {
					if c.ports[mac] == nil {
						c.ports[mac] = make(map[string]uint16)
					}
					c.ports[mac][kind] = port
				}
				if kind == "mdns" {
					// Where the UDP header is: after an IPv4 header without options, or an IPv6 one.
					ipv4 := binary.BigEndian.Uint16(buf[12:14]) == unix.ETH_P_IP
					source := buf[54:56]
					if ipv4 {
						source = buf[34:36]
					}
					if c.mdnsPorts[mac] == nil {
						c.mdnsPorts[mac] = make(map[bool]uint16)
					}
					c.mdnsPorts[mac][ipv4] = binary.BigEndian.Uint16(source)
				}
				c.mutex.Unlock()
			}
		}
	}()
	return c
}

// udpSource is the port a UDP packet in an Ethernet frame was sent from, over IPv4 without
// options or over IPv6 without a header between: zero for anything else.
func udpSource(frame []byte) uint16 {
	switch {
	case len(frame) >= 42 && binary.BigEndian.Uint16(frame[12:14]) == unix.ETH_P_IP && frame[14] == 0x45 && frame[23] == unix.IPPROTO_UDP:
		return binary.BigEndian.Uint16(frame[34:36])
	case len(frame) >= 62 && binary.BigEndian.Uint16(frame[12:14]) == unix.ETH_P_IPV6 && frame[20] == unix.IPPROTO_UDP:
		return binary.BigEndian.Uint16(frame[54:56])
	}
	return 0
}

// udpKinds are the kinds of what is sent to a UDP port, of either family, to a host: to a group,
// mDNS is "mdns", and SSDP and WS-Discovery are counted by probeOf.
var udpKinds = map[uint16]string{9: "discard", 53: "dns", 67: "dhcp", 137: "netbios", 547: "dhcp", 5353: "mdns lookup", 5355: "llmnr"}

// probeOf tells the MAC an Ethernet frame is from, and the kind of probe it is, if any: a
// broadcast ARP request, an echo request, to a group or to a host, a neighbor solicitation to a
// group, as the worker's and the kernel's first are, an SSDP or WS-Discovery search, to the
// group, or a Resolve of the latter, to a host, a packet to the port of mDNS, of either family:
// to the group, "mdns", or to a host, "mdns lookup"; and what the names are asked by: a packet to
// the port of NetBIOS, of LLMNR or of DNS, a TCP segment, of the metadata and the descriptions
// fetched, and "udp" for one to any other port, which nothing here sends.
func probeOf(frame []byte) (mac, kind string) {
	if len(frame) < 14 {
		return "", ""
	}
	mac = net.HardwareAddr(frame[6:12]).String()
	udp := func(multicast bool, port uint16) string {
		switch {
		case port == 5353 && multicast:
			return "mdns"
		case port == 1900:
			return "ssdp"
		case port == 3702 && multicast:
			return "wsd"
		case port == 3702:
			return "wsd resolve"
		}
		if kind, ok := udpKinds[port]; ok {
			return kind
		}
		return "udp"
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case unix.ETH_P_ARP:
		if len(frame) >= 22 && binary.BigEndian.Uint16(frame[20:22]) == 1 && frame[0]&1 == 1 {
			return mac, "arp"
		}
	case 0x88cc:
		return mac, "lldp"
	case unix.ETH_P_IP:
		// A header without options, as all here.
		if len(frame) < 42 || frame[14] != 0x45 {
			return "", ""
		}
		switch frame[23] {
		case unix.IPPROTO_TCP:
			return mac, "tcp"
		case unix.IPPROTO_UDP:
			return mac, udp(frame[30]&0xf0 == 0xe0, binary.BigEndian.Uint16(frame[36:38]))
		}
	case unix.ETH_P_IPV6:
		if len(frame) < 58 {
			return "", ""
		}
		multicast, payload := frame[38] == 0xff, frame[54:]
		switch frame[20] {
		case unix.IPPROTO_ICMPV6:
			switch {
			case payload[0] == 128 && multicast:
				return mac, "multicast ping"
			case payload[0] == 128:
				return mac, "ping"
			case payload[0] == 135 && multicast:
				return mac, "solicitation"
			}
		case unix.IPPROTO_TCP:
			return mac, "tcp"
		case unix.IPPROTO_UDP:
			return mac, udp(multicast, binary.BigEndian.Uint16(payload[2:4]))
		}
	}
	return "", ""
}

// A host that leaves goes from IPv4 a lifetime after the kernel last confirmed it there: not a
// lifetime after the next read of the table, which still has its entry, made stale by the sweep
// before it, for the kernel to check. And the hosts that stay, stay, through every read.
func TestLiveIPv4HostLeaves(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveIPv4HostLeaves")
		return
	}
	const lifetime = 90 * time.Second
	// A rediscovery shorter than the minute between two reads: a sweep before each.
	a := startInstance(t, lan["a"].namespace, Config{Protocols: findingProtocols(), Lifetime: 9 * time.Second, Rediscover: 20 * time.Second,
		IPv6: Family{Enabled: true, Listen: true}, IPv4: Family{Enabled: true, Listen: true, Active: true, Lifetime: lifetime}})
	defer a.stop()
	q := lan["q"]
	staying := []lanHost{lan["p"], lan["b"]}
	waitFor(t, 30*time.Second, "the hosts' IPv4 addresses, after the first sweep", func() bool {
		r := a.report()
		return r.has(q.mac, q.ipv4) && r.has(staying[0].mac, staying[0].ipv4) && r.has(staying[1].mac, staying[1].ipv4)
	})
	found := time.Now()

	// From now on, those that stay are always there.
	stop := make(chan struct{})
	missing := make(chan string, 1)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(250 * time.Millisecond):
			}
			r := a.report()
			for _, h := range staying {
				if !r.has(h.mac, h.ipv4) {
					select {
					case missing <- fmt.Sprintf("%s went, %s after it was found, though it answers", h.ipv4, time.Since(found).Round(time.Second)):
					default:
					}
				}
			}
		}
	}()
	defer close(stop)

	// q leaves just after the read that found it: the next read is most of a minute away.
	time.Sleep(5 * time.Second)
	ip(t, "link", "set", "port-q", "down")
	left := time.Now()

	time.Sleep(lifetime - 30*time.Second)
	if !a.report().has(q.mac, q.ipv4) {
		t.Errorf("%s expired %s after q left, before its lifetime from when it was last confirmed", q.ipv4, time.Since(left).Round(time.Second))
	}
	waitFor(t, time.Until(left.Add(lifetime+5*time.Second)), "q's IPv4 address to expire, a lifetime after q left", func() bool {
		return !a.report().has(q.mac, q.ipv4)
	})
	t.Logf("%s expired %s after q left, with a lifetime of %s", q.ipv4, time.Since(left).Round(100*time.Millisecond), lifetime)

	// Two more reads, each after a sweep, with q gone: the others are still there.
	time.Sleep(2*interfaceCheckInterval + 15*time.Second)
	select {
	case m := <-missing:
		t.Error(m)
	default:
	}
	r := a.report()
	for _, h := range staying {
		if !r.has(h.mac, h.ipv4) {
			t.Errorf("%s is gone at the end", h.ipv4)
		}
	}
	if r.has(q.mac, q.ipv4) {
		t.Errorf("%s is back, though q left", q.ipv4)
	}
}
