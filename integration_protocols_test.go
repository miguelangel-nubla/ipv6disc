//go:build linux && integration

package ipv6disc

// The names by the other protocols, and the hosts by what they send, over a real link, told by
// real services where there is one that runs in a namespace: Samba's nmbd for NetBIOS,
// systemd-resolved for LLMNR, dnsmasq as the DNS and DHCP server of a router, udhcpc and dhclient
// as its clients, wsdd2 for WS-Discovery and lldpd for LLDP. Each has its own mounts and host
// name, as each avahi has. Only the SSDP device is the test's own: a search answered and a
// description served as a UPnP device does.

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/miguelangel-nubla/ipv6disc/internal/ptr"
)

// service is a program running in a host's namespace, with mounts and a host name of its own.
type service struct {
	t    *testing.T
	name string
	cmd  *exec.Cmd
	log  *lockedBuffer
}

// startService runs a shell script in a host's namespace, as a service of that host: its last
// command is the service, which stays. Without the program it needs, the test is skipped.
func startService(t *testing.T, namespace, program, script string) *service {
	t.Helper()
	if _, err := exec.LookPath(program); err != nil {
		t.Skipf("needs %s", program)
	}
	s := &service{t: t, name: filepath.Base(program) + " in " + namespace, log: &lockedBuffer{},
		cmd: exec.Command("ip", "netns", "exec", namespace, "unshare", "-m", "-u", "sh", "-c", script)}
	s.cmd.Stdout, s.cmd.Stderr = s.log, s.log
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.stop)
	return s
}

// said waits for the service to have written text.
func (s *service) said(text string, timeout time.Duration) {
	s.t.Helper()
	deadline := time.Now().Add(timeout)
	for !strings.Contains(s.log.String(), text) {
		if time.Now().After(deadline) || s.cmd.ProcessState != nil {
			s.t.Fatalf("%s did not say %q:\n%s", s.name, text, s.log.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (s *service) stop() {
	if s.cmd.ProcessState != nil {
		return
	}
	s.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { s.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		s.cmd.Process.Kill()
		<-done
	}
}

// inNamespace runs a command in a host's namespace, and returns what it wrote.
func inNamespace(t *testing.T, namespace string, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", append([]string{"netns", "exec", namespace}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s in %s: %v\n%s", strings.Join(args, " "), namespace, err, out)
	}
	return string(out)
}

const helperEnv = "IPV6DISC_TEST_HELPER"

// helper runs TestHelper in a host's namespace, the test binary again, with what to do: it
// returns what it wrote. A helper that stays, as a device, is started with startHelper.
func helper(t *testing.T, namespace string, words ...string) string {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", namespace, os.Args[0], "-test.run=^TestHelper$")
	cmd.Env = append(os.Environ(), helperEnv+"="+strings.Join(words, " "))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v in %s: %v\n%s", words, namespace, err, out)
	}
	return string(out)
}

func startHelper(t *testing.T, namespace string, words ...string) *lockedBuffer {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", namespace, os.Args[0], "-test.run=^TestHelper$", "-test.timeout=10m")
	cmd.Env = append(os.Environ(), helperEnv+"="+strings.Join(words, " "))
	log := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(log.String(), "READY") {
		if time.Now().After(deadline) {
			t.Fatalf("%v in %s did not start:\n%s", words, namespace, log.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return log
}

// TestHelper is no test, but what helper runs in a namespace: what a host of the link does that
// no program at hand does for it.
func TestHelper(t *testing.T) {
	words := strings.Fields(os.Getenv(helperEnv))
	if len(words) == 0 {
		t.Skip("run by helper, in a namespace")
	}
	iface, err := net.InterfaceByName("lan")
	if err != nil {
		t.Fatal(err)
	}
	switch words[0] {
	case "netbios-unasked":
		// A node status response nobody asked for, from the port of NetBIOS at an address of
		// this host, to a port of another: from, to, name.
		conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(words[1]), 137)))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		for id := range 16 {
			if _, err := conn.WriteToUDPAddrPort(nodeStatus(uint16(0x1000+id), words[3]), netip.MustParseAddrPort(words[2])); err != nil {
				t.Fatal(err)
			}
		}
	case "llmnr-ask":
		// The name of an address asked of its host over LLMNR, by a question to the host alone
		// or to the group: target, unicast or multicast.
		target := netip.MustParseAddr(words[1])
		question, err := ptr.Query(0x4242, target, false)
		if err != nil {
			t.Fatal(err)
		}
		network, destination := "udp4", &net.UDPAddr{IP: net.ParseIP("224.0.0.252"), Port: 5355}
		if target.Is6() {
			network, destination = "udp6", &net.UDPAddr{IP: net.ParseIP("ff02::1:3"), Port: 5355, Zone: "lan"}
		}
		if words[2] == "unicast" {
			destination = &net.UDPAddr{IP: target.AsSlice(), Port: 5355}
		}
		conn, err := net.ListenUDP(network, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if target.Is4() {
			ipv4.NewPacketConn(conn).SetMulticastInterface(iface)
		} else {
			ipv6.NewPacketConn(conn).SetMulticastInterface(iface)
		}
		if _, err := conn.WriteTo(question, destination); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if answer, err := ptr.Parse(buf[:n]); err == nil && answer.ID == 0x4242 {
				name, _ := answer.Name(target)
				fmt.Printf("NAME %s\n", name)
				return
			}
		}
	case "arp":
		// An ARP request to all, which says the sender is at a MAC and an address: sender MAC,
		// sender address, target address. The frame is from this host's own MAC.
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		packet := make([]byte, 28)
		binary.BigEndian.PutUint16(packet[0:2], 1)
		binary.BigEndian.PutUint16(packet[2:4], 0x0800)
		packet[4], packet[5] = 6, 4
		binary.BigEndian.PutUint16(packet[6:8], 1)
		copy(packet[8:14], mustMAC(words[1]))
		copy(packet[14:18], netip.MustParseAddr(words[2]).AsSlice())
		copy(packet[24:28], netip.MustParseAddr(words[3]).AsSlice())
		var protocol [2]byte
		binary.BigEndian.PutUint16(protocol[:], unix.ETH_P_ARP)
		to := &unix.SockaddrLinklayer{Protocol: binary.NativeEndian.Uint16(protocol[:]), Ifindex: iface.Index, Halen: 6, Addr: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}
		if err := unix.Sendto(fd, packet, 0, to); err != nil {
			t.Fatal(err)
		}
	case "dhcp":
		// A DHCPREQUEST to all, of a client that says it is at a MAC, has a host name, and
		// asks for an address: the client's MAC, the name, the address. The frame is from this
		// host's own MAC.
		message := make([]byte, 240, 300)
		message[0], message[1], message[2] = 1, 1, 6
		copy(message[28:34], mustMAC(words[1]))
		binary.BigEndian.PutUint32(message[236:], 0x63825363)
		message = append(message, 53, 1, 3, 12, byte(len(words[2])))
		message = append(message, words[2]...)
		message = append(message, 50, 4)
		message = append(message, netip.MustParseAddr(words[3]).AsSlice()...)
		message = append(message, 255)
		datagram := binary.BigEndian.AppendUint16(nil, 68)
		datagram = binary.BigEndian.AppendUint16(datagram, 67)
		datagram = binary.BigEndian.AppendUint16(datagram, uint16(8+len(message)))
		// No checksum, as IPv4 lets it be.
		datagram = append(append(datagram, 0, 0), message...)
		header := []byte{0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255}
		binary.BigEndian.PutUint16(header[2:4], uint16(len(header)+len(datagram)))
		binary.BigEndian.PutUint16(header[10:12], ^onesSum(header))
		sendFrame(t, iface, unix.ETH_P_IP, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, append(header, datagram...))
	case "dhcp6":
		// A DHCPv6 SOLICIT to the servers of the link, of a client that says it sends from an
		// address, and has a name: the address, the name. The frame is from this host's own MAC.
		from, servers := netip.MustParseAddr(words[1]).As16(), netip.MustParseAddr("ff02::1:2").As16()
		message := []byte{1, 0x42, 0x42, 0x42, 0, 39, 0, byte(3 + len(words[2])), 1, byte(len(words[2]))}
		message = append(append(message, words[2]...), 0)
		datagram := binary.BigEndian.AppendUint16(nil, 546)
		datagram = binary.BigEndian.AppendUint16(datagram, 547)
		datagram = binary.BigEndian.AppendUint16(datagram, uint16(8+len(message)))
		datagram = append(append(datagram, 0, 0), message...)
		pseudo := slices.Concat(from[:], servers[:], []byte{0, 0, byte(len(datagram) >> 8), byte(len(datagram)), 0, 0, 0, 17}, datagram)
		binary.BigEndian.PutUint16(datagram[6:8], ^onesSum(pseudo))
		header := []byte{0x60, 0, 0, 0, byte(len(datagram) >> 8), byte(len(datagram)), 17, 1}
		header = slices.Concat(header, from[:], servers[:])
		sendFrame(t, iface, unix.ETH_P_IPV6, net.HardwareAddr{0x33, 0x33, 0, 1, 0, 2}, append(header, datagram...))
	case "device":
		// A UPnP device, over IPv6: it answers the searches of SSDP, each to where it came
		// from, with the LOCATION of its description, and serves descriptions over HTTP, at
		// its own address. Its address, the host the LOCATION names, the path, and the
		// friendly name, with _ for each space.
		own, path := netip.MustParseAddr(words[1]), words[3]
		name := strings.ReplaceAll(words[4], "_", " ")
		listener, err := net.Listen("tcp6", netip.AddrPortFrom(own, 49152).String())
		if err != nil {
			t.Fatal(err)
		}
		go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("FETCHED %s by %s\n", r.URL.Path, r.RemoteAddr)
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprintf(w, `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType><friendlyName>%s</friendlyName><manufacturer>ipv6disc</manufacturer><modelName>test</modelName><UDN>uuid:00000000-0000-0000-0000-%012x</UDN><deviceList><device><friendlyName>An embedded device</friendlyName></device></deviceList></device></root>`, name, len(r.URL.Path))
		}))
		conn, err := net.ListenPacket("udp6", "[::]:1900")
		if err != nil {
			t.Fatal(err)
		}
		if err := ipv6.NewPacketConn(conn).JoinGroup(iface, &net.UDPAddr{IP: net.ParseIP("ff02::c")}); err != nil {
			t.Fatal(err)
		}
		fmt.Println("READY")
		location := "http://" + net.JoinHostPort(words[2], "49152") + path
		buf := make([]byte, 4096)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if !strings.HasPrefix(string(buf[:n]), "M-SEARCH * HTTP/1.1\r\n") {
				continue
			}
			// From its own address, as a device answers a search.
			answer, err := net.DialUDP("udp6", &net.UDPAddr{IP: own.AsSlice()}, from.(*net.UDPAddr))
			if err != nil {
				continue
			}
			fmt.Fprintf(answer, "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: %s\r\nSERVER: Linux/6 UPnP/1.0 ipv6disc-test/1\r\nST: upnp:rootdevice\r\nUSN: uuid:00000000-0000-0000-0000-000000000001::upnp:rootdevice\r\n\r\n", location)
			answer.Close()
		}
	default:
		t.Fatalf("unknown helper %q", words)
	}
}

// sendFrame sends a frame of a protocol out of iface, from its own MAC, to the MAC to.
func sendFrame(t *testing.T, iface *net.Interface, protocol uint16, to net.HardwareAddr, payload []byte) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var network [2]byte
	binary.BigEndian.PutUint16(network[:], protocol)
	address := &unix.SockaddrLinklayer{Protocol: binary.NativeEndian.Uint16(network[:]), Ifindex: iface.Index, Halen: 6}
	copy(address.Addr[:], to)
	if err := unix.Sendto(fd, payload, 0, address); err != nil {
		t.Fatal(err)
	}
}

// onesSum is the sum the checksums of the internet are the complement of.
func onesSum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}

// nodeStatus is a NetBIOS node status response, as a node answers a node status request: its
// one name, as a workstation's.
func nodeStatus(id uint16, name string) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = binary.BigEndian.AppendUint16(b, 0x8400)
	b = append(b, 0, 0, 0, 1, 0, 0, 0, 0)
	b = append(b, 0x20, 'C', 'K')
	b = append(b, []byte(strings.Repeat("A", 30))...)
	b = append(b, 0, 0, 0x21, 0, 1, 0, 0, 0, 0)
	b = binary.BigEndian.AppendUint16(b, 1+18+46)
	b = append(b, 1)
	b = append(b, fmt.Appendf(nil, "%-15s", strings.ToUpper(name))...)
	b = append(b, 0x00, 0x04, 0x00)
	return append(b, make([]byte, 46)...)
}

// stopClean stops a worker, and tells what it logged as an error: as it stops, a listener that
// was closed under its read must end without a word.
func stopClean(t *testing.T, instance *remoteInstance) {
	t.Helper()
	instance.stop()
	if log := instance.log.String(); strings.Contains(log, "ERROR") {
		t.Errorf("the worker in %s logged errors:\n%s", instance.name, log)
	}
}

// namesBy is a worker that learns names by those protocols alone, over the families given, with
// short lifetimes: beside the protocols that find hosts by default, each of those is enabled, and
// the names of WS-Discovery and SSDP are those protocols' option.
// findingProtocols are the protocols that find hosts, of DefaultProtocols, and none of the names:
// what a test of them adds to, or of another, leaves alone.
func findingProtocols() Protocols {
	p := DefaultProtocols()
	p.MDNS.Enabled, p.DHCP.Enabled, p.LLDP.Enabled = false, false, false
	p.NetBIOS.Enabled, p.LLMNR.Enabled, p.DNS.Enabled = false, false, false
	p.SSDP.Names, p.WSD.Names = false, false
	return p
}

func namesBy(ipv6, ipv4 Family, protocols ...string) Config {
	config := Config{Protocols: findingProtocols(), Lifetime: time.Minute, Rediscover: 3 * time.Second, IPv6: ipv6, IPv4: ipv4,
		Hostnames: Hostnames{Lifetime: namesLifetime}}
	on := Protocol{Enabled: true}
	for _, protocol := range protocols {
		switch protocol {
		case NameMDNS:
			config.Protocols.MDNS = MDNSProtocol{Enabled: true, Ask: true}
		case NameDNS:
			config.Protocols.DNS.Enabled = true
		case NameNetBIOS:
			config.Protocols.NetBIOS = on
		case NameLLMNR:
			config.Protocols.LLMNR = on
		case NameWSD:
			config.Protocols.WSD.Names = true
		case NameSSDP:
			config.Protocols.SSDP.Names = true
		case NameDHCP:
			config.Protocols.DHCP = on
		case NameLLDP:
			config.Protocols.LLDP = on
		default:
			panic("no such protocol of the names: " + protocol)
		}
	}
	return config
}

// sources are what said the name of a host, when it has that one name.
func (r report) sources(mac, name string) []string {
	if len(r.Names[mac]) != 1 || r.Names[mac][0].Name != name {
		return nil
	}
	return r.Names[mac][0].Sources
}

// A machine that answers NetBIOS, as Windows does and Samba's nmbd, here, is named by asking it:
// a node status request, to it alone, whose answer has its name as a workstation among those of
// its workgroup and its services. A host that doesn't answer is asked once in a rediscovery, and
// one that sends such an answer unasked, to the port the questions come from, is not named.
func TestLiveNamesNetBIOS(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveNamesNetBIOS")
		return
	}
	a, b, p, q := lan["a"], lan["b"], lan["p"], lan["q"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "smb.conf"), fmt.Appendf(nil, "[global]\nnetbios name = WINBOX-P\nworkgroup = TESTGROUP\ninterfaces = lan\nbind interfaces only = yes\nserver role = standalone server\nlock directory = %[1]s\nstate directory = %[1]s\ncache directory = %[1]s\npid directory = %[1]s\nprivate dir = %[1]s\nlog file = %[1]s/log\n", dir), 0o644); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll("/run/samba", 0o755)
	startService(t, p.namespace, "nmbd", "mount -t tmpfs tmpfs /run/samba && exec nmbd -F --no-process-group --debug-stdout -s "+filepath.Join(dir, "smb.conf"))

	config := namesBy(Family{}, probing, NameNetBIOS)
	instance := startInstance(t, a.namespace, config)
	defer instance.stop()
	started := time.Now()
	// nmbd has its name once it registered it on the link, which takes it some seconds.
	waitFor(t, 40*time.Second, "the name of p, asked over NetBIOS", func() bool { return instance.report().named(p.mac, "winbox-p") })
	waitFor(t, 20*time.Second, "b and q found", func() bool {
		r := instance.report()
		return r.has(b.mac, b.ipv4) && r.has(q.mac, q.ipv4)
	})
	port := wire.port(a.mac, "netbios")
	if port == 0 || port == 137 {
		t.Fatalf("the worker asks from port %d", port)
	}
	// q answers what nobody asked, through two rediscoveries: while a question to it waits, and
	// not.
	for range 4 {
		helper(t, q.namespace, "netbios-unasked", q.ipv4.String(), netip.AddrPortFrom(a.ipv4, port).String(), "evil-q")
		time.Sleep(1500 * time.Millisecond)
	}
	time.Sleep(4 * time.Second)
	elapsed := time.Since(started)
	r := instance.report()
	if got := r.sources(p.mac, "winbox-p"); !slices.Equal(got, []string{"netbios"}) {
		t.Errorf("the names of p: %+v", r.Names[p.mac])
	}
	if len(r.Names[q.mac]) != 0 || len(r.Names[b.mac]) != 0 || len(r.Names[a.mac]) != 0 {
		t.Errorf("named by an answer nobody asked for, or by none: q %+v, b %+v, the worker's machine %+v", r.Names[q.mac], r.Names[b.mac], r.Names[a.mac])
	}
	sent := wire.from(a.mac)
	rediscoveries := int(elapsed/config.Rediscover) + 2
	// To p until it answered, and to b and q once in each rediscovery.
	if sent["netbios"] < 3 || sent["netbios"] > 3*rediscoveries {
		t.Errorf("%d questions in %s, want one to each host without a name in each rediscovery of %s", sent["netbios"], elapsed.Round(time.Second), config.Rediscover)
	}
	if r.Sent["netbios"] < uint64(sent["netbios"]) || r.Received["netbios"] == 0 {
		t.Errorf("the worker counts %d sent and %d taken, the wire has %d from it", r.Sent["netbios"], r.Received["netbios"], sent["netbios"])
	}
	if sent["mdns"]+sent["mdns lookup"]+sent["llmnr"]+sent["dns"]+sent["tcp"] != 0 {
		t.Errorf("asked by other protocols than the one asked for: %v", sent)
	}
	t.Logf("p named %+v; a sent %v in %s", r.Names[p.mac], sent, elapsed.Round(time.Second))
}

// A machine that answers LLMNR, as Windows does and systemd-resolved, here, is named by asking
// it the name of its address, over IPv4 and over IPv6. The question goes to the group: the
// responder leaves out the one sent to it alone over UDP, which the test shows first, as any
// host can.
func TestLiveNamesLLMNR(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveNamesLLMNR")
		return
	}
	const resolved = "/usr/lib/systemd/systemd-resolved"
	a, b, p := lan["a"], lan["b"], lan["p"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	os.MkdirAll("/run/systemd", 0o755)
	os.MkdirAll("/etc/systemd", 0o755)
	responder := startService(t, p.namespace, resolved, "mount -t tmpfs tmpfs /run/systemd && mount -t tmpfs tmpfs /etc/systemd && printf '[Resolve]\\nLLMNR=yes\\nMulticastDNS=no\\nDNSStubListener=no\\n' > /etc/systemd/resolved.conf && hostname resolved-p && SYSTEMD_LOG_LEVEL=debug exec "+resolved)
	// Its names are its own once it probed for them.
	responder.said("IN AAAA "+p.ipv6.String()+" successfully probed", 30*time.Second)
	responder.said("IN A "+p.ipv4.String()+" successfully probed", 30*time.Second)

	for _, target := range []netip.Addr{p.ipv4, p.ipv6} {
		if got := helper(t, b.namespace, "llmnr-ask", target.String(), "unicast"); strings.Contains(got, "NAME") {
			t.Errorf("the responder answered a UDP question sent to %s alone, %q: the questions needn't go to the group", target, got)
		}
		if got := helper(t, b.namespace, "llmnr-ask", target.String(), "multicast"); !strings.Contains(got, "NAME resolved-p.") {
			t.Fatalf("the responder, asked the name of %s by the group: %q", target, got)
		}
	}

	for family, config := range map[string]Config{
		"IPv6": namesBy(probing, Family{}, NameLLMNR),
		"IPv4": namesBy(Family{}, probing, NameLLMNR),
	} {
		wire.reset()
		instance := startInstance(t, a.namespace, config)
		started := time.Now()
		waitFor(t, 30*time.Second, "the name of p, asked over "+family, func() bool { return instance.report().named(p.mac, "resolved-p") })
		// By its first answer: over IPv6 that comes from its link-local address, whatever
		// address was asked of, and is still its own. Not by the question of a round after.
		if asked := wire.from(a.mac)["llmnr"]; asked > 3 {
			t.Errorf("%s: p named after %d questions to the hosts, want by the answer to the first to it", family, asked)
		}
		waitFor(t, 20*time.Second, "b found over "+family, func() bool {
			r := instance.report()
			return r.has(b.mac, b.ipv4) || r.has(b.mac, b.ipv6)
		})
		time.Sleep(7 * time.Second)
		elapsed := time.Since(started)
		r := instance.report()
		if got := r.sources(p.mac, "resolved-p"); !slices.Equal(got, []string{"llmnr"}) {
			t.Errorf("%s: the names of p: %+v", family, r.Names[p.mac])
		}
		if len(r.Names[b.mac]) != 0 || len(r.Names[a.mac]) != 0 {
			t.Errorf("%s: b, which has no responder, has the names %+v; the worker's machine %+v", family, r.Names[b.mac], r.Names[a.mac])
		}
		sent := wire.from(a.mac)
		rediscoveries := int(elapsed/config.Rediscover) + 2
		if sent["llmnr"] < 2 || sent["llmnr"] > 4+rediscoveries {
			t.Errorf("%s: %d questions in %s, want one or two to p, and one to b in each rediscovery of %s", family, sent["llmnr"], elapsed.Round(time.Second), config.Rediscover)
		}
		if sent["mdns"]+sent["mdns lookup"]+sent["netbios"]+sent["dns"]+sent["tcp"] != 0 {
			t.Errorf("%s: asked by other protocols than the one asked for: %v", family, sent)
		}
		t.Logf("%s: p named %+v; a sent %v in %s", family, r.Names[p.mac], sent, elapsed.Round(time.Second))
		instance.stop()
	}
	// Nothing of LLMNR is joined: the questions are sent, and their answers come to a port.
	if groups := inNamespace(t, a.namespace, "ip", "maddr", "show", "dev", "lan"); strings.Contains(groups, "224.0.0.252") || strings.Contains(groups, "ff02::1:3") {
		t.Errorf("the groups of LLMNR joined:\n%s", groups)
	}
}

// startDnsmasq runs dnsmasq in a host's namespace, as the router of the link: its DNS server,
// which knows the names it is given and those of its leases, and asks nobody else; and with
// ranges, its DHCP server.
func startDnsmasq(t *testing.T, namespace string, options ...string) *service {
	t.Helper()
	// Its leases where it keeps them, which a system that confines it lets it: each its own.
	os.MkdirAll("/var/lib/misc", 0o755)
	args := append([]string{"mount -t tmpfs tmpfs /var/lib/misc && exec", "dnsmasq", "-k", "--conf-file=/dev/null", "--user=root", "--interface=lan", "--bind-interfaces", "--no-resolv", "--no-hosts",
		"--pid-file=", "--log-facility=-", "--log-dhcp", "--log-queries", "--domain=lan.test", "--local=/lan.test/", "--bogus-priv"}, options...)
	s := startService(t, namespace, "dnsmasq", strings.Join(args, " "))
	s.said("started", 10*time.Second)
	return s
}

// The DNS servers given are asked the name of each address, as the dnsmasq of a router, which
// knows its clients: a host is named by what the PTR record of one of its addresses points to,
// asked at another of them when the first has none. The questions go to those servers alone.
func TestLiveNamesDNS(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveNamesDNS")
		return
	}
	a, b, p, q := lan["a"], lan["b"], lan["p"], lan["q"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	config := namesBy(probing, probing, NameDNS)
	config.Protocols.DNS.Servers = []netip.AddrPort{netip.AddrPortFrom(b.ipv4, 53)}
	instance := startInstance(t, a.namespace, config)
	defer instance.stop()
	// The hosts are there, with all their addresses, and were asked of, before the server is.
	// p was asked of at its IPv6 address, the first the discovery finds, which is the one the
	// server will have no name for: it has to be asked of at the other.
	waitFor(t, 30*time.Second, "p's IPv6 address, and a question of it", func() bool {
		return instance.report().has(p.mac, p.ipv6) && wire.from(a.mac)["dns"] >= 1
	})
	if r := instance.report(); r.has(p.mac, p.ipv4) {
		t.Logf("p's IPv4 address was found as soon as its IPv6 one: which of them was asked of first is not known")
	}
	waitFor(t, 30*time.Second, "the hosts, and a question of each", func() bool {
		r := instance.report()
		return r.has(p.mac, p.ipv4) && r.has(q.mac, q.ipv4) && r.has(b.mac, b.ipv4) && wire.from(a.mac)["dns"] >= 3
	})
	if r := instance.report(); len(r.Names) != 0 {
		t.Fatalf("names before there is a server: %+v", r.Names)
	}

	// p has a name by its IPv4 address alone, and so has q, which has no other.
	router := startDnsmasq(t, b.namespace, "--host-record=printer-p.lan.test,"+p.ipv4.String(), "--host-record=Quiet_Q.lan.test,"+q.ipv4.String())
	wire.reset()
	started := time.Now()
	waitFor(t, 30*time.Second, "the name of q, by its IPv4 address", func() bool { return instance.report().named(q.mac, "quiet-q") })
	waitFor(t, 30*time.Second, "the name of p, by its IPv4 address, asked of in turn with its IPv6 one", func() bool { return instance.report().named(p.mac, "printer-p") })
	time.Sleep(7 * time.Second)
	elapsed := time.Since(started)
	r := instance.report()
	if !slices.Equal(r.sources(p.mac, "printer-p"), []string{"dns"}) || !slices.Equal(r.sources(q.mac, "quiet-q"), []string{"dns"}) {
		t.Errorf("the names of p: %+v; of q: %+v", r.Names[p.mac], r.Names[q.mac])
	}
	// The server has no name for itself, and says so: it is asked again, and has none.
	if len(r.Hosts[b.mac]) == 0 || len(r.Names[b.mac]) != 0 || len(r.Names[a.mac]) != 0 {
		t.Errorf("b has the addresses %+v and the names %+v; the worker's machine the names %+v", r.Hosts[b.mac], r.Names[b.mac], r.Names[a.mac])
	}
	sent := wire.from(a.mac)
	rediscoveries := int(elapsed/config.Rediscover) + 2
	// One of q, one or two of p, and one of b in each rediscovery; one more of each when its
	// name is about to expire.
	if sent["dns"] < 3 || sent["dns"] > 5+rediscoveries {
		t.Errorf("%d questions in %s, want one of q, two of p at most, and one of b in each rediscovery of %s", sent["dns"], elapsed.Round(time.Second), config.Rediscover)
	}
	if r.Sent["dns"] < uint64(sent["dns"]) || r.Received["dns"] == 0 {
		t.Errorf("the worker counts %d sent and %d taken, the wire has %d from it since the server started", r.Sent["dns"], r.Received["dns"], sent["dns"])
	}
	if sent["mdns"]+sent["mdns lookup"]+sent["netbios"]+sent["llmnr"]+sent["tcp"] != 0 {
		t.Errorf("asked by other protocols than the one asked for: %v", sent)
	}
	// Every question was the server's to take: its log has those of a.
	if log := router.log.String(); !strings.Contains(log, "query[PTR]") || !strings.Contains(log, "from "+a.ipv4.String()) {
		t.Errorf("the server was not asked by the worker:\n%s", log)
	}
	t.Logf("p named %+v, q %+v; a sent %v in %s", r.Names[p.mac], r.Names[q.mac], sent, elapsed.Round(time.Second))
}

// A host that asks for an address by DHCP tells its name as it does, to all: it is named by it,
// at its MAC, and the address it asks for is found by the discovery, with nothing probed, as
// soon as it has it. Over DHCPv6 it tells its name from its link-local address, and is named by
// that at the MAC the discovery finds the address at. Nothing is sent, and no port taken: beside
// the DHCP server itself, on its machine, a worker hears the same, and the server serves.
func TestLiveNamesDHCP(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveNamesDHCP")
		return
	}
	a, b, p, q := lan["a"], lan["b"], lan["p"], lan["q"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	router := startDnsmasq(t, b.namespace, "--dhcp-range=10.66.5.32,10.66.5.60,255.255.255.192,10m", "--dhcp-range=fd00:6:5::1000,fd00:6:5::1fff,64,10m")
	config := namesBy(listening, listening, NameDHCP)
	instances := map[string]*remoteInstance{
		"a": startInstance(t, a.namespace, config),
		// Beside the server, which has the ports.
		"b": startInstance(t, b.namespace, config),
	}
	for name, instance := range instances {
		defer instance.stop()
		waitFor(t, 30*time.Second, "the own addresses of the worker on "+name, func() bool {
			found6, _ := instance.report().self(lan[name].ipv6)
			found4, _ := instance.report().self(lan[name].ipv4)
			return found6 && found4
		})
	}
	// p has no IPv4 address until it is given one.
	inNamespace(t, p.namespace, "ip", "addr", "del", p.ipv4.String()+"/26", "dev", "lan")
	time.Sleep(2 * time.Second)
	wire.reset()

	leased := func(r report) bool {
		return slices.ContainsFunc(r.Hosts[p.mac], func(addr reportAddr) bool {
			return netip.MustParsePrefix("10.66.5.32/27").Contains(addr.IP)
		})
	}
	script := filepath.Join(t.TempDir(), "bound")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n[ \"$1\" = bound ] && ip addr add $ip/$mask dev $interface\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	asked := time.Now()
	client := startService(t, p.namespace, "udhcpc", "exec udhcpc -f -i lan -x hostname:DHCP_P -s "+script)
	for name, instance := range instances {
		waitFor(t, 15*time.Second, "p named by what it told its DHCP server, and its address found, by the worker on "+name, func() bool {
			r := instance.report()
			return r.named(p.mac, "dhcp-p") && leased(r)
		})
		t.Logf("the worker on %s named p and found its address %s after it asked", name, time.Since(asked).Round(100*time.Millisecond))
		if r := instance.report(); !slices.Equal(r.sources(p.mac, "dhcp-p"), []string{"dhcp"}) || r.Received["dhcp"] == 0 {
			t.Errorf("the worker on %s: the names of p: %+v; %d messages taken", name, r.Names[p.mac], r.Received["dhcp"])
		}
	}
	client.said("obtained", 10*time.Second)
	if log := router.log.String(); !strings.Contains(log, "DHCPACK(lan)") {
		t.Errorf("the server, beside a worker, gave no lease:\n%s", log)
	}

	// Over DHCPv6: the name is in what the client sends the servers' group.
	// Its files where it keeps them, which a system that confines it lets it: each its own. And
	// no script: it only has to ask.
	for _, dir := range []string{"/etc/dhcp", "/var/lib/dhcp"} {
		os.MkdirAll(dir, 0o755)
	}
	startService(t, p.namespace, "dhclient", `mount -t tmpfs tmpfs /etc/dhcp && mount -t tmpfs tmpfs /var/lib/dhcp && printf 'send fqdn.fqdn "dhcp6-p.lan.test.";\nsend fqdn.encoded on;\nsend fqdn.server-update on;\nalso request dhcp6.fqdn;\n' > /etc/dhcp/dhclient.conf && exec dhclient -6 -d -cf /etc/dhcp/dhclient.conf -lf /var/lib/dhcp/dhclient6.leases -pf /run/dhclient6.ipv6disc-test.pid -sf /bin/true lan`)
	for name, instance := range instances {
		waitFor(t, 20*time.Second, "p named by what it told the DHCPv6 servers, by the worker on "+name, func() bool {
			return instance.report().named(p.mac, "dhcp6-p")
		})
		r := instance.report()
		if !r.has(p.mac, linkLocal(mustMAC(p.mac))) {
			t.Errorf("the worker on %s named p without its link-local address, which the name came from: %+v", name, r.Hosts[p.mac])
		}
	}

	// Another host says it is the client. q writes b's MAC in a request of its own, and b's
	// link-local address as the source of a solicitation: frames from q's MAC, which name
	// nobody. The same of q itself, as it is, do name it: they were heard, and read.
	inNamespace(t, b.namespace, "ping", "-c1", "-W1", a.ipv4.String())
	inNamespace(t, b.namespace, "ping", "-c1", "-W1", linkLocal(mustMAC(a.mac)).String()+"%lan")
	inNamespace(t, q.namespace, "ping", "-c1", "-W1", a.ipv4.String())
	waitFor(t, 10*time.Second, "b and q, by what they sent the worker on a", func() bool {
		r := instances["a"].report()
		return r.has(b.mac, b.ipv4) && r.has(b.mac, linkLocal(mustMAC(b.mac))) && r.has(q.mac, q.ipv4)
	})
	helper(t, q.namespace, "dhcp", b.mac, "evil4-b", "10.66.5.44")
	helper(t, q.namespace, "dhcp6", linkLocal(mustMAC(b.mac)).String(), "evil6-b")
	helper(t, q.namespace, "dhcp", q.mac, "forged4-q", q.ipv4.String())
	helper(t, q.namespace, "dhcp6", linkLocal(mustMAC(q.mac)).String(), "forged6-q")
	for name, instance := range instances {
		waitFor(t, 15*time.Second, "q named by the messages it made up of itself, by the worker on "+name, func() bool {
			r := instance.report()
			return r.named(q.mac, "forged4-q") && r.named(q.mac, "forged6-q")
		})
	}
	time.Sleep(2 * time.Second)
	for name, instance := range instances {
		r := instance.report()
		if len(r.Names[b.mac]) != 0 || r.named(q.mac, "evil4-b") || r.named(q.mac, "evil6-b") {
			t.Errorf("the worker on %s named a host by another's message: b %+v, q %+v", name, r.Names[b.mac], r.Names[q.mac])
		}
	}

	// It only hears: nothing went to the ports of DHCP, of either family, and none is taken.
	if sent := wire.from(a.mac); sent["dhcp"] != 0 {
		t.Errorf("the worker sent to the ports of DHCP: %v", sent)
	}
	if sockets := inNamespace(t, a.namespace, "ss", "-Hulpn"); strings.Contains(sockets, ":67 ") || strings.Contains(sockets, ":68 ") || strings.Contains(sockets, ":547 ") || strings.Contains(sockets, ":546 ") {
		t.Errorf("a port of DHCP taken by the worker:\n%s", sockets)
	}
	for _, instance := range instances {
		stopClean(t, instance)
	}
}

// The ARP a host sends tells it at once: a host that only asks for another's address, which the
// kernel of the worker never talked to, is found within a second, not at the reading of the
// neighbor table of the minute after, and without a sweep. A frame from one MAC that says an
// address is at another names no host; a gratuitous one, of its sender's own address, does.
func TestLivePassiveARP(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLivePassiveARP")
		return
	}
	a, b, p, q := lan["a"], lan["b"], lan["p"], lan["q"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	// No names, and nothing probed.
	instance := startInstance(t, a.namespace, Config{Protocols: findingProtocols(), Lifetime: time.Minute, Rediscover: 3 * time.Second, IPv4: listening})
	defer instance.stop()
	waitFor(t, 30*time.Second, "the worker's own address", func() bool {
		found, _ := instance.report().self(a.ipv4)
		return found
	})
	time.Sleep(3 * time.Second)
	if r := instance.report(); len(r.Hosts) != 1 {
		t.Fatalf("hosts found before any said anything: %+v", r.Hosts)
	}

	// q asks for an address nobody has: one request, to all.
	found := func(h lanHost, since time.Time) time.Duration {
		t.Helper()
		for !instance.report().has(h.mac, h.ipv4) {
			if time.Since(since) > 5*time.Second {
				t.Fatalf("%s not found by the ARP it sent, in %s", h.ipv4, time.Since(since).Round(time.Second))
			}
			time.Sleep(20 * time.Millisecond)
		}
		return time.Since(since)
	}
	asked := time.Now()
	ping := exec.Command("ip", "netns", "exec", q.namespace, "ping", "-c1", "-W1", "10.66.5.50")
	if err := ping.Start(); err != nil {
		t.Fatal(err)
	}
	if took := found(q, asked); took > time.Second {
		t.Errorf("q found %s after it asked: want within a second of its request", took.Round(10*time.Millisecond))
	} else {
		t.Logf("q found %s after it asked for another's address", took.Round(10*time.Millisecond))
	}
	ping.Wait()
	// A frame of p's that says an address is at another MAC, three times; then p announces its
	// own, to all, in a gratuitous one; and b's says b's own address is at the worker's MAC.
	const liarMAC, lie = "02:00:00:00:05:ee", "10.66.5.33"
	for range 3 {
		helper(t, p.namespace, "arp", liarMAC, lie, a.ipv4.String())
	}
	helper(t, b.namespace, "arp", a.mac, b.ipv4.String(), a.ipv4.String())
	announced := time.Now()
	helper(t, p.namespace, "arp", p.mac, p.ipv4.String(), p.ipv4.String())
	took := found(p, announced)
	time.Sleep(time.Second)
	r := instance.report()
	if len(r.Hosts[liarMAC]) != 0 || r.has(p.mac, netip.MustParseAddr(lie)) || r.has(a.mac, b.ipv4) || len(r.Hosts[b.mac]) != 0 {
		t.Errorf("a host by a frame that says an address is at another MAC than it came from: %+v", r.Hosts)
	}
	if r.Received["arp"] < 5 {
		t.Errorf("the worker counts %d ARP packets heard", r.Received["arp"])
	}
	// It only heard: not one request of its own, of the worker's nor of its kernel's.
	if sent := wire.from(a.mac); sent["arp"] != 0 || sent["discard"] != 0 {
		t.Errorf("the worker's machine sent %v", sent)
	}
	t.Logf("p found %s after its gratuitous ARP; the worker heard %d packets", took.Round(10*time.Millisecond), r.Received["arp"])
	stopClean(t, instance)
}

// Without the privilege for packet sockets, CAP_NET_RAW, what needs them is not heard, and says
// so once each: the ARP of the hosts, DHCP and LLDP. The rest runs as it did: the hosts are found
// by the neighbor table, after the sweep, and nothing is an error.
func TestLiveWithoutPacketSockets(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveWithoutPacketSockets")
		return
	}
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Skip("needs setpriv")
	}
	a, p := lan["a"], lan["p"]
	// IPv4 alone: NDP has a raw socket of its own to need it for.
	instance := startInstanceAs(t, a.namespace, namesBy(Family{}, probing, NameDHCP, NameLLDP), "setpriv", "--bounding-set", "-net_raw", "--")
	defer instance.stop()
	waitFor(t, 30*time.Second, "p, by the neighbor table", func() bool { return instance.report().has(p.mac, p.ipv4) })
	// Three more rediscoveries, and readings of the table.
	time.Sleep(10 * time.Second)
	r := instance.report()
	if !r.has(p.mac, p.ipv4) || r.Received["arp"] != 0 || r.Received["dhcp"] != 0 || r.Received["lldp"] != 0 {
		t.Errorf("without packet sockets: p found %v, and heard %v", r.has(p.mac, p.ipv4), r.Received)
	}
	if sockets := inNamespace(t, a.namespace, "cat", "/proc/net/packet"); strings.Count(sockets, "\n") > 1 {
		t.Errorf("packet sockets without the privilege for them:\n%s", sockets)
	}
	instance.stop()
	log := instance.log.String()
	for _, said := range []string{"not listening for ARP, which needs CAP_NET_RAW", "not listening for DHCP, which needs CAP_NET_RAW", "not listening for LLDP, which needs CAP_NET_RAW"} {
		if got := strings.Count(log, said); got != 1 {
			t.Errorf("%q said %d times, want once:\n%s", said, got, log)
		}
	}
	if strings.Contains(log, "ERROR") || strings.Contains(log, "panic") {
		t.Errorf("the worker logged errors:\n%s", log)
	}
}

// A computer that answers WS-Discovery, as Windows does and wsdd2, here, for Samba, is named by
// its metadata: asked where it is by a Resolve sent to it alone, and fetched from it over HTTP.
func TestLiveNamesWSD(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveNamesWSD")
		return
	}
	a, b, p := lan["a"], lan["b"], lan["p"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	startService(t, p.namespace, "wsdd2", "exec wsdd2 -w -W -i lan -N WINBOX-P -G TESTGROUP").said("starting", 10*time.Second)
	time.Sleep(time.Second)

	config := namesBy(probing, Family{}, NameWSD)
	instance := startInstance(t, a.namespace, config)
	defer instance.stop()
	started := time.Now()
	waitFor(t, 30*time.Second, "the name of p, of its metadata", func() bool { return instance.report().named(p.mac, "winbox-p") })
	waitFor(t, 20*time.Second, "b found", func() bool { return instance.report().has(b.mac, b.ipv6) })
	time.Sleep(7 * time.Second)
	elapsed := time.Since(started)
	r := instance.report()
	if got := r.sources(p.mac, "winbox-p"); !slices.Equal(got, []string{"wsd"}) {
		t.Errorf("the names of p: %+v", r.Names[p.mac])
	}
	if len(r.Names[b.mac]) != 0 || len(r.Names[a.mac]) != 0 {
		t.Errorf("b, which answers nothing, has the names %+v; the worker's machine %+v", r.Names[b.mac], r.Names[a.mac])
	}
	// Its metadata is fetched once, while its name stays: not at every probe.
	sent := wire.from(a.mac)
	if sent["tcp"] == 0 || sent["tcp"] > 12 || sent["wsd resolve"] > 1 {
		t.Errorf("%d TCP segments and %d Resolve in %s, want those of one request", sent["tcp"], sent["wsd resolve"], elapsed.Round(time.Second))
	}
	if sent["mdns"]+sent["mdns lookup"]+sent["netbios"]+sent["llmnr"]+sent["dns"] != 0 {
		t.Errorf("asked by other protocols than the one asked for: %v", sent)
	}
	t.Logf("p named %+v; a sent %v in %s", r.Names[p.mac], sent, elapsed.Round(time.Second))
}

// A device that answers the search of SSDP is named by the friendly name of its description,
// fetched from it: only when the LOCATION of its answer is at the address it answered from. One
// that points to another host's is not asked, nor is that host.
func TestLiveNamesSSDP(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveNamesSSDP")
		return
	}
	a, p, q := lan["a"], lan["p"], lan["q"]
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	device := startHelper(t, p.namespace, "device", p.ipv6.String(), p.ipv6.String(), "/description.xml", "Living_Room_TV")
	// q's answer points to p's address: a description that is not its own.
	elsewhere := startHelper(t, q.namespace, "device", q.ipv6.String(), p.ipv6.String(), "/of-q.xml", "Elsewhere")

	config := namesBy(probing, Family{}, NameSSDP)
	instance := startInstance(t, a.namespace, config)
	defer instance.stop()
	started := time.Now()
	waitFor(t, 30*time.Second, "the name of p, of its description", func() bool { return instance.report().named(p.mac, "living-room-tv") })
	waitFor(t, 20*time.Second, "q found by its answer to the search", func() bool { return instance.report().has(q.mac, q.ipv6) })
	time.Sleep(7 * time.Second)
	elapsed := time.Since(started)
	r := instance.report()
	if got := r.sources(p.mac, "living-room-tv"); !slices.Equal(got, []string{"ssdp"}) {
		t.Errorf("the names of p: %+v", r.Names[p.mac])
	}
	if len(r.Names[q.mac]) != 0 {
		t.Errorf("q named by a description at another host: %+v", r.Names[q.mac])
	}
	if fetched := strings.Count(device.String(), "FETCHED"); fetched != 1 || strings.Contains(device.String(), "of-q") || strings.Contains(elsewhere.String(), "FETCHED") {
		t.Errorf("fetched %d times from p, want its description once, while its name stays, and nothing q pointed to:\n%s%s", fetched, device.String(), elsewhere.String())
	}
	sent := wire.from(a.mac)
	if sent["mdns"]+sent["mdns lookup"]+sent["netbios"]+sent["llmnr"]+sent["dns"]+sent["wsd resolve"] != 0 {
		t.Errorf("asked by other protocols than the one asked for: %v", sent)
	}
	t.Logf("p named %+v; a sent %v in %s", r.Names[p.mac], sent, elapsed.Round(time.Second))
}

// A neighbor that says who it is by LLDP, as a switch does and a host that runs lldpd, here, is
// named by its system name, at the MAC its frames come from, once the discovery found a host
// there. Nothing is sent.
func TestLiveNamesLLDP(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveNamesLLDP")
		return
	}
	a, p := lan["a"], lan["p"]
	// A bridge keeps the frames of LLDP to itself: this one lets them through, as a wire.
	ip(t, "link", "set", "br0", "type", "bridge", "group_fwd_mask", "0x4000")
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	instance := startInstance(t, a.namespace, namesBy(probing, Family{}, NameLLDP))
	defer instance.stop()
	waitFor(t, 30*time.Second, "p's address", func() bool { return instance.report().has(p.mac, p.ipv6) })

	os.MkdirAll("/run/lldpd", 0o755)
	startService(t, p.namespace, "lldpd", "mount -t tmpfs tmpfs /run/lldpd && hostname lldp-p && exec lldpd -d -I lan -m "+p.ipv6.String())
	waitFor(t, 45*time.Second, "p named by its LLDP", func() bool { return instance.report().named(p.mac, "lldp-p") })
	r := instance.report()
	if got := r.sources(p.mac, "lldp-p"); !slices.Equal(got, []string{"lldp"}) || r.Received["lldp"] == 0 {
		t.Errorf("the names of p: %+v; %d frames taken", r.Names[p.mac], r.Received["lldp"])
	}
	if sent := wire.from(a.mac); sent["lldp"] != 0 {
		t.Errorf("the worker's machine sent LLDP: %v", sent)
	}
	if heard := wire.from(p.mac); heard["lldp"] == 0 {
		t.Errorf("the capture saw no LLDP of p: %v", heard)
	}
	stopClean(t, instance)
}

// With the protocols of names off, nothing of any of this: beside the services that would answer,
// a worker that probes over both families sends nothing to their ports, fetches nothing, joins no
// group, and hears no DHCP nor LLDP; and it has no name.
func TestLiveNamesProtocolsOff(t *testing.T) {
	if os.Getenv(insideEnv) == "" {
		runOnLAN(t, "TestLiveNamesProtocolsOff")
		return
	}
	a, b, p, q := lan["a"], lan["b"], lan["p"], lan["q"]
	ip(t, "link", "set", "br0", "type", "bridge", "group_fwd_mask", "0x4000")
	wire := startCapture(t, "port-a", "port-b", "port-p", "port-q")
	// What answers each: a computer of WS-Discovery, a device of SSDP, and a DNS and DHCP
	// server; given too, which alone asks nothing.
	startService(t, p.namespace, "wsdd2", "exec wsdd2 -w -W -i lan -N WINBOX-P -G TESTGROUP").said("starting", 10*time.Second)
	device := startHelper(t, q.namespace, "device", q.ipv6.String(), q.ipv6.String(), "/description.xml", "Living_Room_TV")
	startDnsmasq(t, b.namespace, "--host-record=printer-p.lan.test,"+p.ipv4.String(), "--dhcp-range=10.66.5.32,10.66.5.60,255.255.255.192,10m")

	// The protocols that find hosts, and none of the names: the servers are given, and not asked.
	config := namesBy(probing, probing)
	config.Protocols.DNS.Servers = []netip.AddrPort{netip.AddrPortFrom(b.ipv4, 53)}
	instance := startInstance(t, a.namespace, config)
	defer instance.stop()
	waitFor(t, 30*time.Second, "the hosts", func() bool {
		r := instance.report()
		return r.has(p.mac, p.ipv6) && r.has(p.mac, p.ipv4) && r.has(q.mac, q.ipv6) && r.has(b.mac, b.ipv4)
	})
	// A client asks for an address, with its name, while the worker listens.
	script := filepath.Join(t.TempDir(), "bound")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	startService(t, p.namespace, "udhcpc", "exec udhcpc -f -i lan -x hostname:dhcp-p -s "+script).said("obtained", 15*time.Second)
	// Four rediscoveries.
	time.Sleep(12 * time.Second)

	r := instance.report()
	if len(r.Names) != 0 {
		t.Errorf("names without asking for them: %+v", r.Names)
	}
	sent := wire.from(a.mac)
	for _, kind := range []string{"mdns", "mdns lookup", "netbios", "llmnr", "dns", "dhcp", "tcp", "wsd resolve", "udp", "lldp"} {
		if sent[kind] != 0 {
			t.Errorf("%d of %q sent with the protocols of names off: %v", sent[kind], kind, sent)
		}
	}
	// The probes went, and were answered: there was what to fetch.
	if sent["wsd"] == 0 || sent["ssdp"] == 0 || sent["multicast ping"] == 0 || sent["arp"] == 0 {
		t.Errorf("the capture saw no probe of the worker: %v", sent)
	}
	if strings.Contains(device.String(), "FETCHED") {
		t.Errorf("a description fetched with the protocols of names off:\n%s", device.String())
	}
	if r.Received["wsd"] == 0 || r.Received["ssdp"] == 0 {
		t.Errorf("the probes had no answer: nothing was there to fetch: %v", r.Received)
	}
	groups := inNamespace(t, a.namespace, "ip", "maddr", "show", "dev", "lan")
	for _, group := range []string{"224.0.0.251", "ff02::fb", "224.0.0.252", "ff02::1:3", "01:80:c2:00:00:0e", "ff02::1:2"} {
		if strings.Contains(groups, group) {
			t.Errorf("the group %s joined with the protocols of names off:\n%s", group, groups)
		}
	}
	// The packet sockets of the machine: the one that hears ARP, which is of the IPv4
	// discovery, and none of IPv4, IPv6 nor LLDP, which the names' are.
	sockets := inNamespace(t, a.namespace, "cat", "/proc/net/packet")
	if !strings.Contains(sockets, " 0806 ") {
		t.Errorf("no socket hears ARP, though IPv4 listens:\n%s", sockets)
	}
	for _, protocol := range []string{" 0800 ", " 86dd ", " 88cc ", " 0003 "} {
		if strings.Contains(sockets, protocol) {
			t.Errorf("a packet socket of the protocol%swith the protocols of names off:\n%s", protocol, sockets)
		}
	}
}
