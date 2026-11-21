package rdns

import (
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/miguelangel-nubla/ipv6disc/internal/ptr"
	"github.com/miguelangel-nubla/ipv6disc/internal/questions"
)

func TestParseServer(t *testing.T) {
	for given, want := range map[string]string{
		"192.168.1.1":      "192.168.1.1:53",
		"192.168.1.1:5353": "192.168.1.1:5353",
		"fd00::1":          "[fd00::1]:53",
		"[fd00::1]:5353":   "[fd00::1]:5353",
		"fe80::1%eth0":     "[fe80::1%eth0]:53",
	} {
		if got, err := ParseServer(given); err != nil || got.String() != want {
			t.Errorf("%s: %s, %v; want %s", given, got, err, want)
		}
	}
	for _, given := range []string{"", "router.lan", "router.lan:53", "192.168.1.1:0", "192.168.1.1:x", "[fd00::1]", "192.168.1"} {
		if got, err := ParseServer(given); err == nil {
			t.Errorf("%q read as %s", given, got)
		}
	}
}

// server is a DNS server on the loopback, which answers the name of each address it knows, and
// an error for the others; and records what it was asked.
type testServer struct {
	conn  net.PacketConn
	mutex sync.Mutex
	asked []string
}

func startServer(t *testing.T, network, address string, names map[netip.Addr]string) *testServer {
	t.Helper()
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { conn.Close() })
	s := &testServer{conn: conn}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			q, err := ptr.Parse(buf[:n])
			if err != nil {
				continue
			}
			var p dnsmessage.Parser
			header, _ := p.Start(buf[:n])
			s.mutex.Lock()
			s.asked = append(s.asked, q.Question)
			s.mutex.Unlock()
			if !header.RecursionDesired {
				t.Error("a question without recursion desired")
			}
			for addr, name := range names {
				if q.Asks(addr) {
					answer, _ := ptr.Response(q.ID, addr, dnsmessage.RCodeSuccess, name)
					conn.WriteTo(answer, from)
				}
			}
			if !slices.ContainsFunc(slices.Collect(mapKeys(names)), q.Asks) {
				// The question again, with the error.
				buf[2] |= 0x80
				buf[3] = buf[3]&0xf0 | byte(dnsmessage.RCodeNameError)
				conn.WriteTo(buf[:n], from)
			}
		}
	}()
	return s
}

func mapKeys(m map[netip.Addr]string) func(func(netip.Addr) bool) {
	return func(yield func(netip.Addr) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func (s *testServer) addr() netip.AddrPort {
	return s.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Each server given is asked the name of an address, and the name the PTR record points to is
// told, whole: an error, or a server that has none, tells nothing.
func TestAskName(t *testing.T) {
	host, unknown := netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("192.168.1.99")
	host6 := netip.MustParseAddr("2001:db8::20")
	first := startServer(t, "udp4", "127.0.0.1:0", map[netip.Addr]string{host: "printer.lan."})
	second := startServer(t, "udp6", "[::1]:0", map[netip.Addr]string{host6: "printer6.lan."})

	answers := make(chan string, 4)
	conn, err := Dial([]netip.AddrPort{first.addr(), second.addr(), first.addr()}, Handler{
		Answered: func(asked netip.Addr, name string) { answers <- asked.String() + " " + name },
		Error:    func(err error) { t.Error(err) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if len(conn.servers) != 2 || len(conn.closers) != 2 {
		t.Fatalf("%d servers on %d sockets, want the two given, once each", len(conn.servers), len(conn.closers))
	}
	for _, addr := range []netip.Addr{host, unknown, host6} {
		if err := conn.AskName(addr); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for range 2 {
		select {
		case answer := <-answers:
			got = append(got, answer)
		case <-time.After(5 * time.Second):
			t.Fatalf("answers: %v", got)
		}
	}
	slices.Sort(got)
	if want := []string{"192.168.1.20 printer.lan.", "2001:db8::20 printer6.lan."}; !slices.Equal(got, want) {
		t.Errorf("answers %v, want %v", got, want)
	}
	// All six answers came, four of them errors, and nothing more is told.
	deadline := time.Now().Add(5 * time.Second)
	for conn.PacketsReceived.Load() < 6 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if conn.PacketsSent.Load() != 6 || conn.PacketsReceived.Load() != 6 || conn.HostsFound.Load() != 2 || len(answers) != 0 {
		t.Errorf("%d sent, %d taken, %d with a name", conn.PacketsSent.Load(), conn.PacketsReceived.Load(), conn.HostsFound.Load())
	}
	first.mutex.Lock()
	defer first.mutex.Unlock()
	if want := []string{"20.1.168.192.in-addr.arpa.", "99.1.168.192.in-addr.arpa.", "0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."}; !slices.Equal(first.asked, want) {
		t.Errorf("the server was asked %v, want %v", first.asked, want)
	}
}

// An answer is taken only from a server, at its address and port, as the answer to a question
// sent to that very server: with its ID and the question itself. Anything else names nobody.
func TestConnTakesOnlyAnswers(t *testing.T) {
	var answers []string
	one, two := netip.MustParseAddrPort("192.168.1.1:53"), netip.MustParseAddrPort("192.168.1.2:53")
	conn, err := Dial(nil, Handler{Answered: func(asked netip.Addr, name string) { answers = append(answers, asked.String()+" "+name) }})
	if err != nil {
		t.Fatal(err)
	}
	if conn.Asks(netip.MustParseAddr("192.168.1.20")) {
		t.Error("asks without a server")
	}
	// Without their sockets: nothing is sent here.
	for _, addr := range []netip.AddrPort{one, two} {
		conn.servers = append(conn.servers, asked{addr: addr, asked: &questions.Table{}})
	}
	host, other := netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("192.168.1.66")
	id := conn.servers[0].asked.Ask(host)
	answer := func(id uint16, addr netip.Addr, rcode dnsmessage.RCode, names ...string) []byte {
		message, err := ptr.Response(id, addr, rcode, names...)
		if err != nil {
			t.Fatal(err)
		}
		return message
	}
	question, _ := ptr.Query(id, host, true)
	for name, c := range map[string]struct {
		from   netip.AddrPort
		packet []byte
	}{
		"another host":                {netip.MustParseAddrPort("192.168.1.66:53"), answer(id, host, 0, "evil.")},
		"another port of the server":  {netip.MustParseAddrPort("192.168.1.1:5353"), answer(id, host, 0, "evil.")},
		"the other server":            {two, answer(id, host, 0, "evil.")},
		"another ID":                  {one, answer(id+1, host, 0, "evil.")},
		"the answer to another":       {one, answer(id, other, 0, "evil.")},
		"a question":                  {one, question},
		"what is no message":          {one, []byte("not DNS")},
		"a message cut in its answer": {one, answer(id, host, 0, "evil.")[:50]},
	} {
		conn.take(c.from, c.packet)
		if len(answers) != 0 || conn.PacketsReceived.Load() != 0 || conn.servers[0].asked.Waiting() != 1 {
			t.Fatalf("%s: taken without being the answer to the question: %v", name, answers)
		}
	}
	conn.take(netip.MustParseAddrPort("[::ffff:192.168.1.1]:53"), answer(id, host, 0, "Printer.lan.", "second.lan."))
	conn.take(one, answer(id, host, 0, "again.lan."))
	if want := []string{"192.168.1.20 Printer.lan."}; !slices.Equal(answers, want) || conn.PacketsReceived.Load() != 1 {
		t.Errorf("answers %v, want %v, once", answers, want)
	}
	// An error answers the question, and names nobody.
	id = conn.servers[1].asked.Ask(host)
	conn.take(two, answer(id, host, dnsmessage.RCodeNameError, "evil."))
	if len(answers) != 1 || conn.servers[1].asked.Waiting() != 0 || conn.PacketsReceived.Load() != 2 || conn.HostsFound.Load() != 1 {
		t.Errorf("an error: %v", answers)
	}

	for addr, want := range map[string]bool{
		"192.168.1.20": true, "203.0.113.9": true, "2001:db8::20": true, "fd00::20": true,
		"fe80::20": false, "169.254.1.1": false, "127.0.0.1": false, "224.0.0.1": false, "::": false,
	} {
		if got := conn.Asks(netip.MustParseAddr(addr)); got != want {
			t.Errorf("asks of %s: %v, want %v", addr, got, want)
		}
	}
	if err := conn.AskName(netip.MustParseAddr("fe80::20")); err == nil {
		t.Error("a link-local address asked of")
	}
	if _, err := Dial([]netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 0)}, Handler{}); err == nil {
		t.Error("a server without a port")
	}
}
