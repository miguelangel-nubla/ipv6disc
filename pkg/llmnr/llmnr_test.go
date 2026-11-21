package llmnr

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/miguelangel-nubla/ipv6disc/internal/onlink"
	"github.com/miguelangel-nubla/ipv6disc/internal/ptr"
)

func response(t *testing.T, id uint16, addr netip.Addr, rcode dnsmessage.RCode, names ...string) []byte {
	t.Helper()
	message, err := ptr.Response(id, addr, rcode, names...)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func testConn(answers *[]string) *Conn {
	return &Conn{iface: &net.Interface{Name: "eth0"},
		link: onlink.Among(netip.MustParsePrefix("192.168.1.5/24"), netip.MustParsePrefix("2001:db8::5/64")),
		handler: Handler{Answered: func(asked, from netip.Addr, name string) {
			*answers = append(*answers, asked.String()+" from "+from.String()+" "+name)
		}}}
}

// An answer is taken only as the answer to a question asked: a response, with its ID and the
// question itself, from the port of LLMNR at an address of the link, over the family asked over.
// Anything else names nobody, and leaves the question waiting for its answer, which is taken
// once.
func TestConnTakesOnlyAnswers(t *testing.T) {
	var answers []string
	conn := testConn(&answers)
	host, other := netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("192.168.1.66")
	id := conn.asked.Ask(host)

	question, _ := ptr.Query(id, host, false)
	for name, c := range map[string]struct {
		from   netip.AddrPort
		packet []byte
	}{
		"another ID":               {netip.AddrPortFrom(host, Port), response(t, id+1, host, 0, "evil.")},
		"another port":             {netip.AddrPortFrom(host, 5353), response(t, id, host, 0, "evil.")},
		"an address off the link":  {netip.MustParseAddrPort("203.0.113.9:5355"), response(t, id, host, 0, "evil.")},
		"the interface's own":      {netip.MustParseAddrPort("192.168.1.5:5355"), response(t, id, host, 0, "evil.")},
		"the answer to another":    {netip.AddrPortFrom(host, Port), response(t, id, other, 0, "evil.")},
		"another family":           {netip.MustParseAddrPort("[fe80::20]:5355"), response(t, id, host, 0, "evil.")},
		"a question":               {netip.AddrPortFrom(host, Port), question},
		"what is no message":       {netip.AddrPortFrom(host, Port), []byte("not LLMNR")},
		"a multicast source":       {netip.MustParseAddrPort("224.0.0.252:5355"), response(t, id, host, 0, "evil.")},
		"an unspecified source":    {netip.MustParseAddrPort("0.0.0.0:5355"), response(t, id, host, 0, "evil.")},
		"a loopback source":        {netip.MustParseAddrPort("127.0.0.1:5355"), response(t, id, host, 0, "evil.")},
		"a cut message":            {netip.AddrPortFrom(host, Port), response(t, id, host, 0, "evil.")[:20]},
		"an ID that was never one": {netip.AddrPortFrom(host, Port), response(t, 0, host, 0, "evil.")},
	} {
		conn.take(c.from, c.packet)
		if len(answers) != 0 || conn.PacketsReceived.Load() != 0 || conn.asked.Waiting() != 1 {
			t.Fatalf("%s: taken without being the answer to the question: %v", name, answers)
		}
	}
	conn.take(netip.AddrPortFrom(host, Port), response(t, id, host, 0, "Winbox.", "second."))
	conn.take(netip.AddrPortFrom(host, Port), response(t, id, host, 0, "again."))
	if want := []string{"192.168.1.20 from 192.168.1.20 Winbox."}; !slices.Equal(answers, want) || conn.PacketsReceived.Load() != 1 || conn.HostsFound.Load() != 1 {
		t.Errorf("answers %v, want %v, once", answers, want)
	}
}

// A responder answers from the address its system chooses: another of the link is told as it
// is, for the caller to prove it is the host asked. And a host that has no name for the address
// answers the question too, with nothing.
func TestConnAnswersFromAnotherAddress(t *testing.T) {
	var answers []string
	conn := testConn(&answers)
	global, linkLocal := netip.MustParseAddr("2001:db8::20"), netip.MustParseAddr("fe80::20")
	id := conn.asked.Ask(global)
	conn.take(netip.AddrPortFrom(linkLocal.WithZone("eth0"), Port), response(t, id, global, 0, "winbox."))
	if want := []string{"2001:db8::20 from fe80::20 winbox."}; !slices.Equal(answers, want) {
		t.Errorf("answers %v, want %v", answers, want)
	}
	for _, rcode := range []dnsmessage.RCode{dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError} {
		id = conn.asked.Ask(global)
		conn.take(netip.AddrPortFrom(global, Port), response(t, id, global, rcode))
		if len(answers) != 1 || conn.asked.Waiting() != 0 {
			t.Errorf("an answer without a name, %s: %v, %d waiting", rcode, answers, conn.asked.Waiting())
		}
	}
	if conn.PacketsReceived.Load() != 3 || conn.HostsFound.Load() != 1 {
		t.Errorf("%d taken, %d with a name", conn.PacketsReceived.Load(), conn.HostsFound.Load())
	}
}

// Only a host of the interface's link is asked, over a family the Conn asks over.
func TestAsks(t *testing.T) {
	var answers []string
	conn := testConn(&answers)
	if conn.Asks(netip.MustParseAddr("192.168.1.20")) || conn.Asks(netip.MustParseAddr("2001:db8::20")) {
		t.Error("asks without a socket of the family")
	}
	if err := conn.AskName(netip.MustParseAddr("192.168.1.20")); err == nil || conn.asked.Waiting() != 0 {
		t.Errorf("asked without a socket: %v", err)
	}
	lo := loopback(t)
	listening, err := Listen(lo, Options{IPv4: true, IPv6: true}, Handler{Error: func(err error) { t.Error(err) }})
	if err != nil {
		t.Skip(err)
	}
	defer listening.Close()
	listening.link = conn.link
	for addr, want := range map[string]bool{
		"192.168.1.20": true, "::ffff:192.168.1.20": true, "2001:db8::20": true, "fe80::20": true,
		"192.168.1.5": false, "2001:db8::5": false, "10.0.0.1": false, "2001:db8:1::1": false, "224.0.0.252": false,
	} {
		if got := listening.Asks(netip.MustParseAddr(addr)); got != want {
			t.Errorf("asks %s: %v, want %v", addr, got, want)
		}
	}
	for _, c := range listening.closers {
		if port := c.LocalAddr().(*net.UDPAddr).Port; port == Port || port == 0 {
			t.Errorf("listening on port %d", port)
		}
	}
	only4, err := Listen(lo, Options{IPv4: true}, Handler{})
	if err != nil {
		t.Fatal(err)
	}
	defer only4.Close()
	only4.link = conn.link
	if !only4.Asks(netip.MustParseAddr("192.168.1.20")) || only4.Asks(netip.MustParseAddr("2001:db8::20")) || len(only4.closers) != 1 {
		t.Error("the families asked over are not those of the options")
	}
}

func loopback(t *testing.T) *net.Interface {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return &iface
		}
	}
	t.Skip("no loopback interface")
	return nil
}
