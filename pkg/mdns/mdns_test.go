package mdns

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// record is a record of a crafted message.
type record struct {
	name string
	// An address, for an A or an AAAA record, or a name, for a PTR one.
	addr  netip.Addr
	ptr   string
	ttl   uint32
	class dnsmessage.Class
}

// message crafts an mDNS message with those answers and additional records, and a TXT record
// among the answers, which says nothing here.
func message(t testing.TB, header dnsmessage.Header, answers, additionals []record) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, header)
	b.EnableCompression()
	add := func(records []record) {
		for _, r := range records {
			if r.class == 0 {
				r.class = dnsmessage.ClassINET
			}
			h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(r.name), Class: r.class, TTL: r.ttl}
			var err error
			switch {
			case r.ptr != "":
				err = b.PTRResource(h, dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(r.ptr)})
			case r.addr.Is4():
				err = b.AResource(h, dnsmessage.AResource{A: r.addr.As4()})
			default:
				err = b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: r.addr.As16()})
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	add(answers)
	if err := b.TXTResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("printer.local."), Class: dnsmessage.ClassINET, TTL: 120}, dnsmessage.TXTResource{TXT: []string{"a=b"}}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAdditionals(); err != nil {
		t.Fatal(err)
	}
	add(additionals)
	packet, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

var (
	printer4 = netip.MustParseAddr("192.168.1.20")
	printer6 = netip.MustParseAddr("2001:db8::20")
	// The cache-flush bit, which the records a host announces as its own have.
	flush = dnsmessage.ClassINET | 0x8000
)

func TestParse(t *testing.T) {
	response := dnsmessage.Header{Response: true, Authoritative: true}
	packet := message(t, response, []record{
		{name: "Printer.local.", addr: printer4, ttl: 120, class: flush},
		{name: "20.1.168.192.in-addr.arpa.", ptr: "Printer.local.", ttl: 120, class: flush},
		// A service, a record that says goodbye, and one of another class: nothing of them.
		{name: "_services._dns-sd._udp.local.", ptr: "_ipp._tcp.local.", ttl: 4500},
		{name: "gone.local.", addr: netip.MustParseAddr("192.168.1.21"), ttl: 0},
		{name: "chaos.local.", addr: netip.MustParseAddr("192.168.1.22"), ttl: 120, class: dnsmessage.ClassCHAOS},
	}, []record{
		{name: "Printer.local.", addr: printer6, ttl: 120, class: flush},
		{name: ReverseName(printer6), ptr: "Printer.local.", ttl: 120},
	})
	got, err := Parse(packet)
	want := Message{Response: true, Records: []Record{
		{Name: "Printer.local.", Addr: printer4},
		{Name: "Printer.local.", Addr: printer4, PTR: true},
		{Name: "Printer.local.", Addr: printer6},
		{Name: "Printer.local.", Addr: printer6, PTR: true},
	}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, %v\nwant %+v", got, err, want)
	}

	// A query's answers are those its sender knows already, of other hosts: none is taken.
	packet = message(t, dnsmessage.Header{ID: 7}, []record{{name: "other.local.", addr: printer4, ttl: 120}}, nil)
	if got, err := Parse(packet); err != nil || got.Response || got.ID != 7 || len(got.Records) != 0 {
		t.Errorf("a query: %+v, %v", got, err)
	}

	// No more records than the bound, however many it carries.
	var many []record
	for i := range 3 * MaxRecords {
		many = append(many, record{name: "many.local.", addr: netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), ttl: 120})
	}
	if got, err := Parse(message(t, response, many, nil)); err != nil || len(got.Records) != MaxRecords {
		t.Errorf("%d records taken of %d, %v, want %d", len(got.Records), len(many), err, MaxRecords)
	}
}

// A message that can't be read to its end gives nothing, whatever was read of it before.
func TestParseMalformed(t *testing.T) {
	whole := message(t, dnsmessage.Header{Response: true}, []record{{name: "printer.local.", addr: printer4, ttl: 120}}, []record{{name: "printer.local.", addr: printer6, ttl: 120}})
	if _, err := Parse(whole); err != nil {
		t.Fatal(err)
	}
	for cut := range len(whole) {
		if got, err := Parse(whole[:cut]); err == nil || len(got.Records) != 0 {
			t.Errorf("cut at %d of %d: %+v, %v", cut, len(whole), got, err)
		}
	}
	// A name that points to itself.
	loop := []byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 1}
	if got, err := Parse(loop); err == nil || len(got.Records) != 0 {
		t.Errorf("a name that points to itself: %+v, %v", got, err)
	}
	// An A record of 3 bytes.
	short := message(t, dnsmessage.Header{Response: true}, []record{{name: "a.local.", addr: printer4, ttl: 120}}, nil)
	for i := 12; i+1 < len(short); i++ {
		if short[i] == 0 && short[i+1] == 4 && i+6 <= len(short) && short[i+2] == 192 {
			short[i+1] = 3
		}
	}
	if got, err := Parse(short); err == nil || len(got.Records) != 0 {
		t.Errorf("an A record of 3 bytes: %+v, %v", got, err)
	}
}

func TestReverseName(t *testing.T) {
	for addr, want := range map[string]string{
		"192.168.1.20":         "20.1.168.192.in-addr.arpa.",
		"2001:db8::20":         "0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
		"fe80::1%eth0":         "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
		"::ffff:192.168.1.255": "255.1.168.192.in-addr.arpa.",
	} {
		a := netip.MustParseAddr(addr)
		got := ReverseName(a)
		if got != want {
			t.Errorf("ReverseName(%s) = %q, want %q", addr, got, want)
		}
		if back, ok := reverseAddr(got); !ok || back != a.Unmap().WithZone("") {
			t.Errorf("reverseAddr(%q) = %s, %v", got, back, ok)
		}
	}
	// As any name, whatever its case.
	if back, ok := reverseAddr("0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.B.D.0.1.0.0.2.IP6.ARPA."); !ok || back != printer6 {
		t.Errorf("upper case: %s, %v", back, ok)
	}
	for _, name := range []string{
		"printer.local.", "in-addr.arpa.", "1.168.192.in-addr.arpa.", "1.2.3.4.5.in-addr.arpa.", "a.1.168.192.in-addr.arpa.", "256.1.168.192.in-addr.arpa.",
		"ip6.arpa.", "0.2.ip6.arpa.", "g.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
		"00.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", "0020.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
	} {
		if addr, ok := reverseAddr(name); ok {
			t.Errorf("reverseAddr(%q) = %s", name, addr)
		}
	}
}

// What is asked: a question alone, for the PTR records of the name, with no bit asking for a
// unicast response, which the port it is sent from already gets.
func TestQuery(t *testing.T) {
	packet, err := query(0x1234, ReverseName(printer4))
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	header, err := p.Start(packet)
	if err != nil || header.ID != 0x1234 || header.Response {
		t.Fatalf("header %+v, %v", header, err)
	}
	questions, err := p.AllQuestions()
	if err != nil || len(questions) != 1 || questions[0].Name.String() != "20.1.168.192.in-addr.arpa." || questions[0].Type != dnsmessage.TypePTR || questions[0].Class != dnsmessage.ClassINET {
		t.Errorf("questions %+v, %v", questions, err)
	}
	if _, err := p.AnswerHeader(); err != dnsmessage.ErrSectionDone {
		t.Errorf("answers in a query: %v", err)
	}
	if servicesName != "_services._dns-sd._udp.local." || Port != 5353 || group4 != netip.MustParseAddr("224.0.0.251") || group6 != netip.MustParseAddr("ff02::fb") {
		t.Errorf("mDNS asks %s of %s and %s, port %d", servicesName, group4, group6, Port)
	}
}

// heard is what a Conn told its handler.
type heard struct {
	from     []netip.Addr
	said     []string
	answered []string
}

// testConn is a Conn without sockets, on an interface with those addresses.
func testConn(h *heard, prefixes ...string) *Conn {
	conn := &Conn{iface: &net.Interface{Index: 2, Name: "eth0"}, questions: make(map[uint16]question), prefixesAt: time.Now()}
	for _, p := range prefixes {
		conn.prefixes = append(conn.prefixes, netip.MustParsePrefix(p))
	}
	conn.handler = Handler{
		Heard: func(from netip.Addr) bool { h.from = append(h.from, from); return len(h.from) == 1 },
		Said: func(from netip.Addr, name string, addr netip.Addr, onLink bool) {
			link := "off the link"
			if onLink {
				link = "on the link"
			}
			h.said = append(h.said, from.String()+" "+name+" "+addr.String()+" "+link)
		},
		Answered: func(asked netip.Addr, name string) { h.answered = append(h.answered, asked.String()+" "+name) },
	}
	return conn
}

// A response is taken from the link only, and never from the interface's own address; each of its
// records is told as what its sender says, with whether the address is of the link, and nothing
// is told of a query but its sender.
func TestTake(t *testing.T) {
	var h heard
	conn := testConn(&h, "192.168.1.5/24", "2001:db8::5/64", "fe80::5/64")
	response := message(t, dnsmessage.Header{Response: true}, []record{
		{name: "printer.local.", addr: printer4, ttl: 120},
		{name: "printer.local.", addr: printer6, ttl: 120},
		{name: "elsewhere.local.", addr: netip.MustParseAddr("203.0.113.9"), ttl: 120},
	}, nil)

	for _, from := range []string{
		"203.0.113.7", "2001:db8:1::7", // routed in
		"192.168.1.5", "2001:db8::5", "fe80::5", // this machine's own responder
		"127.0.0.1", "::1", "224.0.0.251", "0.0.0.0",
	} {
		conn.take(netip.MustParseAddr(from), response, false)
	}
	if len(h.from) != 0 || len(h.said) != 0 || conn.PacketsReceived.Load() != 0 {
		t.Fatalf("taken from off the link, or from itself: %+v", h)
	}

	conn.take(netip.MustParseAddr("::ffff:192.168.1.20"), response, false)
	conn.take(netip.MustParseAddr("fe80::20%eth0"), []byte("not DNS"), false)
	conn.take(netip.MustParseAddr("fe80::20%eth0"), message(t, dnsmessage.Header{}, []record{{name: "known.local.", addr: printer4, ttl: 120}}, nil), false)
	want := heard{
		from: []netip.Addr{printer4, netip.MustParseAddr("fe80::20")},
		said: []string{
			"192.168.1.20 printer.local. 192.168.1.20 on the link",
			"192.168.1.20 printer.local. 2001:db8::20 on the link",
			"192.168.1.20 elsewhere.local. 203.0.113.9 off the link",
		},
	}
	if !reflect.DeepEqual(h, want) {
		t.Errorf("got %+v\nwant %+v", h, want)
	}
	if stats := conn.Stats(); stats["recv"] != uint64(2) || stats["hosts"] != uint64(1) {
		t.Errorf("stats: %v", stats)
	}
}

// The answer to a question is the PTR record of the address asked, in a response with the
// question's ID, on the socket it was sent from, and once. On that socket, which takes what is
// sent to this machine from anywhere, nothing else is taken at all: not a response with another
// ID, nor a second one with the same.
func TestTakeAnswer(t *testing.T) {
	var h heard
	conn := testConn(&h, "192.168.1.5/24")
	answer := func(id uint16, addr netip.Addr) []byte {
		return message(t, dnsmessage.Header{ID: id, Response: true}, []record{{name: ReverseName(addr), ptr: "printer.local.", ttl: 10}}, nil)
	}
	other := netip.MustParseAddr("192.168.1.30")
	id := conn.ask(printer4)
	if id == 0 {
		t.Fatal("a question with the ID of what is sent to all")
	}

	conn.take(printer4, answer(id+1, printer4), true) // another ID
	conn.take(printer4, answer(id, printer4), false)  // on the group's socket
	conn.take(printer4, answer(id, other), true)      // another address than the one asked
	if len(h.answered) != 0 {
		t.Fatalf("answers that are none: %v", h.answered)
	}
	// That last one took the question: it is asked again.
	id = conn.ask(printer4)
	conn.take(other, answer(id, printer4), true) // from another address of the host
	conn.take(printer4, answer(id, printer4), true)
	if want := []string{"192.168.1.20 printer.local."}; !reflect.DeepEqual(h.answered, want) {
		t.Errorf("answers: %v, want %v", h.answered, want)
	}
	// What its sender says, and no more: the one heard in the group, and the record of another
	// address in the answer to a question.
	if want := []string{
		"192.168.1.20 printer.local. 192.168.1.20 on the link",
		"192.168.1.20 printer.local. 192.168.1.30 on the link",
	}; !reflect.DeepEqual(h.said, want) {
		t.Errorf("said: %v, want %v", h.said, want)
	}
	// The sender of what answers nothing isn't even a host heard: two of the five were none.
	if len(h.from) != 3 || conn.PacketsReceived.Load() != 3 {
		t.Errorf("taken on the socket of the questions: from %v, %d packets, want the three that answered or came in the group", h.from, conn.PacketsReceived.Load())
	}

	// One that waited too long is no answer.
	id = conn.ask(printer4)
	conn.questions[id] = question{printer4, time.Now().Add(-2 * questionTimeout)}
	conn.take(printer4, answer(id, printer4), true)
	if len(h.answered) != 1 {
		t.Errorf("a late answer taken: %v", h.answered)
	}
	conn.ask(other)
	if _, waiting := conn.questions[id]; waiting || len(conn.questions) != 1 {
		t.Errorf("the questions that wait: %v", conn.questions)
	}
}

// The query for the services is answered by every host, each with its ID, to the socket it was
// sent from, for as long as it waits; what comes there with another ID, as from someone who
// guessed the port, with no ID, as what is sent to the group, or as a query, is left: neither its
// records nor its sender are taken.
func TestTakeServicesAnswers(t *testing.T) {
	var h heard
	conn := testConn(&h, "192.168.1.5/24")
	other := netip.MustParseAddr("192.168.1.30")
	response := func(id uint16, addr netip.Addr) []byte {
		return message(t, dnsmessage.Header{ID: id, Response: true}, []record{{name: "host.local.", addr: addr, ttl: 120}}, nil)
	}
	id := conn.ask(netip.Addr{})
	if id == 0 {
		t.Fatal("a query with the ID of what is sent to all")
	}

	conn.take(printer4, response(id+1, printer4), true)
	conn.take(printer4, response(0, printer4), true)
	conn.take(printer4, message(t, dnsmessage.Header{ID: id}, nil, nil), true)
	if len(h.from) != 0 || len(h.said) != 0 || conn.PacketsReceived.Load() != 0 {
		t.Fatalf("taken on the socket of the questions, though it answers none: %+v", h)
	}
	// The query's own ID was not taken by the query above: every host answers it.
	if _, waited := conn.answered(id); !waited {
		t.Fatal("the query for the services no longer waits, after a query came with its ID")
	}

	conn.take(printer4, response(id, printer4), true)
	conn.take(other, response(id, other), true)
	want := []string{"192.168.1.20 host.local. 192.168.1.20 on the link", "192.168.1.30 host.local. 192.168.1.30 on the link"}
	if !reflect.DeepEqual(h.said, want) || len(h.from) != 2 || len(h.answered) != 0 {
		t.Errorf("the answers of two hosts to the query for the services: %+v, want said %v", h, want)
	}

	// Its time over, it waits no more.
	conn.questions[id] = question{at: time.Now().Add(-2 * questionTimeout)}
	conn.take(printer4, response(id, printer4), true)
	if len(h.said) != 2 {
		t.Errorf("a late answer to the query for the services taken: %v", h.said)
	}
	// Each query waits, and those whose time is over are forgotten at the next.
	for range 3 {
		conn.ask(netip.Addr{})
	}
	if len(conn.questions) != 3 {
		t.Errorf("%d questions wait, want the three in time", len(conn.questions))
	}
}

func TestAsks(t *testing.T) {
	conn := testConn(&heard{}, "192.168.1.5/24", "2001:db8::5/64")
	// No socket of either family: nothing is asked.
	if conn.Asks(printer4) || conn.Asks(printer6) {
		t.Error("asks without a socket")
	}
	if err := conn.AskName(printer4); err == nil {
		t.Error("AskName without a socket: no error")
	}
	for addr, want := range map[string]bool{
		"192.168.1.20": true, "192.168.1.5": false, "192.168.2.20": false,
		"2001:db8::20": true, "fe80::20": true, "2001:db8:1::20": false, "2001:db8::5": false, "ff02::fb": false,
	} {
		if got := conn.OnLink(netip.MustParseAddr(addr)); got != want {
			t.Errorf("OnLink(%s) = %v, want %v", addr, got, want)
		}
	}
}

// A Conn on a real interface, which sends nothing here: Close ends its four readers without an
// error told, and a second Conn has the port beside the first, as beside a responder. Without an
// interface to join the groups on, as in a sandbox, there is nothing to tell.
func TestListenClose(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skip(err)
	}
	before := runtime.NumGoroutine()
	errs := make(chan error, 16)
	handler := Handler{Error: func(err error) { errs <- err }}
	var first, second *Conn
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if first, err = Listen(&iface, Options{IPv4: true, IPv6: true}, handler); err != nil {
			continue
		}
		if second, err = Listen(&iface, Options{IPv4: true, IPv6: true}, handler); err != nil {
			first.Close()
			t.Fatalf("a second Conn on %s, beside the first: %v", iface.Name, err)
		}
		break
	}
	if first == nil || second == nil {
		t.Skipf("no interface to listen for mDNS on: %v", err)
	}
	if got := runtime.NumGoroutine(); got < before+8 {
		t.Errorf("%d goroutines with two Conns, %d before: want the four readers of each", got, before)
	}
	if err := errors.Join(first.Close(), second.Close()); err != nil {
		t.Errorf("Close: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines after Close, %d before", runtime.NumGoroutine(), before)
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-errs:
		t.Errorf("an error told of a Conn that was closed: %v", err)
	default:
	}
}

// The reading of a socket takes what came in on the Conn's interface, and what the system doesn't
// tell the interface of: a socket in a group hears it on every interface anything joined it on,
// and what came in on another is that link's, not this one's. An error of a read is told, and the
// next tried; the one of a socket closed ends it, untold.
func TestRead(t *testing.T) {
	var h heard
	var errs []error
	conn := testConn(&h, "192.168.1.5/24")
	conn.handler.Error = func(err error) { errs = append(errs, err) }
	response := func(name string) []byte {
		return message(t, dnsmessage.Header{Response: true}, []record{{name: name, addr: printer4, ttl: 120}}, nil)
	}
	type packet struct {
		payload []byte
		index   int
		err     error
	}
	packets := []packet{
		{payload: response("other-link.local."), index: conn.iface.Index + 1},
		{err: errors.New("a read that failed")},
		{payload: response("this-link.local."), index: conn.iface.Index},
		{payload: response("untold.local.")},
		{err: net.ErrClosed},
		{payload: response("after-close.local."), index: conn.iface.Index},
	}
	next := 0
	conn.read(func(b []byte) (int, int, net.Addr, error) {
		p := packets[next]
		next++
		return copy(b, p.payload), p.index, &net.UDPAddr{IP: printer4.AsSlice(), Port: Port}, p.err
	}, false)

	want := []string{
		"192.168.1.20 this-link.local. 192.168.1.20 on the link",
		"192.168.1.20 untold.local. 192.168.1.20 on the link",
	}
	if !reflect.DeepEqual(h.said, want) {
		t.Errorf("said: %v, want %v", h.said, want)
	}
	if len(errs) != 1 || next != 5 {
		t.Errorf("errors told: %v, and %d reads, want the one that failed, and to end at the fifth", errs, next)
	}
}
