package ptr

import (
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// Response is the answer of a responder to the question for the name of asked: with records, each
// the PTR record of an address's reverse name, which points to a name.
func response(t testing.TB, id uint16, rcode dnsmessage.RCode, asked netip.Addr, records ...[2]string) []byte {
	t.Helper()
	question, err := Query(id, asked, false)
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(question); err != nil {
		t.Fatal(err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, RCode: rcode})
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	for _, r := range records {
		header := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(r[0]), Class: dnsmessage.ClassINET, TTL: 30}
		if err := b.PTRResource(header, dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(r[1])}); err != nil {
			t.Fatal(err)
		}
	}
	message, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func TestQueryAndAnswer(t *testing.T) {
	v4, v6 := netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("2001:db8::20")
	for _, addr := range []netip.Addr{v4, v6} {
		question, err := Query(77, addr, true)
		if err != nil {
			t.Fatal(err)
		}
		q, err := Parse(question)
		if err != nil || q.ID != 77 || q.Response || !q.Asks(addr) || len(q.Names) != 0 {
			t.Errorf("the question for %s: %+v, %v", addr, q, err)
		}
		if _, ok := q.Name(addr); ok {
			t.Errorf("a question taken as the answer for %s", addr)
		}
	}
	const reverse4 = "20.1.168.192.in-addr.arpa."

	a, err := Parse(response(t, 9, dnsmessage.RCodeSuccess, v4, [2]string{"20.1.168.192.IN-ADDR.ARPA.", "Printer.lan."}, [2]string{reverse4, "second.lan."}))
	if name, ok := a.Name(v4); err != nil || !ok || name != "Printer.lan." || a.ID != 9 || !slices.Equal(a.Names, []string{"Printer.lan.", "second.lan."}) {
		t.Errorf("an answer: %+v, %v", a, err)
	}
	// It answers its own question alone.
	if _, ok := a.Name(v6); ok || a.Asks(v6) {
		t.Error("an answer taken for another address than it is of")
	}
	// A record of another name than the one asked is another host's, and names nobody.
	a, _ = Parse(response(t, 9, dnsmessage.RCodeSuccess, v4, [2]string{"66.1.168.192.in-addr.arpa.", "other.lan."}))
	if _, ok := a.Name(v4); ok || !a.Asks(v4) {
		t.Errorf("another address's record taken: %+v", a)
	}
	// An error has no name, whatever records come with it; nor has an answer without one.
	for _, rcode := range []dnsmessage.RCode{dnsmessage.RCodeNameError, dnsmessage.RCodeRefused, dnsmessage.RCodeServerFailure} {
		a, err = Parse(response(t, 9, rcode, v4, [2]string{reverse4, "printer.lan."}))
		if _, ok := a.Name(v4); err != nil || ok || !a.Asks(v4) {
			t.Errorf("an answer with the error %s: %+v, %v", rcode, a, err)
		}
	}
	if a, _ = Parse(response(t, 9, dnsmessage.RCodeSuccess, v4)); !a.Asks(v4) {
		t.Errorf("an empty answer: %+v", a)
	}
	if _, ok := a.Name(v4); ok {
		t.Error("an empty answer names")
	}

	// What can't be read to the end of its answers is nothing.
	whole := response(t, 9, dnsmessage.RCodeSuccess, v4, [2]string{reverse4, "printer.lan."})
	for _, cut := range []int{0, 5, 12, len(whole) - 3} {
		if a, err := Parse(whole[:cut]); err == nil {
			t.Errorf("cut at %d: %+v", cut, a)
		}
	}
	// No question, or two: nothing asked it.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.StartAnswers()
	b.PTRResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(reverse4), Class: dnsmessage.ClassINET}, dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("x.lan.")})
	bare, _ := b.Finish()
	if a, err := Parse(bare); err == nil {
		t.Errorf("an answer without a question: %+v", a)
	}
}

func FuzzParse(f *testing.F) {
	v4 := netip.MustParseAddr("192.168.1.20")
	f.Add(response(f, 9, dnsmessage.RCodeSuccess, v4, [2]string{"20.1.168.192.in-addr.arpa.", "printer.lan."}))
	question, _ := Query(1, netip.MustParseAddr("2001:db8::1"), true)
	f.Add(question)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		a, err := Parse(packet)
		if err != nil && (a.ID != 0 || a.Question != "" || len(a.Names) != 0) {
			t.Errorf("an error with something taken: %+v", a)
		}
		if a.Question == "" && len(a.Names) != 0 {
			t.Errorf("names without a question: %+v", a)
		}
		if name, ok := a.Name(v4); ok && (name == "" || !a.Asks(v4)) {
			t.Errorf("a name %q for an address not asked of: %+v", name, a)
		}
	})
}
