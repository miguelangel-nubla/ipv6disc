package netbios

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/miguelangel-nubla/ipv6disc/internal/onlink"
)

// The question is a node status request for the name any node answers for, as nmblookup -A
// sends it.
func TestQuery(t *testing.T) {
	want := append([]byte{0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20}, "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"...)
	want = append(want, 0, 0, 0x21, 0, 1)
	if got := query(0x1234); !bytes.Equal(got, want) {
		t.Errorf("query:\n% x\nwant\n% x", got, want)
	}
}

type nodeName struct {
	name   string
	suffix byte
	flags  uint16
}

// response is a node status response with those names, as a node sends it.
func response(id uint16, flags uint16, names ...nodeName) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = binary.BigEndian.AppendUint16(b, flags)
	b = append(b, 0, 0, 0, 1, 0, 0, 0, 0)
	b = append(b, statusNameBytes()...)
	b = append(b, 0, 0x21, 0, 1, 0, 0, 0, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(1+18*len(names)+46))
	b = append(b, byte(len(names)))
	for _, n := range names {
		b = append(b, fmt.Appendf(nil, "%-15s", n.name)...)
		b = append(b, n.suffix)
		b = binary.BigEndian.AppendUint16(b, n.flags)
	}
	// The statistics, which start with the MAC of the node: Samba's is all zeros.
	return append(b, make([]byte, 46)...)
}

func statusNameBytes() []byte { return statusName }

// What Samba's nmbd answers, and Windows: the machine's name for each of its services, and its
// workgroup.
var machine = []nodeName{
	{"TESTGROUP", 0x00, 0x8400},
	{"WINBOX-P", 0x03, 0x0400},
	{"WINBOX-P", 0x00, 0x0400},
	{"WINBOX-P", 0x20, 0x0400},
	{"TESTGROUP", 0x1e, 0x8400},
}

func TestParse(t *testing.T) {
	for name, c := range map[string]struct {
		packet []byte
		want   string
		fails  bool
	}{
		"a machine":                {response(7, 0x8400, machine...), "WINBOX-P", false},
		"a group alone":            {response(7, 0x8400, nodeName{"TESTGROUP", 0x00, 0x8400}), "", false},
		"a name in conflict":       {response(7, 0x8400, nodeName{"CLASH", 0x00, 0x0c00}), "", false},
		"a name being released":    {response(7, 0x8400, nodeName{"GOING", 0x00, 0x1400}), "", false},
		"a name not registered":    {response(7, 0x8400, nodeName{"PENDING", 0x00, 0x0000}), "", false},
		"no workstation name":      {response(7, 0x8400, nodeName{"SERVER", 0x20, 0x0400}), "", false},
		"no names":                 {response(7, 0x8400), "", false},
		"a request":                {response(7, 0x0000, machine...), "", true},
		"an error":                 {response(7, 0x8403, machine...), "", true},
		"another operation":        {response(7, 0xa800, machine...), "", true},
		"cut within its names":     {response(7, 0x8400, machine...)[:80], "", true},
		"cut within its header":    {response(7, 0x8400, machine...)[:11], "", true},
		"more names than it holds": {append(response(7, 0x8400)[:56], 0, 1, 9), "", true},
		"empty":                    {nil, "", true},
	} {
		got, err := Parse(c.packet)
		if (err != nil) != c.fails || got.Name != c.want || err == nil && got.ID != 7 {
			t.Errorf("%s: %+v, %v; want the name %q, failing %v", name, got, err, c.want, c.fails)
		}
	}
	// The name of the record can be a pointer, and a record of another type is no status.
	pointed := response(7, 0x8400, machine...)
	pointed = append(append(slices.Clone(pointed[:12]), 0xc0, 0x0c), pointed[12+34:]...)
	if got, err := Parse(pointed); err != nil || got.Name != "WINBOX-P" {
		t.Errorf("a name given by a pointer: %+v, %v", got, err)
	}
	other := response(7, 0x8400, machine...)
	other[12+34+1] = 0x20
	if _, err := Parse(other); err == nil {
		t.Error("a record that is no node status was read as one")
	}
}

// An answer is taken only as the answer to a question asked: with its ID, from the address it
// was sent to, and from the port of NetBIOS. Anything else names nobody, and leaves the question
// waiting for its answer, which is taken once.
func TestConnTakesOnlyAnswers(t *testing.T) {
	var answers []string
	conn := &Conn{iface: &net.Interface{Name: "eth0"}, link: onlink.Among(netip.MustParsePrefix("192.168.1.5/24")),
		handler: Handler{Answered: func(asked netip.Addr, name string) { answers = append(answers, asked.String()+" "+name) }}}
	host, other := netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("192.168.1.66")
	id := conn.asked.Ask(host)

	conn.take(netip.AddrPortFrom(host, Port), response(id+1, 0x8400, machine...))
	conn.take(netip.AddrPortFrom(other, Port), response(id, 0x8400, nodeName{"EVIL", 0x00, 0x0400}))
	conn.take(netip.AddrPortFrom(host, 4000), response(id, 0x8400, nodeName{"EVIL", 0x00, 0x0400}))
	conn.take(netip.AddrPortFrom(host, Port), query(id))
	conn.take(netip.AddrPortFrom(host, Port), []byte("not NetBIOS"))
	if len(answers) != 0 || conn.PacketsReceived.Load() != 0 {
		t.Fatalf("taken without being the answer to the question: %v", answers)
	}
	conn.take(netip.AddrPortFrom(host, Port), response(id, 0x8400, machine...))
	conn.take(netip.AddrPortFrom(host, Port), response(id, 0x8400, nodeName{"AGAIN", 0x00, 0x0400}))
	if want := []string{"192.168.1.20 WINBOX-P"}; !slices.Equal(answers, want) || conn.PacketsReceived.Load() != 1 || conn.HostsFound.Load() != 1 {
		t.Errorf("answers %v, want %v, once", answers, want)
	}
	// One without a name answers the question too, and names nobody.
	id = conn.asked.Ask(host)
	conn.take(netip.AddrPortFrom(host, Port), response(id, 0x8400))
	if len(answers) != 1 || conn.PacketsReceived.Load() != 2 || conn.asked.Waiting() != 0 {
		t.Errorf("an answer without a name: %v, %d taken", answers, conn.PacketsReceived.Load())
	}
}

// Only an IPv4 host of the interface's link is asked.
func TestAsks(t *testing.T) {
	conn := &Conn{iface: &net.Interface{Name: "eth0"}, link: onlink.Among(netip.MustParsePrefix("192.168.1.5/24"), netip.MustParsePrefix("2001:db8::5/64"))}
	for addr, want := range map[string]bool{
		"192.168.1.20": true, "::ffff:192.168.1.20": true, "192.168.1.5": false, "10.0.0.1": false,
		"2001:db8::20": false, "fe80::1": false, "224.0.0.1": false, "0.0.0.0": false,
	} {
		if got := conn.Asks(netip.MustParseAddr(addr)); got != want {
			t.Errorf("asks %s: %v, want %v", addr, got, want)
		}
	}
	if err := conn.AskName(netip.MustParseAddr("10.0.0.1")); err == nil || conn.PacketsSent.Load() != 0 || conn.asked.Waiting() != 0 {
		t.Errorf("a host off the link asked: %v", err)
	}
}

// Listen opens one socket, on a port of its own, and Close ends its reading: nothing is sent
// before a host is asked.
func TestListen(t *testing.T) {
	lo, err := net.InterfaceByName(loopbackName(t))
	if err != nil {
		t.Skip(err)
	}
	conn, err := Listen(lo, Handler{Error: func(err error) { t.Error(err) }})
	if err != nil {
		t.Fatal(err)
	}
	if port := conn.closer.LocalAddr().(*net.UDPAddr).Port; port == Port || port == 0 {
		t.Errorf("listening on port %d", port)
	}
	if err := conn.Close(); err != nil {
		t.Error(err)
	}
	if stats := conn.Stats(); stats["sent"] != uint64(0) || stats["recv"] != uint64(0) {
		t.Errorf("stats: %v", stats)
	}
}

func loopbackName(t *testing.T) string {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Name
		}
	}
	t.Skip("no loopback interface")
	return ""
}

func FuzzParse(f *testing.F) {
	f.Add(response(7, 0x8400, machine...))
	f.Add(response(7, 0x8400))
	f.Add(query(1))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		status, err := Parse(packet)
		if err != nil && status != (Status{}) {
			t.Errorf("an error with something taken: %+v", status)
		}
		if len(status.Name) > nameLen-1 {
			t.Errorf("a name longer than a NetBIOS name: %q", status.Name)
		}
	})
}
