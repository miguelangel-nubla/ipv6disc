package wsd

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/internal/onlink"
)

// matches is what a target service answers a Probe, or a Resolve, with: as Samba's wsdd2 does.
func matches(kind, relatesTo, endpoint, xaddrs string) []byte {
	if xaddrs != "" {
		xaddrs = "<wsd:XAddrs>" + xaddrs + "</wsd:XAddrs>"
	}
	return fmt.Appendf(nil, `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/%[1]ses</wsa:Action><wsa:MessageID>urn:uuid:a52b57fa-88fa-5770-eb5b-53ffb9e2b746</wsa:MessageID><wsa:RelatesTo>%[2]s</wsa:RelatesTo></soap:Header><soap:Body><wsd:%[1]ses><wsd:%[1]s><wsa:EndpointReference><wsa:Address>%[3]s</wsa:Address></wsa:EndpointReference><wsd:Types>wsdp:Device pub:Computer</wsd:Types>%[4]s<wsd:MetadataVersion>2</wsd:MetadataVersion></wsd:%[1]s></wsd:%[1]ses></soap:Body></soap:Envelope>`, kind, relatesTo, endpoint, xaddrs)
}

// testNames is the learning of names of a listener on a link, which records what it would send
// and fetch.
type testNames struct {
	*names
	sent, fetched []string
	wants         bool
}

func newTestNames() *testNames {
	n := &testNames{wants: true}
	n.names = newNames(&net.Interface{Name: "eth0"}, Names{Wants: func(netip.Addr) bool { return n.wants }})
	n.link = onlink.Among(netip.MustParsePrefix("2001:db8::5/64"))
	n.send = func(to netip.Addr, message []byte) { n.sent = append(n.sent, to.String()+" "+string(message)) }
	n.fetch = func(from netip.Addr, port int, path, endpoint string) {
		n.fetched = append(n.fetched, fmt.Sprintf("%s %d %s %s", from, port, path, endpoint))
	}
	return n
}

const (
	probeID  = "urn:uuid:11111111-1111-4111-8111-111111111111"
	endpoint = "urn:uuid:07048606-4e29-49e1-9aa1-13aaaf819b8f"
)

// The name of a computer is asked of the host that answered a probe, at the address it answered
// from, and nowhere else: by the address its answer gives, when it is that one, or has a name in
// its place; and otherwise by a Resolve sent to it alone, whose answer is its own.
func TestNamesTake(t *testing.T) {
	host, other := netip.MustParseAddr("2001:db8::20"), netip.MustParseAddr("2001:db8::66")
	linkLocal := netip.MustParseAddr("fe80::20")

	n := newTestNames()
	defer n.fetcher.Close()
	// Before any probe: an answer is to nothing.
	n.take(host, matches("ProbeMatch", probeID, endpoint, "http://[2001:db8::20]:5357/uuid"))
	n.probed(probeID)
	for name, c := range map[string]struct {
		from   netip.Addr
		packet []byte
	}{
		"to another probe":       {host, matches("ProbeMatch", "urn:uuid:22222222-2222-4222-8222-222222222222", endpoint, "http://[2001:db8::20]:5357/uuid")},
		"related to nothing":     {host, matches("ProbeMatch", "", endpoint, "http://[2001:db8::20]:5357/uuid")},
		"from off the link":      {netip.MustParseAddr("2001:db8:ffff::9"), matches("ProbeMatch", probeID, endpoint, "http://[2001:db8:ffff::9]:5357/uuid")},
		"from the interface":     {netip.MustParseAddr("2001:db8::5"), matches("ProbeMatch", probeID, endpoint, "http://[2001:db8::5]:5357/uuid")},
		"what is no message":     {host, []byte("HTTP/1.1 200 OK\r\n\r\n")},
		"a ResolveMatch unasked": {host, matches("ResolveMatch", probeID, endpoint, "http://[2001:db8::20]:5357/uuid")},
		"without an endpoint":    {host, matches("ProbeMatch", probeID, "", "http://[2001:db8::20]:5357/uuid")},
		"an endpoint too long":   {host, matches("ProbeMatch", probeID, "urn:"+strings.Repeat("x", maxEndpoint), "http://[2001:db8::20]:5357/uuid")},
	} {
		n.take(c.from, c.packet)
		if len(n.sent)+len(n.fetched) != 0 {
			t.Fatalf("%s: sent %q, fetched %q", name, n.sent, n.fetched)
		}
	}

	// Its own address among those it gives: fetched there, whatever else it lists.
	n.take(host, matches("ProbeMatch", " "+probeID+" ", " "+endpoint+" ", "http://[2001:db8::66]:5357/other http://192.168.1.20:5357/v4 http://[2001:db8::20]:5357/uuid"))
	// A name in place of its address, as wsdd2 gives: its port and path, at the address it
	// answered from, here its link-local one.
	n.take(linkLocal.WithZone("eth0"), matches("ProbeMatch", probeID, endpoint, "http://winbox:3702/uuid"))
	if want := []string{"2001:db8::20 5357 /uuid " + endpoint, "fe80::20 3702 /uuid " + endpoint}; !slices.Equal(n.fetched, want) || len(n.sent) != 0 {
		t.Fatalf("fetched %q, want %q; sent %q", n.fetched, want, n.sent)
	}

	// No address of its own: asked for it, by a Resolve to that host alone, with its endpoint.
	n.fetched = nil
	hostile := `urn:x"><evil a="`
	n.take(host, matches("ProbeMatch", probeID, "urn:x&quot;&gt;&lt;evil a=&quot;", ""))
	n.take(other, matches("ProbeMatch", probeID, endpoint, "http://[2001:db8::20]:5357/of-another"))
	if len(n.sent) != 2 || len(n.fetched) != 0 || !strings.HasPrefix(n.sent[0], "2001:db8::20 ") || !strings.HasPrefix(n.sent[1], "2001:db8::66 ") {
		t.Fatalf("sent %q, fetched %q: want a Resolve to each", n.sent, n.fetched)
	}
	var resolve struct {
		Action    string `xml:"Header>Action"`
		MessageID string `xml:"Header>MessageID"`
		Endpoint  string `xml:"Body>Resolve>EndpointReference>Address"`
	}
	decode(t, strings.SplitN(n.sent[0], " ", 2)[1], &resolve)
	if resolve.Action != "http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve" || resolve.Endpoint != hostile || !strings.HasPrefix(resolve.MessageID, "urn:uuid:") {
		t.Errorf("the Resolve: %+v", resolve)
	}
	// Its answer: from another host, or to another Resolve, it is nothing; from that host, it
	// tells where, once. And one that tells nothing of its own is the end: no other is sent.
	n.sent = nil
	n.take(other, matches("ResolveMatch", resolve.MessageID, hostile, "http://[2001:db8::66]:5357/spoofed"))
	n.take(host, matches("ResolveMatch", probeID, hostile, "http://[2001:db8::20]:5357/of-the-probe"))
	if len(n.fetched) != 0 {
		t.Fatalf("fetched by an answer that is not the host's to its Resolve: %q", n.fetched)
	}
	n.take(host, matches("ResolveMatch", resolve.MessageID, "urn:x&quot;&gt;&lt;evil a=&quot;", "http://[2001:db8::20]:5357/resolved"))
	n.take(host, matches("ResolveMatch", resolve.MessageID, endpoint, "http://[2001:db8::20]:5357/again"))
	if want := []string{"2001:db8::20 5357 /resolved " + hostile}; !slices.Equal(n.fetched, want) || len(n.sent) != 0 {
		t.Errorf("fetched %q, want %q; sent %q", n.fetched, want, n.sent)
	}

	// A host whose name isn't wanted is neither asked nor fetched from.
	n.fetched, n.wants = nil, false
	n.take(host, matches("ProbeMatch", probeID, endpoint, "http://[2001:db8::20]:5357/uuid"))
	n.take(host, matches("ProbeMatch", probeID, endpoint, ""))
	if len(n.sent)+len(n.fetched) != 0 {
		t.Errorf("a host whose name isn't wanted: sent %q, fetched %q", n.sent, n.fetched)
	}

	// The answers to a probe are waited for a while, and those to a Resolve: then they are to
	// nothing.
	n.wants = true
	n.mutex.Lock()
	n.probes[probeID] = time.Now().Add(-answerTimeout - time.Second)
	n.mutex.Unlock()
	n.take(host, matches("ProbeMatch", probeID, endpoint, "http://[2001:db8::20]:5357/late"))
	if len(n.fetched) != 0 {
		t.Errorf("an answer to a probe of long ago: %q", n.fetched)
	}
}

func decode(t *testing.T, document string, into any) {
	t.Helper()
	if err := xmlUnmarshal([]byte(document), into); err != nil {
		t.Fatalf("%v:\n%s", err, document)
	}
}

// The metadata is asked for by a WS-Transfer Get, to the endpoint, and the computer's name is
// what its host relationship has before the workgroup, or the domain.
func TestNamesGet(t *testing.T) {
	var request struct {
		method, contentType, path string
		To                        string `xml:"Header>To"`
		Action                    string `xml:"Header>Action"`
		MessageID                 string `xml:"Header>MessageID"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		request.method, request.contentType, request.path = r.Method, r.Header.Get("Content-Type"), r.URL.Path
		if err := xmlUnmarshal(body, &request); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/soap+xml")
		io.WriteString(w, metadata("WINBOX-P/Workgroup:TESTGROUP"))
	}))
	defer server.Close()
	addr := server.Listener.Addr().(*net.TCPAddr).AddrPort()

	named := make(chan string, 1)
	n := newNames(&net.Interface{Name: "lo"}, Names{Named: func(from netip.Addr, name string) { named <- from.String() + " " + name }})
	n.get(addr.Addr(), int(addr.Port()), "/uuid", `urn:uuid:<&>`)
	select {
	case got := <-named:
		if got != addr.Addr().String()+" WINBOX-P" {
			t.Errorf("named %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no name")
	}
	n.fetcher.Close()
	if request.method != "POST" || request.contentType != "application/soap+xml" || request.path != "/uuid" || request.To != "urn:uuid:<&>" ||
		request.Action != "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get" || !strings.HasPrefix(request.MessageID, "urn:uuid:") {
		t.Errorf("the request: %+v", request)
	}
}

func metadata(computer string) string {
	return `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsx="http://schemas.xmlsoap.org/ws/2004/09/mex" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof" xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07"><soap:Body><wsx:Metadata><wsx:MetadataSection Dialect="http://schemas.xmlsoap.org/ws/2006/02/devprof/ThisDevice"><wsdp:ThisDevice><wsdp:FriendlyName>WSD Device WINBOX-P</wsdp:FriendlyName></wsdp:ThisDevice></wsx:MetadataSection><wsx:MetadataSection Dialect="http://schemas.xmlsoap.org/ws/2006/02/devprof/Relationship"><wsdp:Relationship Type="http://schemas.xmlsoap.org/ws/2006/02/devprof/host"><wsdp:Host><wsa:EndpointReference xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"><wsa:Address>urn:uuid:07048606</wsa:Address></wsa:EndpointReference><wsdp:Types>pub:Computer</wsdp:Types><wsdp:ServiceId>urn:uuid:07048606</wsdp:ServiceId><pub:Computer>` + computer + `</pub:Computer></wsdp:Host></wsdp:Relationship></wsx:MetadataSection></wsx:Metadata></soap:Body></soap:Envelope>`
}

func TestComputerName(t *testing.T) {
	for document, want := range map[string]string{
		metadata("WINBOX-P/Workgroup:TESTGROUP"):   "WINBOX-P",
		metadata(`WINBOX-P\Domain:EXAMPLE`):        "WINBOX-P",
		metadata(" winbox-p/Workgroup:WORKGROUP "): "winbox-p",
		metadata("winbox-p"):                       "winbox-p",
		metadata("/Workgroup:WORKGROUP"):           "",
		metadata(""):                               "",
		// A device that is no computer has a friendly name alone, which is a model's.
		`<Envelope><Body><Metadata><ThisDevice><FriendlyName>HP LaserJet</FriendlyName></ThisDevice></Metadata></Body></Envelope>`: "",
		`<Envelope><Computer>cut`: "",
		`not XML`:                 "",
		``:                        "",
	} {
		if got, ok := computerName([]byte(document)); got != want || ok != (want != "") {
			t.Errorf("%q, %v; want %q, of\n%s", got, ok, want, document)
		}
	}
}

func FuzzNames(f *testing.F) {
	f.Add(matches("ProbeMatch", probeID, endpoint, "http://[2001:db8::20]:5357/uuid"), []byte(metadata("WINBOX-P/Workgroup:TESTGROUP")))
	f.Add(matches("ResolveMatch", probeID, endpoint, ""), []byte{})
	f.Fuzz(func(t *testing.T, packet, document []byte) {
		n := newTestNames()
		defer n.fetcher.Close()
		n.probed(probeID)
		host := netip.MustParseAddr("2001:db8::20")
		n.take(host, packet)
		// Whatever it says, only that host is asked, or fetched from.
		for _, sent := range slices.Concat(n.sent, n.fetched) {
			if !strings.HasPrefix(sent, "2001:db8::20 ") {
				t.Errorf("asked of another host: %q", sent)
			}
		}
		if name, ok := computerName(document); ok && (name == "" || strings.ContainsAny(name, `/\`)) {
			t.Errorf("the name %q", name)
		}
	})
}
