package wsd

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/miguelangel-nubla/ipv6disc/internal/fetch"
	"github.com/miguelangel-nubla/ipv6disc/internal/onlink"
	"github.com/miguelangel-nubla/ipv6disc/internal/udp"
)

// Names is what a Conn that learns names needs of its caller.
type Names struct {
	// Wants tells whether the name of the host at from is to be asked for now: it is not, for
	// one asked a moment ago, or that has a name.
	Wants func(from netip.Addr) bool
	// Named is called with the name of the computer at from, as its metadata has it, fetched
	// from that address.
	Named func(from netip.Addr, name string)
}

const (
	resolveMessage = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <soap:Header>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action>
    <wsa:MessageID>urn:uuid:%s</wsa:MessageID>
  </soap:Header>
  <soap:Body>
    <wsd:Resolve><wsa:EndpointReference><wsa:Address>%s</wsa:Address></wsa:EndpointReference></wsd:Resolve>
  </soap:Body>
</soap:Envelope>
`
	getMessage = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <soap:Header>
    <wsa:To>%s</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>
    <wsa:MessageID>urn:uuid:%s</wsa:MessageID>
    <wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
    <wsa:From><wsa:Address>urn:uuid:%s</wsa:Address></wsa:From>
  </soap:Header>
  <soap:Body />
</soap:Envelope>
`
	// How long the answers to a probe, or to a Resolve, are waited for, and how many wait.
	answerTimeout = 10 * time.Second
	mostWaiting   = 256
	// The longest endpoint address taken: it is a UUID's URN, or a URL.
	maxEndpoint = 256
)

// match is what a ProbeMatch or a ResolveMatch says of a target service: its endpoint, and where
// its metadata is.
type match struct {
	Endpoint string `xml:"EndpointReference>Address"`
	XAddrs   string `xml:"XAddrs"`
}

// answer is what is read of a message that answers a Probe or a Resolve.
type answer struct {
	RelatesTo      string  `xml:"Header>RelatesTo"`
	ProbeMatches   []match `xml:"Body>ProbeMatches>ProbeMatch"`
	ResolveMatches []match `xml:"Body>ResolveMatches>ResolveMatch"`
}

// names is the learning of names of a Conn: what it asked, and waits the answers of.
type names struct {
	// What sends a Resolve to a host, and what fetches the metadata of one: the Conn's, unless
	// a test says.
	send  func(to netip.Addr, message []byte)
	fetch func(from netip.Addr, port int, path, endpoint string)

	conn    *udp.Conn
	iface   *net.Interface
	link    *onlink.Link
	handler Names
	fetcher *fetch.Fetcher
	// What a Get says it is from.
	self string

	mutex sync.Mutex
	// The IDs of the probes sent, and of each Resolve the host it was sent to: what an
	// answer relates to.
	probes   map[string]time.Time
	resolves map[string]resolving
}

type resolving struct {
	addr netip.Addr
	at   time.Time
}

func newNames(iface *net.Interface, handler Names) *names {
	n := &names{iface: iface, link: onlink.Of(iface), handler: handler, fetcher: fetch.New(iface.Name), self: uuid.New().String(),
		probes: make(map[string]time.Time), resolves: make(map[string]resolving)}
	n.send = func(to netip.Addr, message []byte) { _ = n.conn.Send(to, wsDiscoveryPort, message) }
	n.fetch = n.get
	return n
}

// probed keeps the ID of a probe sent, for its answers.
func (n *names) probed(id string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.expire()
	if len(n.probes) < mostWaiting {
		n.probes[id] = time.Now()
	}
}

// expire forgets what was asked too long ago. With the mutex held.
func (n *names) expire() {
	now := time.Now()
	for id, at := range n.probes {
		if now.Sub(at) > answerTimeout {
			delete(n.probes, id)
		}
	}
	for id, r := range n.resolves {
		if now.Sub(r.at) > answerTimeout {
			delete(n.resolves, id)
		}
	}
}

// take is what is done of a message from from, for the name of its sender: the computer's name
// is in the metadata of the device, which it gives over HTTP, at the transport address of its
// endpoint. A ProbeMatch may tell that address, and if not a Resolve sent to the host alone
// asks it; then a WS-Transfer Get there asks the metadata.
//
// Each step is the answer to a question asked: a ProbeMatch to a probe sent in the last seconds,
// a ResolveMatch to the Resolve sent to that very host. And only a host of the link is asked,
// at the address it answered from: of the addresses its answer gives, the first that is that
// address, or that has a name in place of one, as Samba's wsdd2 gives its host name, of which
// only the port and the path are taken. No name is ever resolved, and an address that is
// another's never connected to.
func (n *names) take(from netip.Addr, packet []byte) {
	from = from.Unmap().WithZone("")
	if !n.link.Has(from) {
		return
	}
	var a answer
	if err := xmlUnmarshal(packet, &a); err != nil || a.RelatesTo == "" {
		return
	}
	related := strings.TrimSpace(a.RelatesTo)
	n.mutex.Lock()
	n.expire()
	_, probed := n.probes[related]
	resolve, resolved := n.resolves[related]
	if resolved && resolve.addr == from {
		delete(n.resolves, related)
	} else {
		resolved = false
	}
	n.mutex.Unlock()

	var matches []match
	switch {
	case probed && len(a.ProbeMatches) > 0:
		matches = a.ProbeMatches
	case resolved && len(a.ResolveMatches) > 0:
		matches = a.ResolveMatches
	default:
		return
	}
	// A host is one device here: its first.
	m := matches[0]
	endpoint := strings.TrimSpace(m.Endpoint)
	if endpoint == "" || len(endpoint) > maxEndpoint {
		return
	}
	for _, address := range strings.Fields(m.XAddrs) {
		if port, path, ok := fetch.Target(address, from, true); ok {
			// One it was asked the address of was wanted then.
			if resolved || n.handler.Wants(from) {
				n.fetch(from, port, path, endpoint)
			}
			return
		}
	}
	// No address of its own in a ProbeMatch: it is asked. A ResolveMatch without is the end.
	if resolved || !n.handler.Wants(from) {
		return
	}
	id := uuid.New().String()
	n.mutex.Lock()
	if len(n.resolves) < mostWaiting {
		n.resolves[uuidURN(id)] = resolving{from, time.Now()}
	}
	n.mutex.Unlock()
	n.send(from, fmt.Appendf(nil, resolveMessage, id, escape(endpoint)))
}

// get asks the device at from for its metadata, and tells the computer's name it has.
func (n *names) get(from netip.Addr, port int, path, endpoint string) {
	body := fmt.Appendf(nil, getMessage, escape(endpoint), uuid.New().String(), n.self)
	n.fetcher.Go(from, port, path, "application/soap+xml", body, func(document []byte) {
		if name, ok := computerName(document); ok {
			n.handler.Named(from, name)
		}
	})
}

func uuidURN(id string) string { return "urn:uuid:" + id }

func escape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// computerName is the name of the computer a device's metadata is of: what the Computer element
// of its host relationship has before the workgroup or the domain, "NAME/Workgroup:WORKGROUP" or
// "NAME\Domain:DOMAIN", as Windows gives it, and Samba's wsdd. A device that is no computer, as
// a printer, has none: its friendly name is a model's, and is left.
func computerName(document []byte) (string, bool) {
	decoder := xml.NewDecoder(bytes.NewReader(document))
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", false
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "Computer" {
			continue
		}
		var text string
		if err := decoder.DecodeElement(&text, &start); err != nil {
			return "", false
		}
		name, _, _ := strings.Cut(strings.TrimSpace(text), "/")
		name, _, _ = strings.Cut(name, `\`)
		return name, name != ""
	}
}

// xmlUnmarshal reads a document whose elements are told by their names alone, whatever the
// prefixes of their namespaces.
func xmlUnmarshal(document []byte, into any) error {
	return xml.Unmarshal(document, into)
}
