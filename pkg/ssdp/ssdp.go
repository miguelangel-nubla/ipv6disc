package ssdp

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/internal/fetch"
	"github.com/miguelangel-nubla/ipv6disc/internal/onlink"
	"github.com/miguelangel-nubla/ipv6disc/internal/udp"
)

const ssdpPort = 1900

// The link-local scope SSDP multicast address.
var ssdpMulticastAddress = netip.MustParseAddr("ff02::c")

type Conn struct {
	*udp.Conn
	// What fetches the descriptions, when names were asked for: nil without.
	fetcher *fetch.Fetcher
	// When the last search was sent, for the answers that are to it.
	searched *atomic.Int64
}

// answerTimeout is how long after a search what comes is an answer to it: a device waits up to
// the three seconds of its MX before it answers.
const answerTimeout = 10 * time.Second

// DiscoverMulticast asks every SSDP device on the link to announce itself.
func (conn *Conn) DiscoverMulticast() error {
	conn.DiscoveryRuns.Add(1)
	return conn.SendSSDPRequest(&ssdpMulticastAddress)
}

// SendSSDPRequest sends the search to target, out of the listener's interface whatever the zone
// of target.
func (conn *Conn) SendSSDPRequest(target *netip.Addr) error {
	if conn.searched != nil {
		conn.searched.Store(time.Now().UnixNano())
	}
	return conn.Send(*target, ssdpPort, searchMessage(*target))
}

// searchMessage is an M-SEARCH request for every device and service. Its Host header is the
// address it is sent to, without its zone, which is this machine's name for the link, and as an
// HTTP request its lines end in CRLF, with an empty one last.
func searchMessage(target netip.Addr) []byte {
	host := net.JoinHostPort(target.WithZone("").String(), strconv.Itoa(ssdpPort))
	return fmt.Appendf(nil, "M-SEARCH * HTTP/1.1\r\nHOST: %s\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n", host)
}

func ListenForSSDP(iface *net.Interface, addr netip.Addr, onFoundAddr func(netip.Addr) bool, onError func(error)) (*Conn, error) {
	conn, err := udp.Listen(iface, addr, onFoundAddr, onError)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for SSDP packets: %w", err)
	}
	return &Conn{Conn: conn}, nil
}

// Names is what a Conn that learns names needs of its caller.
type Names struct {
	// Wants tells whether the name of the host at from is to be asked for now: it is not, for
	// one asked a moment ago, or that has a name.
	Wants func(from netip.Addr) bool
	// Named is called with the friendly name of the device at from, as its description has
	// it, fetched from that address.
	Named func(from netip.Addr, name string)
}

// ListenForSSDPNames is ListenForSSDP, which also learns the name each device that answers the
// search gives itself: the friendlyName of the description its answer points to, by one HTTP
// request to the address it answered from, bounded as internal/fetch says.
//
// Only a host of the link is asked, and only when the LOCATION of its answer is at the very
// address it answered from, written as an address: a description elsewhere is never fetched,
// and no name resolved. And only in the seconds after a search was sent, as its answer: the
// socket takes what anyone sends it, whenever, and a search has nothing an answer must repeat,
// so what comes with none sent, as when nothing probes, fetches nothing. A host of the link can
// still write another's address as the source of an answer to a search it heard, and that one is
// then asked for a document, at a port and a path of the writer's choosing: once, by the bounds
// of Names.Wants, and what comes of it is told to nobody but as that host's name.
func ListenForSSDPNames(iface *net.Interface, addr netip.Addr, onFoundAddr func(netip.Addr) bool, handler Names, onError func(error)) (*Conn, error) {
	fetcher := fetch.New(iface.Name)
	n := &names{link: onlink.Of(iface), handler: handler}
	n.fetch = func(from netip.Addr, port int, path string) {
		fetcher.Go(from, port, path, "", nil, func(document []byte) {
			if name, ok := FriendlyName(document); ok {
				handler.Named(from, name)
			}
		})
	}
	conn, err := udp.ListenPackets(iface, addr, func(from netip.Addr, packet []byte) bool {
		n.take(from, packet, time.Now())
		return onFoundAddr(from)
	}, onError)
	if err != nil {
		fetcher.Close()
		return nil, fmt.Errorf("failed to listen for SSDP packets: %w", err)
	}
	return &Conn{Conn: conn, fetcher: fetcher, searched: &n.searched}, nil
}

// names is the learning of names of a Conn.
type names struct {
	link    *onlink.Link
	handler Names
	// What fetches the description of the device at from: the Conn's, unless a test says.
	fetch func(from netip.Addr, port int, path string)
	// When the last search was sent, in nanoseconds: zero when none was.
	searched atomic.Int64
}

// take is what is done of a packet from from, at now, for the name of its sender.
func (n *names) take(from netip.Addr, packet []byte, now time.Time) {
	from = from.Unmap().WithZone("")
	if !answers(n.searched.Load(), now) || !n.link.Has(from) {
		return
	}
	location, ok := Location(packet)
	if !ok {
		return
	}
	if port, path, ok := fetch.Target(location, from, false); ok && n.handler.Wants(from) {
		n.fetch(from, port, path)
	}
}

// answers tells whether what comes at now can be the answer to the last search, sent at
// searched, in nanoseconds: zero when none was.
func answers(searched int64, now time.Time) bool {
	return searched != 0 && now.Sub(time.Unix(0, searched)) <= answerTimeout
}

// Close ends the listening, and what is being fetched.
func (conn *Conn) Close() error {
	err := conn.Conn.Close()
	if conn.fetcher != nil {
		conn.fetcher.Close()
	}
	return err
}

// Location is where the answer to a search says the description of its device is: the LOCATION
// header of a response that says OK.
func Location(packet []byte) (string, bool) {
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(packet)), nil)
	if err != nil {
		return "", false
	}
	response.Body.Close()
	location := strings.TrimSpace(response.Header.Get("Location"))
	if response.StatusCode != http.StatusOK || location == "" {
		return "", false
	}
	return location, true
}

// FriendlyName is the name a device's description gives it: the friendlyName of its root device.
func FriendlyName(document []byte) (string, bool) {
	var description struct {
		Device struct {
			FriendlyName string `xml:"friendlyName"`
		} `xml:"device"`
	}
	if err := xml.Unmarshal(document, &description); err != nil {
		return "", false
	}
	name := strings.TrimSpace(description.Device.FriendlyName)
	return name, name != ""
}
