package ssdp

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/internal/onlink"
)

const answer = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://[fe80::20]:49152/description.xml\r\nSERVER: Linux/6 UPnP/1.0 test/1\r\nST: upnp:rootdevice\r\nUSN: uuid:1::upnp:rootdevice\r\n\r\n"

// The description of a device is where the LOCATION of its answer to the search says: of a
// response that says OK, whatever the case of the header.
func TestLocation(t *testing.T) {
	for packet, want := range map[string]string{
		answer: "http://[fe80::20]:49152/description.xml",
		"HTTP/1.1 200 OK\r\nlocation:   http://[fe80::20]/d.xml  \r\n\r\n": "http://[fe80::20]/d.xml",
		"HTTP/1.1 200 OK\r\nLocation: http://[fe80::20]/d.xml\r\n":         "",
		"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n":                   "",
		"HTTP/1.1 200 OK\r\nLOCATION:\r\n\r\n":                             "",
		"HTTP/1.1 404 Not Found\r\nLOCATION: http://[fe80::20]/\r\n\r\n":   "",
		"HTTP/1.1 200 OK\r\n\r\n":                                          "",
		// What a device announces, and what is asked: neither is an answer.
		"NOTIFY * HTTP/1.1\r\nHOST: [ff02::c]:1900\r\nLOCATION: http://[fe80::20]/d.xml\r\n\r\n": "",
		"M-SEARCH * HTTP/1.1\r\nHOST: [ff02::c]:1900\r\n\r\n":                                    "",
		"not HTTP": "",
		"":         "",
	} {
		if got, ok := Location([]byte(packet)); got != want || ok != (want != "") {
			t.Errorf("%q: %q, %v; want %q", packet, got, ok, want)
		}
	}
}

// The description of a device is fetched from the host of the link that answered a search, at
// the very address it answered from, when its name is wanted: and only as the answer to a search
// sent in the last seconds, so that what comes with none sent, or long after, fetches nothing.
func TestNamesTake(t *testing.T) {
	var fetched, wanted []string
	n := &names{link: onlink.Among(netip.MustParsePrefix("2001:db8::1/64")), handler: Names{
		Wants: func(from netip.Addr) bool {
			wanted = append(wanted, from.String())
			return from != netip.MustParseAddr("fe80::30")
		},
	}}
	n.fetch = func(from netip.Addr, port int, path string) {
		fetched = append(fetched, fmt.Sprintf("%s %d %s", from, port, path))
	}
	device := netip.MustParseAddr("fe80::20")
	now := time.Now()

	// No search was sent: what comes answers nothing.
	n.take(device, []byte(answer), now)
	if len(fetched) != 0 || len(wanted) != 0 {
		t.Fatalf("fetched %v, of %v, without a search sent", fetched, wanted)
	}
	n.searched.Store(now.UnixNano())
	at := func(location string) []byte {
		return []byte("HTTP/1.1 200 OK\r\nLOCATION: " + location + "\r\n\r\n")
	}
	n.take(device.WithZone("eth0"), []byte(answer), now.Add(time.Second))
	n.take(netip.MustParseAddr("2001:db8::20"), at("http://[2001:db8::20]/d.xml"), now.Add(time.Second))
	// Elsewhere than the address it came from, by a name, or not plain HTTP: never.
	n.take(device, at("http://[fe80::66]:49152/description.xml"), now.Add(time.Second))
	n.take(device, at("http://device.lan:49152/description.xml"), now.Add(time.Second))
	n.take(device, at("https://[fe80::20]/description.xml"), now.Add(time.Second))
	n.take(device, []byte("NOTIFY * HTTP/1.1\r\nLOCATION: http://[fe80::20]/d.xml\r\n\r\n"), now.Add(time.Second))
	// Not of the link, the interface's own, and one whose name isn't wanted.
	n.take(netip.MustParseAddr("2001:db8:1::20"), at("http://[2001:db8:1::20]/d.xml"), now.Add(time.Second))
	n.take(netip.MustParseAddr("2001:db8::1"), at("http://[2001:db8::1]/d.xml"), now.Add(time.Second))
	n.take(netip.MustParseAddr("fe80::30"), at("http://[fe80::30]/d.xml"), now.Add(time.Second))
	// Long after the search: an answer to nothing.
	n.take(device, []byte(answer), now.Add(answerTimeout+time.Second))
	if want := []string{"fe80::20 49152 /description.xml", "2001:db8::20 80 /d.xml"}; !slices.Equal(fetched, want) {
		t.Errorf("fetched %v, want %v", fetched, want)
	}
	if want := []string{"fe80::20", "2001:db8::20", "fe80::30"}; !slices.Equal(wanted, want) {
		t.Errorf("asked whether wanted of %v, want %v", wanted, want)
	}
}

func description(device string) string {
	return `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion>` + device + `</root>`
}

// The name of a device is the friendlyName of its root device: not one of the devices within.
func TestFriendlyName(t *testing.T) {
	for document, want := range map[string]string{
		description(`<device><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType><friendlyName> Living Room TV </friendlyName><deviceList><device><friendlyName>Embedded</friendlyName></device></deviceList></device>`): "Living Room TV",
		description(`<device><deviceList><device><friendlyName>Embedded</friendlyName></device></deviceList><friendlyName>NAS &amp; more</friendlyName></device>`):                                                                       "NAS & more",
		description(`<device><deviceList><device><friendlyName>Embedded</friendlyName></device></deviceList></device>`):                                                                                                                  "",
		description(`<device><friendlyName></friendlyName></device>`): "",
		description(``):                   "",
		`<root><device><friendlyName>cut`: "",
		`not XML`:                         "",
		``:                                "",
	} {
		if got, ok := FriendlyName([]byte(document)); got != want || ok != (want != "") {
			t.Errorf("%q, %v; want %q, of\n%s", got, ok, want, document)
		}
	}
}

func FuzzNames(f *testing.F) {
	f.Add([]byte(answer), []byte(description(`<device><friendlyName>Living Room TV</friendlyName></device>`)))
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, packet, document []byte) {
		if location, ok := Location(packet); ok && strings.TrimSpace(location) == "" {
			t.Errorf("an empty location, of %q", packet)
		}
		if name, ok := FriendlyName(document); ok && strings.TrimSpace(name) == "" {
			t.Errorf("an empty name, of %q", document)
		}
	})
}
