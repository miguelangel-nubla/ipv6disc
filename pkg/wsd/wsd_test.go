package wsd

import (
	"encoding/xml"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestProbeMessage(t *testing.T) {
	type envelope struct {
		XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"`
		Header  struct {
			To        string `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing To"`
			Action    string `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing Action"`
			MessageID string `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing MessageID"`
		} `xml:"http://www.w3.org/2003/05/soap-envelope Header"`
		Body struct {
			Probe *struct{} `xml:"http://schemas.xmlsoap.org/ws/2005/04/discovery Probe"`
		} `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
	}
	ids := map[string]bool{}
	for range 2 {
		var got envelope
		if err := xml.Unmarshal(probeMessage(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Header.To != "urn:schemas-xmlsoap-org:ws:2005:04:discovery" {
			t.Errorf("To: %q", got.Header.To)
		}
		if got.Header.Action != "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe" {
			t.Errorf("Action: %q", got.Header.Action)
		}
		id, ok := strings.CutPrefix(got.Header.MessageID, "urn:uuid:")
		if _, err := uuid.Parse(id); !ok || err != nil {
			t.Errorf("MessageID: %q", got.Header.MessageID)
		}
		ids[got.Header.MessageID] = true
		if got.Body.Probe == nil {
			t.Error("no Probe in the body")
		}
	}
	// Each probe has its own: a service answers a message ID once.
	if len(ids) != 2 {
		t.Errorf("message IDs: %v", ids)
	}
}

func TestMulticastAddress(t *testing.T) {
	if wsDiscoveryMulticastAddress != netip.MustParseAddr("ff02::c") || !wsDiscoveryMulticastAddress.IsLinkLocalMulticast() || wsDiscoveryPort != 3702 {
		t.Errorf("WS-Discovery goes to %s port %d", wsDiscoveryMulticastAddress, wsDiscoveryPort)
	}
}
