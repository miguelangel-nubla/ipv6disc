package mdns

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func FuzzParse(f *testing.F) {
	f.Add(message(f, dnsmessage.Header{Response: true}, []record{
		{name: "printer.local.", addr: printer4, ttl: 120, class: flush},
		{name: ReverseName(printer6), ptr: "printer.local.", ttl: 120},
	}, []record{{name: "printer.local.", addr: printer6, ttl: 120}}))
	f.Add(message(f, dnsmessage.Header{ID: 7}, nil, nil))
	f.Add([]byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 1})
	f.Fuzz(func(t *testing.T, packet []byte) {
		m, err := Parse(packet)
		if err != nil {
			if len(m.Records) != 0 {
				t.Errorf("records of a message that can't be read: %+v", m)
			}
			return
		}
		if len(m.Records) > MaxRecords || !m.Response && len(m.Records) != 0 {
			t.Errorf("%d records, response %v", len(m.Records), m.Response)
		}
		for _, r := range m.Records {
			if !r.Addr.IsValid() || r.Addr.Is4In6() || r.Addr.Zone() != "" || r.Name == "" {
				t.Errorf("record %+v", r)
			}
		}
	})
}

func FuzzReverseAddr(f *testing.F) {
	f.Add("20.1.168.192.in-addr.arpa.")
	f.Add(ReverseName(printer6))
	f.Add("...in-addr.arpa.")
	f.Fuzz(func(t *testing.T, name string) {
		addr, ok := reverseAddr(name)
		if !ok {
			return
		}
		// What it reads is an address whose reverse name reads back the same.
		if back, ok := reverseAddr(ReverseName(addr)); !ok || back != addr || addr == (netip.Addr{}) {
			t.Errorf("reverseAddr(%q) = %s, which reads back %s, %v", name, addr, back, ok)
		}
	})
}
