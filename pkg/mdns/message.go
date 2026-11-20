package mdns

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Record is what a response says of a name: that it has an address. By an A or an AAAA record of
// the name, or, PTR, by the PTR record of the address's reverse name, which points to it.
type Record struct {
	// The name as the record has it, whole and with its last dot: host.local.
	Name string
	Addr netip.Addr
	PTR  bool
}

// Message is what is taken of an mDNS message.
type Message struct {
	ID       uint16
	Response bool
	// The records of a response, of its answers and its additional ones. A query has none here:
	// the answers it carries are those its sender already knows, of other hosts, and the
	// authorities of a probe what it would like to be.
	Records []Record
}

// MaxRecords bounds the records taken of a message: what follows them is left.
const MaxRecords = 32

// The top bit of a record's class is no class in mDNS: the cache-flush bit (RFC 6762 10.2), and
// in a question the one that asks for a unicast response (5.4).
const classMask = 0x7fff

// Parse reads an mDNS message. One that can't be read to its end is an error, with nothing
// taken of it. A record with a TTL of zero, a goodbye, says the name is going, not that it is
// there, and is left out, as those of another class than IN.
func Parse(packet []byte) (Message, error) {
	var p dnsmessage.Parser
	header, err := p.Start(packet)
	if err != nil {
		return Message{}, err
	}
	m := Message{ID: header.ID, Response: header.Response}
	if err := p.SkipAllQuestions(); err != nil {
		return Message{}, err
	}

	section := func(next func() (dnsmessage.ResourceHeader, error), skip func() error) error {
		for {
			h, err := next()
			if errors.Is(err, dnsmessage.ErrSectionDone) {
				return nil
			}
			if err != nil {
				return err
			}
			if !m.Response || h.Class&classMask != dnsmessage.ClassINET || h.TTL == 0 || len(m.Records) >= MaxRecords {
				if err := skip(); err != nil {
					return err
				}
				continue
			}
			switch h.Type {
			case dnsmessage.TypeA:
				r, err := p.AResource()
				if err != nil {
					return err
				}
				m.Records = append(m.Records, Record{Name: h.Name.String(), Addr: netip.AddrFrom4(r.A)})
			case dnsmessage.TypeAAAA:
				r, err := p.AAAAResource()
				if err != nil {
					return err
				}
				m.Records = append(m.Records, Record{Name: h.Name.String(), Addr: netip.AddrFrom16(r.AAAA).Unmap()})
			case dnsmessage.TypePTR:
				r, err := p.PTRResource()
				if err != nil {
					return err
				}
				// The other PTR records are of services.
				if addr, ok := reverseAddr(h.Name.String()); ok {
					m.Records = append(m.Records, Record{Name: r.PTR.String(), Addr: addr, PTR: true})
				}
			default:
				if err := skip(); err != nil {
					return err
				}
			}
		}
	}
	if err := section(p.AnswerHeader, p.SkipAnswer); err != nil {
		return Message{}, err
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return Message{}, err
	}
	if err := section(p.AdditionalHeader, p.SkipAdditional); err != nil {
		return Message{}, err
	}
	return m, nil
}

// ReverseName is the name whose PTR record tells the name of the host at addr:
// 2.1.168.192.in-addr.arpa., or the 32 nibbles of an IPv6 address under ip6.arpa.
func ReverseName(addr netip.Addr) string {
	addr = addr.Unmap().WithZone("")
	var b strings.Builder
	if addr.Is4() {
		a := addr.As4()
		for i := 3; i >= 0; i-- {
			b.WriteString(strconv.Itoa(int(a[i])))
			b.WriteByte('.')
		}
		b.WriteString("in-addr.arpa.")
		return b.String()
	}
	const digits = "0123456789abcdef"
	a := addr.As16()
	for i := 15; i >= 0; i-- {
		b.WriteByte(digits[a[i]&0xf])
		b.WriteByte('.')
		b.WriteByte(digits[a[i]>>4])
		b.WriteByte('.')
	}
	b.WriteString("ip6.arpa.")
	return b.String()
}

// reverseAddr is the address a reverse name is of, if it is one.
func reverseAddr(name string) (netip.Addr, bool) {
	name = strings.ToLower(name)
	if rest, ok := strings.CutSuffix(name, ".in-addr.arpa."); ok {
		labels := strings.Split(rest, ".")
		if len(labels) != 4 {
			return netip.Addr{}, false
		}
		addr, err := netip.ParseAddr(labels[3] + "." + labels[2] + "." + labels[1] + "." + labels[0])
		return addr, err == nil && addr.Is4()
	}
	if rest, ok := strings.CutSuffix(name, ".ip6.arpa."); ok {
		// 32 nibbles, a dot between each.
		if len(rest) != 63 {
			return netip.Addr{}, false
		}
		var nibbles [32]byte
		for i := range 32 {
			if i > 0 && rest[2*i-1] != '.' {
				return netip.Addr{}, false
			}
			nibbles[31-i] = rest[2*i]
		}
		var a [16]byte
		if _, err := hex.Decode(a[:], nibbles[:]); err != nil {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16(a), true
	}
	return netip.Addr{}, false
}

// servicesName is the name whose PTR records are the kinds of service of the link (RFC 6763 9):
// every host that has any answers a query for it.
const servicesName = "_services._dns-sd._udp.local."

// query is a query for the PTR records of name, a question alone.
func query(id uint16, name string) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}
