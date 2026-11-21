package netbios

import (
	"encoding/binary"
	"errors"
	"strings"
)

// What a node status exchange is made of (RFC 1002 4.2.17 and 4.2.18).
const (
	typeStatus = 0x0021
	classIN    = 0x0001
	// The flags of a name: a group's, and one that is registered and not in conflict nor going.
	flagGroup  = 0x8000
	flagActive = 0x0400
	flagGoing  = 0x1000
	flagClash  = 0x0800
	// The suffix of the name a machine has as a workstation: its own name.
	suffixWorkstation = 0x00
	// A NetBIOS name is 16 bytes: 15 of the name, padded with spaces, and its suffix.
	nameLen = 16
)

// statusName is the name a node status is asked of: "*" and fifteen zeros, which any node
// answers for, in the first-level encoding, each half of a byte as a letter from A on.
var statusName = func() []byte {
	raw := [nameLen]byte{'*'}
	encoded := make([]byte, 0, 2*nameLen+2)
	encoded = append(encoded, 2*nameLen)
	for _, c := range raw {
		encoded = append(encoded, 'A'+c>>4, 'A'+c&0xf)
	}
	return append(encoded, 0)
}()

// query is a node status request with that transaction ID: one question, to one node, with no
// flag set.
func query(id uint16) []byte {
	b := make([]byte, 12, 12+len(statusName)+4)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[4:6], 1)
	b = append(b, statusName...)
	b = binary.BigEndian.AppendUint16(b, typeStatus)
	return binary.BigEndian.AppendUint16(b, classIN)
}

// Status is what is taken of a node status response.
type Status struct {
	ID uint16
	// The name the node has as a workstation, without its padding: "" when it tells none.
	Name string
}

var errStatus = errors.New("not a node status response")

// Parse reads a node status response: a response, without an error, whose one record is a node
// status. Of the names it lists, the node's own is the first that is unique, not a group's,
// registered, and of the workstation service: the others are its workgroup, and its services.
func Parse(packet []byte) (Status, error) {
	if len(packet) < 12 {
		return Status{}, errStatus
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	// A response, of a query, without an error; no question, and one answer.
	if flags&0x8000 == 0 || flags&0x7800 != 0 || flags&0x000f != 0 ||
		binary.BigEndian.Uint16(packet[4:6]) != 0 || binary.BigEndian.Uint16(packet[6:8]) != 1 {
		return Status{}, errStatus
	}
	s := Status{ID: binary.BigEndian.Uint16(packet[0:2])}
	rest, ok := skipName(packet[12:])
	// Its type and class, a TTL, and the length of what follows.
	if !ok || len(rest) < 10 || binary.BigEndian.Uint16(rest[0:2]) != typeStatus || binary.BigEndian.Uint16(rest[2:4]) != classIN {
		return Status{}, errStatus
	}
	length := int(binary.BigEndian.Uint16(rest[8:10]))
	data := rest[10:]
	if length > len(data) || length < 1 {
		return Status{}, errStatus
	}
	data = data[:length]
	count := int(data[0])
	data = data[1:]
	if count*(nameLen+2) > len(data) {
		return Status{}, errStatus
	}
	for i := range count {
		entry := data[i*(nameLen+2):]
		nameFlags := binary.BigEndian.Uint16(entry[nameLen : nameLen+2])
		if entry[nameLen-1] != suffixWorkstation || nameFlags&(flagGroup|flagGoing|flagClash) != 0 || nameFlags&flagActive == 0 {
			continue
		}
		s.Name = strings.TrimRight(string(entry[:nameLen-1]), " \x00")
		break
	}
	return s, nil
}

// skipName returns what follows a name: its labels, or a pointer to one elsewhere.
func skipName(b []byte) ([]byte, bool) {
	for {
		if len(b) == 0 {
			return nil, false
		}
		length := int(b[0])
		switch {
		case length == 0:
			return b[1:], true
		case length&0xc0 == 0xc0:
			if len(b) < 2 {
				return nil, false
			}
			return b[2:], true
		case length > 63 || len(b) < 1+length:
			return nil, false
		}
		b = b[1+length:]
	}
}
