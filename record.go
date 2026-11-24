package ipv6disc

import (
	"cmp"
	"slices"
	"strings"
	"time"
)

// Way is how a protocol of the local discovery saw an address: by what the host itself did.
type Way string

const (
	// The host said the address is its own: unasked, as the advertisement of an address it takes,
	// or about itself, as the address records of its name over mDNS.
	Announced Way = "announced"
	// The host replied to a probe of the discovery's, from or for the address: a ping, a
	// solicitation, an ARP request, an SSDP or WS-Discovery search.
	Answered Way = "answered"
	// The host used the address, unprompted by the discovery: a solicitation or an ARP request it
	// sent from it.
	Heard Way = "heard"
)

// Ways are the ways, in order.
var Ways = []Way{Announced, Answered, Heard}

// The tables a report is of.
const (
	// A neighbor or ARP table: the addresses in use on a link, and their MACs.
	FromNeighbors = "neighbors"
	// DHCP leases: the addresses a server gave, and to which MACs.
	FromLeases = "leases"
	// The addresses an interface of this machine has.
	FromInterfaces = "interfaces"
)

// ReportedByKernel is the reporter of what this machine's own kernel tells: its neighbor table, the
// addresses of its interfaces.
const ReportedByKernel = "kernel"

// Record is one way an address was seen: by a protocol of the local discovery, and how; or
// reported by something else, from one of its tables. An address has a record for each, each with
// its own times: it stays while any of them does.
type Record struct {
	// Of a protocol of the local discovery: its name, as ndp or mdns, and how.
	Protocol string
	Way      Way
	// Of a report: who made it, a plugin's name or ReportedByKernel, and of what type, the
	// plugin's; and of which of its tables.
	By, Type, From string
	// The local interface it was seen on: none for a plugin's report.
	On string

	FirstSeen, LastSeen time.Time
	Lifetime            time.Duration

	// Of State.Attach: a report of an address something else saw, as a lease, which says how it
	// was seen while it counts, and keeps the address no longer than the others do.
	attached bool
	// The order records were added in, of the address: Records and Sources keep it.
	order uint64
}

// Attached tells whether the record is State.Attach's: it says how the address was seen, and keeps
// it no longer than the others do.
func (r Record) Attached() bool { return r.attached }

// Reported tells whether the record is a report, rather than of a protocol.
func (r Record) Reported() bool { return r.Protocol == "" }

// Expiration is when the record is over: its lifetime after it was last seen.
func (r Record) Expiration() time.Time { return r.LastSeen.Add(r.Lifetime) }

// Live tells whether the record still counts, at now.
func (r Record) Live(now time.Time) bool { return r.Expiration().After(now) }

// String is the record as the log and the status say it: ndp:answered on eth0, or reported by
// mikrotik-2 from neighbors.
func (r Record) String() string {
	var b strings.Builder
	if r.Reported() {
		b.WriteString("reported by " + r.By)
		if r.From != "" {
			b.WriteString(" from " + r.From)
		}
	} else {
		b.WriteString(r.Protocol + ":" + string(r.Way))
	}
	if r.On != "" {
		b.WriteString(" on " + r.On)
	}
	return b.String()
}

// source is the name the record gives to Addr.Sources: the interface, or the reporter.
func (r Record) source() string {
	if r.On != "" {
		return r.On
	}
	return r.By
}

// own tells whether the record is RegisterSelf's: of an interface of this machine that has the
// address.
func (r Record) own() bool {
	return r.By == ReportedByKernel && r.From == FromInterfaces && r.On != ""
}

// moveScope is where an address is at one MAC at a time: the link of a local interface, which
// says so of the records seen on it; or the neighbor table of one reporter, which has one MAC for
// each address, as the kernel's and a router's do. Elsewhere, as in DHCP leases, an address can
// be at two MACs, and nothing moves.
type moveScope struct {
	on, by string
}

// scopeOf is the scope a record shows its address in, and whether it has one: a record of this
// machine's own address has none, nor one attached, as a lease.
func scopeOf(r Record) (moveScope, bool) {
	switch {
	case r.own() || r.attached:
		return moveScope{}, false
	case r.On != "":
		return moveScope{on: r.On}, true
	case r.By != "" && r.From == FromNeighbors:
		return moveScope{by: r.By}, true
	}
	return moveScope{}, false
}

// String is the scope as the log says it: the interface, or the reporter's neighbor table.
func (s moveScope) String() string {
	if s.on != "" {
		return s.on
	}
	return s.by + " " + FromNeighbors
}

// has tells whether the record is of the scope.
func (s moveScope) has(r Record) bool {
	if r.own() || r.attached {
		return false
	}
	if s.on != "" {
		return r.On == s.on
	}
	return r.On == "" && r.By == s.by && r.From == FromNeighbors
}

// recordKey tells records apart: the same one seen again is a record refreshed, not another.
type recordKey struct {
	protocol, way, by, from, on string
}

func (r Record) key() recordKey {
	return recordKey{r.Protocol, string(r.Way), r.By, r.From, r.On}
}

// Records returns the records of the address that still count, in the order they came: all of them,
// of one that expired and is still held.
func (a *Addr) Records() []Record {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.liveRecords(time.Now())
}

// liveRecords is Records, with the mutex held.
func (a *Addr) liveRecords(now time.Time) []Record {
	var live, all []Record
	for _, r := range a.records {
		all = append(all, *r)
		if r.Live(now) {
			live = append(live, *r)
		}
	}
	if len(live) == 0 {
		live = all
	}
	slices.SortFunc(live, func(x, y Record) int { return cmp.Compare(x.order, y.order) })
	return live
}

// addRecord merges r into the address's records, with the mutex held: a record seen before is seen
// again, at r's time if later, and takes r's lifetime, as the latest says how long it stays.
func (a *Addr) addRecord(r Record) (added bool) {
	if a.records == nil {
		a.records = make(map[recordKey]*Record)
	}
	k := r.key()
	if old, ok := a.records[k]; ok {
		if r.LastSeen.After(old.LastSeen) {
			old.LastSeen = r.LastSeen
		}
		old.Lifetime = r.Lifetime
		return false
	}
	if r.FirstSeen.IsZero() {
		r.FirstSeen = r.LastSeen
	}
	a.recordsAdded++
	r.order = a.recordsAdded
	copied := r
	a.records[k] = &copied
	return true
}

// lasting is the record that keeps the address longest, of those that count at now, with the mutex
// held: the address expires with it. An attached one keeps it none. The records that are over are
// dropped, but the last one, which an expired address still held keeps.
func (a *Addr) lasting(now time.Time) *Record {
	var best *Record
	for k, r := range a.records {
		if !r.Live(now) && len(a.records) > 1 {
			delete(a.records, k)
			continue
		}
		if r.attached {
			continue
		}
		if best == nil || r.Expiration().After(best.Expiration()) {
			best = r
		}
	}
	return best
}
