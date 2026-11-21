package ipv6disc

import (
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"go.uber.org/zap"
)

// HostName is a name of a host, as something said it: the host itself, over mDNS or as it asked
// for an address, a DNS server asked of it, or the leases of a router. It is whatever the device claims, cleaned to one DNS label by CleanName: nothing
// proves it, and two hosts can claim the same.
//
// A name is the host's, its MAC's, not an address's: one learned over IPv4 is the host's for its
// IPv6 addresses too. It stays its lifetime after it was last said, by any source, and a host can
// have several at once, when its sources disagree or it was renamed.
type HostName struct {
	Name string
	// What said it, in the order they first did: a protocol of the local discovery, as "mdns"
	// or "dhcp" (ProtocolNames), or a plugin's name. Of those whose lifetime runs.
	Sources []string
	// Each that said it, with its own times, in the same order.
	Said []NameSource
	// When it was first said, and last, by any; and until when it stays, the last of Said's.
	FirstSeen  time.Time
	Seen       time.Time
	Expiration time.Time
}

// NameSource is one that said a name, and when: a protocol of the local discovery, on an interface
// or on none, as the reverse DNS; or a report, of a plugin or another caller of RegisterName or
// ReportName, from a table, as the leases of a router.
type NameSource struct {
	Source   string
	On       string
	Reported bool
	From     string

	FirstSeen, LastSeen time.Time
	Lifetime            time.Duration
}

// Expiration is when the source no longer says the name: its lifetime after it last did.
func (s NameSource) Expiration() time.Time { return s.LastSeen.Add(s.Lifetime) }

// String is the source as the page says it: mdns on eth0, or reported by router from leases.
func (s NameSource) String() string {
	var b strings.Builder
	if s.Reported {
		b.WriteString("reported by " + s.Source)
		if s.From != "" {
			b.WriteString(" from " + s.From)
		}
	} else {
		b.WriteString(s.Source)
	}
	if s.On != "" {
		b.WriteString(" on " + s.On)
	}
	return b.String()
}

func (s NameSource) same(o NameSource) bool {
	return s.Source == o.Source && s.On == o.On && s.Reported == o.Reported && s.From == o.From
}

// Valid tells whether the name's lifetime is still running.
func (n HostName) Valid() bool {
	return n.Expiration.After(time.Now())
}

// maxNameLength is the longest DNS label.
const maxNameLength = 63

// CleanName makes a name a device claims into one DNS label, lower case, of letters, digits and
// hyphens, and tells whether there is one left.
//
// Of a dotted name, host.domain or name.local., it is the first label. Upper case becomes lower,
// and an underscore or a space within, as in the ESP_1A2B3C that devices give their DHCP server,
// becomes a hyphen; the hyphens at either end are dropped. Anything else is no name, never mapped
// to one: an empty label, a label that starts with an underscore, which is a service's and not a
// host's, any other character, as the * of a lease without a name, a byte that isn't ASCII, a
// label longer than 63 characters, and an IP address in place of a name.
func CleanName(name string) (string, bool) {
	if _, err := netip.ParseAddr(strings.TrimSuffix(name, ".")); err == nil {
		return "", false
	}
	label, _, _ := strings.Cut(name, ".")
	if label == "" || label[0] == '_' {
		return "", false
	}
	clean := make([]byte, 0, len(label))
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		case c == '_', c == ' ':
			c = '-'
		default:
			return "", false
		}
		clean = append(clean, c)
	}
	result := strings.Trim(string(clean), "-")
	if result == "" || len(result) > maxNameLength {
		return "", false
	}
	return result, true
}

// SetNames says whether the state takes the names of the hosts, which RegisterName leaves out
// otherwise, and the plugins don't read; and their lifetime, which RegisterName then uses in
// place of the one it is given. A zero lifetime keeps the one given.
func (s *State) SetNames(enabled bool, lifetime time.Duration) {
	s.takesNames.Store(enabled)
	s.lifetimeNames.Store(int64(lifetime))
}

// Names tells whether the state takes the names of the hosts, for the plugins to read them.
func (s *State) Names() bool {
	return s.takesNames.Load()
}

// RegisterName adds a name of the host with that MAC, as source said it, or refreshes the one
// already there: it stays lifetime from now, or the lifetime SetNames gave, whatever said it
// before. The name is cleaned by CleanName, and returned as it is kept. It returns "" and true, as
// if known, for what the state leaves out: any name unless SetNames enabled them, one that
// CleanName drops, or one with no MAC or no lifetime.
//
// The host needs no address yet: a name said before its first address is there when it comes.
// When the last address of a host goes, its names go with it.
func (s *State) RegisterName(hw net.HardwareAddr, name, source string, lifetime time.Duration) (string, bool) {
	return s.registerName(hw, name, NameSource{Source: source, Reported: true}, lifetime)
}

// ReportName is RegisterName, of a name by of the table from has, as a plugin's of its router's
// leases.
func (s *State) ReportName(hw net.HardwareAddr, name, by, from string, lifetime time.Duration) (string, bool) {
	return s.registerName(hw, name, NameSource{Source: by, Reported: true, From: from}, lifetime)
}

// registerName is RegisterName, of what said says the name: its source, and on which interface.
func (s *State) registerName(hw net.HardwareAddr, name string, said NameSource, lifetime time.Duration) (string, bool) {
	source := said.Source
	if !s.Names() || len(hw) == 0 {
		return "", true
	}
	clean, ok := CleanName(name)
	if !ok {
		return "", true
	}
	if l := time.Duration(s.lifetimeNames.Load()); l > 0 {
		lifetime = l
	}
	if lifetime <= 0 {
		return "", true
	}
	mac := hw.String()
	now := time.Now()

	s.namesMutex.Lock()
	if s.names == nil {
		s.names = make(map[string]map[string]*HostName)
	}
	host := s.names[mac]
	if host == nil {
		host = make(map[string]*HostName)
		s.names[mac] = host
	}
	n, existing := host[clean]
	// One that expired and was not taken out yet is new again.
	existing = existing && n.Expiration.After(now)
	if !existing {
		n = &HostName{Name: clean, FirstSeen: now}
		host[clean] = n
	}
	n.Said = liveSaid(n.Said, now)
	newSource := !slices.Contains(n.Sources, source)
	said.LastSeen, said.Lifetime = now, lifetime
	if i := slices.IndexFunc(n.Said, said.same); i >= 0 {
		n.Said[i].LastSeen, n.Said[i].Lifetime = now, lifetime
	} else {
		said.FirstSeen = now
		n.Said = append(n.Said, said)
	}
	n.Sources = saidSources(n.Said)
	n.Seen, n.Expiration = now, latestExpiration(n.Said)
	s.namesStopped = false
	s.armNames(n.Expiration)
	s.namesMutex.Unlock()

	if !existing || newSource {
		s.changed()
	}
	if s.logger != nil {
		msg, log := "name refreshed", s.logger.Debugw
		if !existing {
			msg, log = "host named", s.logger.Infow
		}
		log(msg, zap.String("name", clean), zap.String("mac", mac), zap.String("source", source))
	}
	return clean, existing
}

// armNames has the names' timer fire at expiration, unless it fires sooner already. One timer is
// all the names have, and no goroutine while it waits: a name refreshed leaves it as it is, to
// fire early, find nothing and wait for the next. With namesMutex held.
func (s *State) armNames(expiration time.Time) {
	if s.namesStopped {
		return
	}
	if s.namesTimer == nil {
		s.namesTimer = time.AfterFunc(time.Until(expiration), s.expireNames)
		s.namesTimerAt = expiration
		return
	}
	if s.namesTimerAt.IsZero() || expiration.Before(s.namesTimerAt) {
		s.namesTimer.Reset(time.Until(expiration))
		s.namesTimerAt = expiration
	}
}

// expireNames takes out the names whose lifetime passed, and waits for the next to.
func (s *State) expireNames() {
	type expired struct{ mac, name string }
	var gone []expired

	s.namesMutex.Lock()
	if s.namesStopped {
		s.namesMutex.Unlock()
		return
	}
	now := time.Now()
	var next time.Time
	for mac, host := range s.names {
		for name, n := range host {
			if !n.Expiration.After(now) {
				delete(host, name)
				gone = append(gone, expired{mac, name})
			} else if next.IsZero() || n.Expiration.Before(next) {
				next = n.Expiration
			}
		}
		if len(host) == 0 {
			delete(s.names, mac)
		}
	}
	s.namesTimerAt = time.Time{}
	if !next.IsZero() {
		s.armNames(next)
	}
	s.namesMutex.Unlock()

	if len(gone) == 0 {
		return
	}
	s.changed()
	if s.logger != nil {
		for _, g := range gone {
			s.logger.Infow("host name expired", zap.String("name", g.name), zap.String("mac", g.mac))
		}
	}
}

// dropNames takes out the names of a host whose last address went. With macsMutex held, as the
// address is taken out: the caller tells the change.
func (s *State) dropNames(mac string) {
	s.namesMutex.Lock()
	host := s.names[mac]
	delete(s.names, mac)
	s.namesMutex.Unlock()

	if s.logger != nil {
		for _, name := range slices.Sorted(maps.Keys(host)) {
			s.logger.Infow("host name removed", zap.String("name", name), zap.String("mac", mac))
		}
	}
}

// stopNames is Close, of the names: their timer stops, and none is taken out after it. One
// registered again starts it again.
func (s *State) stopNames() {
	s.namesMutex.Lock()
	defer s.namesMutex.Unlock()
	s.namesStopped = true
	if s.namesTimer != nil {
		s.namesTimer.Stop()
		s.namesTimerAt = time.Time{}
	}
}

// NamesOf returns the names of the host with that MAC whose lifetime is running, sorted by name:
// copies, which nothing changes.
func (s *State) NamesOf(hw net.HardwareAddr) []HostName {
	s.namesMutex.Lock()
	defer s.namesMutex.Unlock()
	return validNames(s.names[hw.String()], time.Now())
}

// AllNames returns the names of each MAC that has any, as NamesOf does. A MAC can be there
// without being in GetAll: a name said of a host that has no address yet.
func (s *State) AllNames() map[string][]HostName {
	s.namesMutex.Lock()
	defer s.namesMutex.Unlock()
	now := time.Now()
	result := make(map[string][]HostName, len(s.names))
	for mac, host := range s.names {
		if names := validNames(host, now); len(names) > 0 {
			result[mac] = names
		}
	}
	return result
}

func validNames(host map[string]*HostName, now time.Time) []HostName {
	var names []HostName
	for _, n := range host {
		if n.Expiration.After(now) {
			name := *n
			name.Said = liveSaid(slices.Clone(n.Said), now)
			name.Sources = saidSources(name.Said)
			names = append(names, name)
		}
	}
	slices.SortFunc(names, func(a, b HostName) int { return strings.Compare(a.Name, b.Name) })
	return names
}

// hasHost tells whether the state has a host at that MAC: an address of it, still valid.
func (s *State) hasHost(hw net.HardwareAddr) bool {
	s.macsMutex.RLock()
	collection := s.macs[hw.String()]
	s.macsMutex.RUnlock()
	if collection == nil {
		return false
	}
	return slices.ContainsFunc(collection.Get(), (*Addr).Valid)
}

// has tells whether the state has ip at that MAC, still valid, as the local interface iface saw
// it.
func (s *State) has(hw net.HardwareAddr, ip netip.Addr, iface string) bool {
	s.macsMutex.RLock()
	collection := s.macs[hw.String()]
	s.macsMutex.RUnlock()
	if collection == nil {
		return false
	}
	collection.addressesMutex.RLock()
	addr, ok := collection.addresses[ip.Unmap().WithZone("").String()]
	collection.addressesMutex.RUnlock()
	return ok && addr.Valid() && slices.Contains(addr.Interfaces(), iface)
}

// macOf tells the MAC the state has ip at, among its addresses still valid, for what was heard
// from ip on the local interface iface: the one that interface saw it at, or without one the only
// one there is. An address at two MACs, as a link-local one on two links, is nobody's when the
// interface doesn't tell them apart.
func (s *State) macOf(ip netip.Addr, iface string) (net.HardwareAddr, bool) {
	key := ip.Unmap().WithZone("").String()
	var local, any []*Addr

	s.macsMutex.RLock()
	for _, collection := range s.macs {
		collection.addressesMutex.RLock()
		addr, ok := collection.addresses[key]
		collection.addressesMutex.RUnlock()
		if !ok || !addr.Valid() {
			continue
		}
		any = append(any, addr)
		if slices.Contains(addr.Interfaces(), iface) {
			local = append(local, addr)
		}
	}
	s.macsMutex.RUnlock()

	switch {
	case len(local) == 1:
		return local[0].Hw, true
	case len(local) == 0 && len(any) == 1:
		return any[0].Hw, true
	}
	return nil, false
}

// liveSaid are the sources of said whose lifetime runs at now: of a name that has none, as one
// that expired and is still held, all of them.
func liveSaid(said []NameSource, now time.Time) []NameSource {
	live := slices.DeleteFunc(slices.Clone(said), func(s NameSource) bool { return !s.Expiration().After(now) })
	if len(live) == 0 {
		return said
	}
	return live
}

// saidSources are the names of the sources of said, each once, in order.
func saidSources(said []NameSource) []string {
	var sources []string
	for _, s := range said {
		if !slices.Contains(sources, s.Source) {
			sources = append(sources, s.Source)
		}
	}
	return sources
}

// latestExpiration is the last of the expirations of said.
func latestExpiration(said []NameSource) time.Time {
	var latest time.Time
	for _, s := range said {
		if e := s.Expiration(); e.After(latest) {
			latest = e
		}
	}
	return latest
}
