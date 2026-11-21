package ipv6disc

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/rdns"
)

// Config is how a Worker discovers addresses: the same for each family.
type Config struct {
	// How long an address stays after it was last seen, unless its family says.
	Lifetime time.Duration
	// How often the active discovery runs. Zero: a third of the shortest lifetime of the families
	// that probe, so that a quiet host is probed before it expires. Longer than a family's
	// lifetime, the hosts that stay quiet expire between probes.
	Rediscover time.Duration

	IPv6 Family
	IPv4 Family

	// The names of the hosts: off unless asked for.
	Hostnames Hostnames

	// Interfaces limits the local discovery, of both families, to the interfaces whose name
	// matches one of these patterns, as path.Match takes them: "eth0", "en*". None means every
	// interface. ExcludeInterfaces then leaves out those matching one of its own: "docker*",
	// "veth*". The plugins, which read other hosts' tables, aren't concerned.
	Interfaces        []string
	ExcludeInterfaces []string
}

// Family is how a family's addresses are discovered. Targeted discovery, of given hosts, is
// Worker.Solicit for IPv6 and Worker.SolicitIPv4 for IPv4: its targets come from the caller.
type Family struct {
	// Whether the state takes the family's addresses, and the plugins read them. Without it, the
	// rest is off.
	Enabled bool
	// Passive local discovery. IPv6: listening for NDP, and the answers of the protocols. IPv4:
	// reading the kernel's neighbor table, and on Linux, with CAP_NET_RAW, hearing the ARP the
	// hosts send, which tells each at once.
	Listen bool
	// Probing every host of the local links, at every Rediscover. IPv6: multicast ping, SSDP
	// and WS-Discovery. IPv4: a sweep of the subnets, which broadcasts an ARP request for each
	// address. Only with Listen, which reads the answers: without it, nothing is probed.
	Active bool
	// How long the family's addresses stay after they were last seen, whatever found them, the
	// plugins too. Zero: the lifetime of each registration, Config.Lifetime for the local
	// discovery, and for a plugin the one it was made with.
	Lifetime time.Duration
}

// Hostnames is how the names of the hosts are learned, whatever the family they are heard over.
type Hostnames struct {
	// Whether the state takes names, the plugins read those of their router's leases, and the
	// local discovery learns them by Protocols, on the interfaces and for the families it
	// listens on, and asks the hosts their name. Without it nothing is joined, heard, fetched
	// nor sent for a name.
	Enabled bool
	// The protocols the local discovery learns names by, of NameProtocols: "mdns", "dns",
	// "netbios", "llmnr", "wsd", "ssdp", "dhcp", "lldp". None means all of them. The plugins
	// aren't concerned: they read the names of their leases whatever is here.
	Protocols []string
	// The DNS servers asked the name of each address, the PTR record of its reverse name, by
	// the protocol "dns": none by default, and then nothing is asked. Only these, never the
	// system's resolver. With a port of zero, at 53.
	DNS []netip.AddrPort
	// How long a name stays after it was last said, whatever said it, the plugins too. Zero:
	// the lifetime of each registration, Config.Lifetime for the local discovery, and for a
	// plugin the one it was made with.
	Lifetime time.Duration
}

// DefaultConfig discovers IPv6 addresses by every means, and no IPv4 ones. Rediscover is left zero,
// a third of the lifetime, so that it follows a Lifetime changed afterwards.
func DefaultConfig() Config {
	return Config{
		Lifetime: 4 * time.Hour,
		IPv6:     Family{Enabled: true, Listen: true, Active: true},
	}
}

// warnings tells what of a valid configuration, its defaults filled in, loses hosts that are there.
func (c Config) warnings() []string {
	var warnings []string
	for _, f := range []struct {
		name     string
		probes   bool
		lifetime time.Duration
	}{{"IPv6", c.probesIPv6(), c.IPv6.Lifetime}, {"IPv4", c.probesIPv4(), c.IPv4.Lifetime}} {
		if f.probes && f.lifetime <= c.Rediscover {
			warnings = append(warnings, fmt.Sprintf("the %s lifetime, %s, is not longer than the rediscovery interval, %s: the hosts that stay quiet expire between probes", f.name, f.lifetime, c.Rediscover))
		}
	}
	if c.asksNames() && c.Hostnames.Lifetime <= c.Rediscover {
		warnings = append(warnings, fmt.Sprintf("the names' lifetime, %s, is not longer than the rediscovery interval, %s: a host is asked its name once in each, so the names expire between", c.Hostnames.Lifetime, c.Rediscover))
	}
	if c.Hostnames.Enabled && len(c.Hostnames.DNS) > 0 && !c.names(NameDNS) {
		warnings = append(warnings, "DNS servers are given for the names, but dns is not among the protocols of the names: they are not asked")
	}
	if c.Hostnames.Enabled && len(c.Hostnames.DNS) == 0 && slices.Contains(c.Hostnames.Protocols, NameDNS) {
		warnings = append(warnings, "dns is among the protocols of the names, but no DNS server is given: nothing is asked")
	}
	if c.listensIPv4() && c.IPv4.Lifetime <= interfaceCheckInterval {
		warnings = append(warnings, fmt.Sprintf("the IPv4 lifetime, %s, is not longer than the %s between readings of the neighbor table: the IPv4 addresses expire between them", c.IPv4.Lifetime, interfaceCheckInterval))
	}
	return warnings
}

// selfRefresh is how often the IPv6 discovery registers again the interfaces' own addresses, its
// defaults filled in: well within their lifetime, whatever the rediscovery interval, which is of
// the probes. Nothing else refreshes them.
func (c Config) selfRefresh() time.Duration {
	return max(min(c.Rediscover, c.IPv6.Lifetime/3), time.Second)
}

func (c Config) validate() error {
	var errs []error
	if c.Lifetime <= 0 || c.Rediscover <= 0 {
		errs = append(errs, fmt.Errorf("invalid lifetime %s or rediscovery interval %s: they must be positive", c.Lifetime, c.Rediscover))
	}
	if c.IPv6.Lifetime < 0 || c.IPv4.Lifetime < 0 {
		errs = append(errs, fmt.Errorf("invalid family lifetime: IPv6 %s, IPv4 %s", c.IPv6.Lifetime, c.IPv4.Lifetime))
	}
	if c.Hostnames.Lifetime < 0 {
		errs = append(errs, fmt.Errorf("invalid names' lifetime: %s", c.Hostnames.Lifetime))
	}
	for _, protocol := range c.Hostnames.Protocols {
		if !slices.Contains(NameProtocols(), protocol) {
			errs = append(errs, fmt.Errorf("invalid protocol of the names %q: they are %s", protocol, strings.Join(NameProtocols(), ", ")))
		}
	}
	for _, server := range c.Hostnames.DNS {
		if !server.Addr().IsValid() || server.Addr().IsUnspecified() || server.Addr().IsMulticast() {
			errs = append(errs, fmt.Errorf("invalid DNS server of the names: %s", server))
		}
	}
	for _, pattern := range slices.Concat(c.Interfaces, c.ExcludeInterfaces) {
		if _, err := path.Match(pattern, ""); err != nil {
			errs = append(errs, fmt.Errorf("invalid interface pattern %q: %w", pattern, err))
		}
	}
	return errors.Join(errs...)
}

// withDefaults fills in what is left zero: the families' lifetimes and the names', and the
// rediscovery interval, from the families that probe.
func (c Config) withDefaults() Config {
	shortest := time.Duration(0)
	for _, f := range []*Family{&c.IPv6, &c.IPv4} {
		if f.Lifetime == 0 {
			f.Lifetime = c.Lifetime
		}
		probes := f.Enabled && f.Listen && f.Active
		if probes && (shortest == 0 || f.Lifetime < shortest) {
			shortest = f.Lifetime
		}
	}
	if shortest == 0 {
		shortest = c.Lifetime
	}
	if c.Rediscover == 0 {
		c.Rediscover = shortest / 3
	}
	if c.Hostnames.Lifetime == 0 {
		c.Hostnames.Lifetime = c.Lifetime
	}
	// Its own copy, with the port of DNS where none is given.
	c.Hostnames.DNS = slices.Clone(c.Hostnames.DNS)
	for i, server := range c.Hostnames.DNS {
		if server.Port() == 0 {
			c.Hostnames.DNS[i] = netip.AddrPortFrom(server.Addr(), rdns.Port)
		}
	}
	return c
}

// usesInterface tells whether the local discovery runs on the interface of this name.
func (c Config) usesInterface(name string) bool {
	matches := func(patterns []string) bool {
		for _, pattern := range patterns {
			if ok, _ := path.Match(pattern, name); ok {
				return true
			}
		}
		return false
	}
	return (len(c.Interfaces) == 0 || matches(c.Interfaces)) && !matches(c.ExcludeInterfaces)
}

// listensIPv6 and the others tell what of the configuration runs.
func (c Config) listensIPv6() bool { return c.IPv6.Enabled && c.IPv6.Listen }
func (c Config) probesIPv6() bool  { return c.IPv6.Enabled && c.IPv6.Listen && c.IPv6.Active }
func (c Config) listensIPv4() bool { return c.IPv4.Enabled && c.IPv4.Listen }
func (c Config) probesIPv4() bool  { return c.IPv4.Enabled && c.IPv4.Listen && c.IPv4.Active }

// namesLocally tells whether the local discovery learns names: asked for, and a family listens.
func (c Config) namesLocally() bool {
	return c.Hostnames.Enabled && (c.listensIPv6() || c.listensIPv4())
}

// names tells whether names are learned by that protocol: asked for, and it is among the
// protocols, or none is named.
func (c Config) names(protocol string) bool {
	return c.Hostnames.Enabled && (len(c.Hostnames.Protocols) == 0 || slices.Contains(c.Hostnames.Protocols, protocol))
}

// asksNames tells whether anything asks the hosts their name: the local discovery, or the DNS
// servers given, which are asked of the hosts the plugins found too.
func (c Config) asksNames() bool {
	return c.namesLocally() || c.names(NameDNS) && len(c.Hostnames.DNS) > 0
}

// ParseNameServer reads a DNS server of Hostnames.DNS as it is written: an address, alone or
// with a port, the one of an IPv6 address in brackets. Without a port, it is at 53.
func ParseNameServer(s string) (netip.AddrPort, error) {
	return rdns.ParseServer(s)
}
