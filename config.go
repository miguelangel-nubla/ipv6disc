package ipv6disc

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"slices"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/internal/packet"
	"github.com/miguelangel-nubla/ipv6disc/pkg/arp"
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

	// Whether the names of the hosts are kept: off unless asked for.
	Hostnames Hostnames

	// The protocols of the local discovery, each with its switch and its options. A Config made
	// by hand has none: DefaultProtocols are those of DefaultConfig.
	Protocols Protocols

	// Interfaces limits the local discovery, of both families, to the interfaces whose name
	// matches one of these patterns, as path.Match takes them: "eth0", "en*". None means every
	// interface. ExcludeInterfaces then leaves out those matching one of its own: "docker*",
	// "veth*". The plugins, which read other hosts' tables, aren't concerned.
	Interfaces        []string
	ExcludeInterfaces []string
}

// Family is how a family's addresses are discovered: the switches of all its protocols at once.
// A protocol runs only when it is enabled, in Protocols, and its family and the way it works are
// on here. Targeted discovery, of given hosts, is Worker.Solicit for IPv6 and Worker.SolicitIPv4
// for IPv4: its targets come from the caller.
type Family struct {
	// Whether the state takes the family's addresses, and the plugins read them. Without it, the
	// rest is off.
	Enabled bool
	// The local discovery of the family: its protocols hear, and ask one host of what they heard
	// of it. IPv6: NDP, and the answers to the ping, SSDP and WS-Discovery. IPv4: the
	// kernel's neighbor table, and on Linux, with CAP_NET_RAW, the ARP the hosts send, which
	// tells each at once. And over either, those of the names.
	Listen bool
	// Probing every host of the local links, at every Rediscover. IPv6: multicast ping, SSDP
	// and WS-Discovery. IPv4: a sweep of the subnets, which broadcasts an ARP request for each
	// address. And the query of mDNS, over either. Only with Listen, which reads the answers:
	// without it, nothing is probed.
	Active bool
	// How long the family's addresses stay after they were last seen, whatever found them, the
	// plugins too. Zero: the lifetime of each registration, Config.Lifetime for the local
	// discovery, and for a plugin the one it was made with.
	Lifetime time.Duration
}

// Hostnames is whether the names of the hosts are kept, whatever the family they are heard over.
// What learns them is each protocol's to say, in Protocols.
type Hostnames struct {
	// Whether the state takes names, and the plugins read those of their router's leases. Without
	// it no name is kept: a protocol that also finds hosts, as mDNS, DHCP and LLDP, still does,
	// and takes no name; one that only learns names, as NetBIOS, LLMNR, the reverse DNS, and
	// the names of WS-Discovery and SSDP, is then an error to enable.
	Enabled bool
	// How long a name stays after it was last said, whatever said it, the plugins too. Zero:
	// the lifetime of each registration, Config.Lifetime for the local discovery, and for a
	// plugin the one it was made with.
	Lifetime time.Duration
}

// Protocols are the protocols of the local discovery: each runs when it is Enabled here, and its
// family listens, or probes, as Family says. The zero value runs none.
type Protocols struct {
	// IPv6, while it listens: the neighbor discovery of each link, which tells an address and
	// its MAC, and asks the MAC of what the others hear. Without it they find nothing.
	NDP Protocol
	// IPv6: the ping. Listening, an address is pinged before it expires; active, all are, by
	// multicast.
	Ping Protocol
	// IPv6: SSDP, the devices of UPnP. Active, a search, whose answers it hears while listening.
	SSDP SSDPProtocol
	// IPv6: WS-Discovery, Windows and Samba. Active, a probe, whose answers it hears while
	// listening.
	WSD WSDProtocol
	// Either family: mDNS. Listening, whatever sends to its group is a host, and what it
	// announces its name; active, a query to the group.
	MDNS MDNSProtocol
	// IPv4, while it listens: the kernel's neighbor table, read every minute.
	ARP Protocol
	// IPv4, active: a sweep of the subnets, which has the kernel resolve each address.
	ARPSweep ARPSweepProtocol
	// IPv4, while it listens: the ARP the hosts send, heard. Linux only.
	ARPListen Protocol
	// Either family, while it listens: what the DHCP clients say as they ask for an address,
	// heard. Linux only.
	DHCP Protocol
	// Either family, while it listens: what the LLDP neighbors say, heard. Linux only.
	LLDP Protocol
	// IPv4, while it listens: a host is asked its NetBIOS name. Names only.
	NetBIOS Protocol
	// Either family, while it listens: a host is asked its name by LLMNR. Names only.
	LLMNR Protocol
	// Whatever found the host, the plugins too: DNS servers are asked the name of its
	// addresses. Names only, and of no family.
	DNS DNSProtocol
}

// Protocol is a protocol of the local discovery that has no options.
type Protocol struct {
	Enabled bool
}

// SSDPProtocol is SSDP.
type SSDPProtocol struct {
	Enabled bool
	// Whether a device that answers the search is asked its description, over HTTP, for its
	// friendly name. It needs Hostnames.
	Names bool
}

// WSDProtocol is WS-Discovery.
type WSDProtocol struct {
	Enabled bool
	// Whether a computer that answers the probe is asked its metadata, over HTTP, for its name.
	// It needs Hostnames.
	Names bool
}

// MDNSProtocol is mDNS.
type MDNSProtocol struct {
	Enabled bool
	// Whether questions are sent: the query to the group at every rediscovery, where a family
	// is active, and, with Hostnames, to each host for its name. Without it mDNS only listens.
	Ask bool
}

// ARPSweepProtocol is the sweep of the IPv4 subnets.
type ARPSweepProtocol struct {
	Enabled bool
	// The largest subnet swept whole, by the length of its prefix: 22, a /22 of 1022 addresses,
	// when zero. A larger one is swept in the /24 of the interface's address only, or in the
	// prefix of this length there when that is smaller. From 16 to 30.
	MaxPrefix int
}

// DNSProtocol is the reverse DNS.
type DNSProtocol struct {
	Enabled bool
	// The servers asked the name of each address, the PTR record of its reverse name: needed.
	// Only these, never the system's resolver. With a port of zero, at 53.
	Servers []netip.AddrPort
}

// The protocols of the local discovery, as a configuration names them, and as -live and the log
// do.
const (
	ProtocolNDP       = "ndp"
	ProtocolPing      = "ping"
	ProtocolSSDP      = "ssdp"
	ProtocolWSD       = "wsd"
	ProtocolMDNS      = "mdns"
	ProtocolARP       = "arp"
	ProtocolARPSweep  = "arp-sweep"
	ProtocolARPListen = "arp-listen"
	ProtocolDHCP      = "dhcp"
	ProtocolLLDP      = "lldp"
	ProtocolNetBIOS   = "netbios"
	ProtocolLLMNR     = "llmnr"
	ProtocolDNS       = "dns"
)

// ProtocolNames are the protocols of the local discovery, the fields of Protocols in their order.
func ProtocolNames() []string {
	return []string{ProtocolNDP, ProtocolPing, ProtocolSSDP, ProtocolWSD, ProtocolMDNS, ProtocolARP, ProtocolARPSweep,
		ProtocolARPListen, ProtocolDHCP, ProtocolLLDP, ProtocolNetBIOS, ProtocolLLMNR, ProtocolDNS}
}

// The bounds of ARPSweepProtocol.MaxPrefix.
const (
	MinSweepPrefix = 16
	MaxSweepPrefix = 30
)

// packetSockets tells whether the system has what hears ARP, DHCP and LLDP: a variable for the
// tests.
var packetSockets = packet.Supported

// DefaultProtocols are the protocols that run unless a configuration says: those that find
// hosts, NDP, the ping, SSDP and WS-Discovery over IPv6, and the neighbor table, the sweep and,
// on Linux, where alone it can be, the ARP heard, over IPv4. Those that tell names too, or names
// alone, are off, with the options they have when turned on: mDNS asks.
func DefaultProtocols() Protocols {
	on := Protocol{Enabled: true}
	return Protocols{
		NDP: on, Ping: on, SSDP: SSDPProtocol{Enabled: true}, WSD: WSDProtocol{Enabled: true},
		MDNS: MDNSProtocol{Ask: true},
		ARP:  on, ARPSweep: ARPSweepProtocol{Enabled: true, MaxPrefix: arp.DefaultSweepPrefix},
		ARPListen: Protocol{Enabled: packetSockets},
	}
}

// DefaultConfig discovers IPv6 addresses by every protocol of DefaultProtocols, no IPv4 ones, and
// no names. Rediscover is left zero, a third of the lifetime, so that it follows a Lifetime
// changed afterwards.
func DefaultConfig() Config {
	return Config{
		Lifetime:  4 * time.Hour,
		IPv6:      Family{Enabled: true, Listen: true, Active: true},
		IPv4:      Family{Listen: true, Active: true},
		Protocols: DefaultProtocols(),
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
	if c.runs(ProtocolARP) && c.IPv4.Lifetime <= interfaceCheckInterval {
		warnings = append(warnings, fmt.Sprintf("the IPv4 lifetime, %s, is not longer than the %s between readings of the neighbor table: the IPv4 addresses expire between them", c.IPv4.Lifetime, interfaceCheckInterval))
	}
	// A family that listens with none of its protocols: as a Config made by hand, without
	// DefaultProtocols.
	running := c.running()
	for _, f := range []struct {
		name      string
		listens   bool
		protocols []string
	}{
		{"IPv6", c.listensIPv6(), []string{ProtocolNDP, ProtocolMDNS, ProtocolDHCP, ProtocolLLDP, ProtocolLLMNR}},
		{"IPv4", c.listensIPv4(), []string{ProtocolARP, ProtocolARPListen, ProtocolMDNS, ProtocolDHCP, ProtocolLLDP, ProtocolLLMNR}},
	} {
		if f.listens && !slices.ContainsFunc(f.protocols, func(p string) bool { return slices.Contains(running, p) }) {
			warnings = append(warnings, fmt.Sprintf("%s listens, but no protocol that finds its hosts is enabled: this machine's own addresses only", f.name))
		}
	}
	return warnings
}

// selfRefresh is how often the IPv6 discovery registers again the interfaces' own addresses, its
// defaults filled in: well within their lifetime, whatever the rediscovery interval, which is of
// the probes. Nothing else refreshes them.
func (c Config) selfRefresh() time.Duration {
	return max(min(c.Rediscover, c.IPv6.Lifetime/3), time.Second)
}

// Validate tells what of the configuration a Worker can't start with, as Worker.Start does:
// every error of it, joined. What is left zero is its default first.
func (c Config) Validate() error {
	return c.withDefaults().validate()
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
	for _, pattern := range slices.Concat(c.Interfaces, c.ExcludeInterfaces) {
		if _, err := path.Match(pattern, ""); err != nil {
			errs = append(errs, fmt.Errorf("invalid interface pattern %q: %w", pattern, err))
		}
	}
	return errors.Join(append(errs, c.Protocols.validate(c.Hostnames.Enabled)...)...)
}

// validate tells what of the protocols enabled can't run, whatever the families: with names kept
// or not. The options of a protocol that is off are not looked at.
func (p Protocols) validate(names bool) []error {
	var errs []error
	// Only NDP tells a MAC: the others of IPv6 ask it of what they hear.
	for _, protocol := range []string{ProtocolPing, ProtocolSSDP, ProtocolWSD} {
		if p.enabled(protocol) && !p.NDP.Enabled {
			errs = append(errs, fmt.Errorf("the %s protocol is enabled without ndp, which tells the MAC of the hosts it hears: it would find none", protocol))
		}
	}
	if p.ARPSweep.Enabled {
		if !p.ARP.Enabled && !p.ARPListen.Enabled {
			errs = append(errs, fmt.Errorf("the %s protocol is enabled without %s or %s, which tell the hosts that answer it: it would find none", ProtocolARPSweep, ProtocolARP, ProtocolARPListen))
		}
		if p.ARPSweep.MaxPrefix < MinSweepPrefix || p.ARPSweep.MaxPrefix > MaxSweepPrefix {
			errs = append(errs, fmt.Errorf("invalid max_prefix of the %s protocol, %d: it is from %d to %d", ProtocolARPSweep, p.ARPSweep.MaxPrefix, MinSweepPrefix, MaxSweepPrefix))
		}
	}
	// What hears frames, by a packet socket.
	for _, protocol := range []string{ProtocolARPListen, ProtocolDHCP, ProtocolLLDP} {
		if p.enabled(protocol) && !packetSockets {
			errs = append(errs, fmt.Errorf("the %s protocol is enabled, and this system can't run it: it needs Linux", protocol))
		}
	}
	// What only learns names.
	if !names {
		for _, protocol := range []string{ProtocolNetBIOS, ProtocolLLMNR, ProtocolDNS} {
			if p.enabled(protocol) {
				errs = append(errs, fmt.Errorf("the %s protocol is enabled, and it only learns names, which hostnames, off, doesn't keep: enable hostnames, or disable %s", protocol, protocol))
			}
		}
		for _, protocol := range []string{ProtocolSSDP, ProtocolWSD} {
			if protocol == ProtocolSSDP && p.SSDP.Enabled && p.SSDP.Names || protocol == ProtocolWSD && p.WSD.Enabled && p.WSD.Names {
				errs = append(errs, fmt.Errorf("the names of the %s protocol are on, and hostnames, off, doesn't keep them: enable hostnames, or turn the names of %s off", protocol, protocol))
			}
		}
	}
	if p.DNS.Enabled {
		if len(p.DNS.Servers) == 0 {
			errs = append(errs, fmt.Errorf("the %s protocol is enabled without servers: it asks only those it is given", ProtocolDNS))
		}
		for _, server := range p.DNS.Servers {
			if !server.Addr().IsValid() || server.Addr().IsUnspecified() || server.Addr().IsMulticast() {
				errs = append(errs, fmt.Errorf("invalid server of the %s protocol: %s", ProtocolDNS, server))
			}
		}
	}
	return errs
}

// enabled tells whether the protocol of that name is enabled, whatever its family.
func (p Protocols) enabled(protocol string) bool {
	switch protocol {
	case ProtocolNDP:
		return p.NDP.Enabled
	case ProtocolPing:
		return p.Ping.Enabled
	case ProtocolSSDP:
		return p.SSDP.Enabled
	case ProtocolWSD:
		return p.WSD.Enabled
	case ProtocolMDNS:
		return p.MDNS.Enabled
	case ProtocolARP:
		return p.ARP.Enabled
	case ProtocolARPSweep:
		return p.ARPSweep.Enabled
	case ProtocolARPListen:
		return p.ARPListen.Enabled
	case ProtocolDHCP:
		return p.DHCP.Enabled
	case ProtocolLLDP:
		return p.LLDP.Enabled
	case ProtocolNetBIOS:
		return p.NetBIOS.Enabled
	case ProtocolLLMNR:
		return p.LLMNR.Enabled
	case ProtocolDNS:
		return p.DNS.Enabled
	}
	return false
}

// withDefaults fills in what is left zero: the families' lifetimes and the names', the
// rediscovery interval, from the families that probe, and the options of the protocols.
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
	if c.Protocols.ARPSweep.MaxPrefix == 0 {
		c.Protocols.ARPSweep.MaxPrefix = arp.DefaultSweepPrefix
	}
	// Its own copy, with the port of DNS where none is given.
	c.Protocols.DNS.Servers = slices.Clone(c.Protocols.DNS.Servers)
	for i, server := range c.Protocols.DNS.Servers {
		if server.Port() == 0 {
			c.Protocols.DNS.Servers[i] = netip.AddrPortFrom(server.Addr(), rdns.Port)
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

// listensIPv6 and the others tell what of the families is on.
func (c Config) listensIPv6() bool { return c.IPv6.Enabled && c.IPv6.Listen }
func (c Config) probesIPv6() bool  { return c.IPv6.Enabled && c.IPv6.Listen && c.IPv6.Active }
func (c Config) listensIPv4() bool { return c.IPv4.Enabled && c.IPv4.Listen }
func (c Config) probesIPv4() bool  { return c.IPv4.Enabled && c.IPv4.Listen && c.IPv4.Active }

// runs tells whether a protocol runs: enabled, and its family on, and listening, or for the sweep
// probing. A protocol of either family runs while one listens; one that only learns names, with
// the names kept; and the reverse DNS, which is of no family, whatever they are.
func (c Config) runs(protocol string) bool {
	if !c.Protocols.enabled(protocol) {
		return false
	}
	switch protocol {
	case ProtocolNDP, ProtocolPing, ProtocolSSDP, ProtocolWSD:
		return c.listensIPv6()
	case ProtocolARP, ProtocolARPListen:
		return c.listensIPv4()
	case ProtocolARPSweep:
		return c.probesIPv4()
	case ProtocolNetBIOS:
		return c.listensIPv4() && c.Hostnames.Enabled
	case ProtocolLLMNR:
		return (c.listensIPv6() || c.listensIPv4()) && c.Hostnames.Enabled
	case ProtocolDNS:
		return c.Hostnames.Enabled
	}
	return c.listensIPv6() || c.listensIPv4()
}

// running are the protocols that run, in the order of ProtocolNames.
func (c Config) running() []string {
	var running []string
	for _, protocol := range ProtocolNames() {
		if c.runs(protocol) {
			running = append(running, protocol)
		}
	}
	return running
}

// sweepPrefix is the largest subnet asked whole, by the sweep and by SolicitIPv4 without prefixes:
// the max_prefix of the sweep while it is enabled, and so validated. Of one that is off the
// option is not looked at, as none is: the default then, whatever it says.
func (c Config) sweepPrefix() int {
	if !c.Protocols.ARPSweep.Enabled {
		return arp.DefaultSweepPrefix
	}
	return c.Protocols.ARPSweep.MaxPrefix
}

// fetchesNames tells whether SSDP, or WS-Discovery, asks the hosts that answer it their name.
func (c Config) fetchesNames(protocol string) bool {
	switch protocol {
	case ProtocolSSDP:
		return c.runs(protocol) && c.Protocols.SSDP.Names && c.Hostnames.Enabled
	case ProtocolWSD:
		return c.runs(protocol) && c.Protocols.WSD.Names && c.Hostnames.Enabled
	}
	return false
}

// namesLocally tells whether a protocol of the naming layer runs on the interfaces: those that
// hear on one, or ask from it.
func (c Config) namesLocally() bool {
	return c.runs(ProtocolMDNS) || c.runs(ProtocolNetBIOS) || c.runs(ProtocolLLMNR) || c.runs(ProtocolDHCP) || c.runs(ProtocolLLDP)
}

// naming tells whether the naming layer has anything to do: a protocol of it runs, on the
// interfaces or on none, or one of the discovery fetches names.
func (c Config) naming() bool {
	return c.namesLocally() || c.runs(ProtocolDNS) || c.fetchesNames(ProtocolSSDP) || c.fetchesNames(ProtocolWSD)
}

// asksNames tells whether anything asks the hosts their name, once in a rediscovery.
func (c Config) asksNames() bool {
	return c.Hostnames.Enabled && (c.runs(ProtocolMDNS) && c.Protocols.MDNS.Ask || c.runs(ProtocolNetBIOS) || c.runs(ProtocolLLMNR) || c.runs(ProtocolDNS))
}
