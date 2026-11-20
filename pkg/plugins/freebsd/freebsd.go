package freebsd

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/arp"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

func init() {
	plugins.Describe("freebsd", "A FreeBSD host, as pfSense or OPNsense, over SSH: `ndp -an` for IPv6, `arp -an` for IPv4, and with `-hostnames` the names of the DHCP leases of ISC dhcpd, Kea and dnsmasq.")
	plugins.Register("freebsd", func(name string, config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return nil, err
		}
		return NewFreeBSDPlugin(name, cfg, lifetime), nil
	}, plugins.SSHFields...)
}

type Config = plugins.SSHConfig

func ParseConfig(config string) (Config, error) {
	return plugins.ParseSSHConfig("freebsd", config)
}

// FreeBSDPlugin reads the neighbor tables of a FreeBSD host over SSH, of the families the state
// takes: `ndp -an` for IPv6, `arp -an` for IPv4.
type FreeBSDPlugin struct {
	plugins.Poller

	name     string
	config   Config
	lifetime time.Duration
	// Whether the unverified host key was reported: once, after the first poll that succeeds.
	// Without a lock: only the polls touch it, one at a time, so Start is called once.
	warned bool
}

func NewFreeBSDPlugin(name string, config Config, lifetime time.Duration) *FreeBSDPlugin {
	return &FreeBSDPlugin{
		name:     name,
		config:   config,
		lifetime: lifetime,
	}
}

func (p *FreeBSDPlugin) Name() string {
	return p.name
}

func (p *FreeBSDPlugin) Start(ctx context.Context, state *ipv6disc.State, onError func(error)) error {
	return p.Run(ctx, p.config.Interval, func() (int, error) { return p.discover(ctx, state, onError) }, onError)
}

func (p *FreeBSDPlugin) discover(ctx context.Context, state *ipv6disc.State, onError func(error)) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, plugins.PollTimeout)
	defer cancel()

	// The tables of the families the state takes, in one session.
	var command string
	switch {
	case state.IPv6() && state.IPv4():
		command = "ndp -an; echo " + arpMarker + "; arp -an"
	case state.IPv4():
		command = "echo " + arpMarker + "; arp -an"
	case state.IPv6():
		command = "ndp -an"
	default:
		return 0, nil
	}
	if state.Names() {
		command += leasesCommand
	}
	output, hostKey, err := plugins.RunSSH(ctx, p.config, command)
	if err != nil {
		return 0, err
	}
	if p.config.HostKey == "" && !p.warned && onError != nil {
		p.warned = true
		onError(plugins.HostKeyWarning(p.config.Address, hostKey))
	}

	// Without the marker, IPv6 only, all of it is of ndp. The output has the stderr of the commands
	// too, and the exit status is that of the last one: the lines that are not of a table, as a
	// warning or the error of an ndp that failed, are skipped by the parsers.
	tables, leases, _ := strings.Cut(string(output), leasesMarker+"\n")
	ndpOutput, arpOutput, _ := strings.Cut(tables, arpMarker+"\n")
	found, neighbors := p.parseNeighbors(ndpOutput, state)
	for _, n := range arp.ParseBSD(arpOutput) {
		neighbors[n.IP] = n.MAC
		if _, existing := state.Register(n.MAC, n.IP, p.Name(), p.lifetime, nil); !existing {
			found++
		}
	}

	isc, rest, _ := strings.Cut(leases, keaMarker+"\n")
	kea, dnsmasq, _ := strings.Cut(rest, dnsmasqMarker+"\n")
	plugins.RegisterLeases(state, slices.Concat(plugins.ParseISCLeases(isc), plugins.ParseKeaLeases(kea), plugins.ParseDnsmasqLeases(dnsmasq)), neighbors, p.Name(), p.lifetime)
	return found, nil
}

// The markers separate the tables from the leases, and those of each DHCP server; and
// leasesCommand follows the tables' command to read them, where pfSense and OPNsense keep them:
// those of ISC dhcpd, of Kea, of DHCPv4 and DHCPv6, and of dnsmasq. A file that isn't there, as
// those of the servers the host doesn't run, says nothing, and the last command succeeds, as the
// exit status is its own.
const (
	leasesMarker  = "--- ipv6disc leases ---"
	keaMarker     = "--- ipv6disc kea ---"
	dnsmasqMarker = "--- ipv6disc dnsmasq ---"
	leasesCommand = "; echo '" + leasesMarker + "'; cat /var/dhcpd/var/db/dhcpd.leases 2>/dev/null" +
		"; echo '" + keaMarker + "'; cat /var/lib/kea/dhcp4.leases /var/lib/kea/dhcp6.leases /var/db/kea/kea-leases4.csv /var/db/kea/kea-leases6.csv 2>/dev/null" +
		"; echo '" + dnsmasqMarker + "'; cat /var/db/dnsmasq.leases 2>/dev/null; true"
)

// arpMarker separates the outputs of ndp and arp.
const arpMarker = "--- ipv6disc arp ---"

// parseNDPOutput registers the neighbors in `ndp -an` output, and returns how many are new.
//
//	Neighbor                             Linklayer Address  Netif Expire    S Flags
//	2001:db8::1                          00:11:22:33:44:55   em0 permanent R
//	fe80::211:22ff:fe33:4455%em0         00:11:22:33:44:55   em0 permanent R
func (p *FreeBSDPlugin) parseNDPOutput(output string, state *ipv6disc.State) int {
	count, _ := p.parseNeighbors(output, state)
	return count
}

// parseNeighbors is parseNDPOutput, which returns the neighbors too, registered or known already:
// the MAC of each address, for the leases that only have an address.
func (p *FreeBSDPlugin) parseNeighbors(output string, state *ipv6disc.State) (int, map[netip.Addr]net.HardwareAddr) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	count := 0
	neighbors := make(map[netip.Addr]net.HardwareAddr)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[0] == "Neighbor" {
			continue
		}

		// A stale entry can stay long after its host is gone, and registering it would refresh
		// the address at every poll, so it would never expire: as for Mikrotik, only the
		// entries confirmed recently count. The state is the fifth field.
		if len(fields) > 4 && fields[4] == "S" {
			continue
		}

		// An incomplete entry has "(incomplete)" for its MAC, which doesn't parse either.
		hw, err := net.ParseMAC(fields[1])
		if err != nil {
			continue
		}

		// A link-local address comes with the host's interface as its zone, fe80::1%em0: the state
		// keys and shows addresses without their zone, so it is never taken for an interface of
		// this machine.
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}

		neighbors[ip.WithZone("")] = hw
		if _, existing := state.Register(hw, ip, p.Name(), p.lifetime, nil); !existing {
			count++
		}
	}
	return count, neighbors
}
