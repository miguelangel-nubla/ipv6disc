package freebsd

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/arp"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

func init() {
	plugins.Register("freebsd", func(name string, config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return nil, err
		}
		return NewFreeBSDPlugin(name, cfg, lifetime), nil
	}, "interval", "address", "username", "password", "identity_file", "host_key")
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
	// Whether the unverified host key was reported.
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
	output, hostKey, err := plugins.RunSSH(ctx, p.config, command)
	if err != nil {
		return 0, err
	}
	if p.config.HostKey == "" && !p.warned && onError != nil {
		p.warned = true
		onError(plugins.HostKeyWarning(p.config.Address, hostKey))
	}

	ndpOutput, arpOutput, _ := strings.Cut(string(output), arpMarker+"\n")
	found := p.parseNDPOutput(ndpOutput, state)
	for _, n := range arp.ParseBSD(arpOutput) {
		if _, existing := state.Register(n.MAC, n.IP, p.Name(), p.lifetime, nil); !existing {
			found++
		}
	}
	return found, nil
}

// arpMarker separates the outputs of ndp and arp.
const arpMarker = "--- ipv6disc arp ---"

// parseNDPOutput registers the neighbors in `ndp -an` output, and returns how many are new.
//
//	Neighbor                             Linklayer Address  Netif Expire    S Flags
//	2001:db8::1                          00:11:22:33:44:55   em0 permanent R
//	fe80::211:22ff:fe33:4455%em0         00:11:22:33:44:55   em0 permanent R
func (p *FreeBSDPlugin) parseNDPOutput(output string, state *ipv6disc.State) int {
	scanner := bufio.NewScanner(strings.NewReader(output))
	count := 0

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

		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}

		if _, existing := state.Register(hw, ip, p.Name(), p.lifetime, nil); !existing {
			count++
		}
	}
	return count
}
