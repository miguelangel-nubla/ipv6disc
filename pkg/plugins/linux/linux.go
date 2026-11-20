package linux

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

func init() {
	plugins.Describe("linux", "A Linux host, as OpenWrt, over SSH: `ip neigh`.")
	plugins.Register("linux", func(name string, config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return nil, err
		}
		return NewLinuxPlugin(name, cfg, lifetime), nil
	}, plugins.SSHFields...)
}

type Config = plugins.SSHConfig

func ParseConfig(config string) (Config, error) {
	return plugins.ParseSSHConfig("linux", config)
}

// LinuxPlugin reads the neighbor table of a Linux host over SSH, `ip neigh`, of the families the
// state takes.
type LinuxPlugin struct {
	plugins.Poller

	name     string
	config   Config
	lifetime time.Duration
	// Whether the unverified host key was reported: once, after the first poll that succeeds.
	// Without a lock: only the polls touch it, one at a time, so Start is called once.
	warned bool
}

func NewLinuxPlugin(name string, config Config, lifetime time.Duration) *LinuxPlugin {
	return &LinuxPlugin{
		name:     name,
		config:   config,
		lifetime: lifetime,
	}
}

func (p *LinuxPlugin) Name() string {
	return p.name
}

func (p *LinuxPlugin) Start(ctx context.Context, state *ipv6disc.State, onError func(error)) error {
	return p.Run(ctx, p.config.Interval, func() (int, error) { return p.discover(ctx, state, onError) }, onError)
}

func (p *LinuxPlugin) discover(ctx context.Context, state *ipv6disc.State, onError func(error)) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, plugins.PollTimeout)
	defer cancel()

	// The families the state takes, in one table: their lines are alike.
	var command string
	switch {
	case state.IPv6() && state.IPv4():
		command = "ip neigh"
	case state.IPv4():
		command = "ip -4 neigh"
	case state.IPv6():
		command = "ip -6 neigh"
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
	return p.parseNDPOutput(string(output), state), nil
}

// parseNDPOutput registers the neighbors in `ip -6 neigh` output, and returns how many are new.
// A line is: fe80::21a:2bff:fe3c:4d5e dev eth0 lladdr 00:1a:2b:3c:4d:5e [router] [extern_learn] STALE [proto zebra]
//
// The lines that are not of a neighbor, as a warning of the command, are skipped.
func (p *LinuxPlugin) parseNDPOutput(output string, state *ipv6disc.State) int {
	scanner := bufio.NewScanner(strings.NewReader(output))
	count := 0

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}

		macIndex := slices.Index(fields, "lladdr") + 1
		if macIndex == 0 || macIndex >= len(fields) {
			continue
		}

		// A stale entry can stay long after its host is gone, and registering it would refresh
		// the address at every poll, so it would never expire: as for Mikrotik, only the
		// entries confirmed recently count. The state is not always the last field: an entry
		// installed by a routing daemon has its protocol after it.
		if slices.ContainsFunc(fields[macIndex+1:], func(field string) bool {
			return field == "FAILED" || field == "INCOMPLETE" || field == "STALE"
		}) {
			continue
		}

		hw, err := net.ParseMAC(fields[macIndex])
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
