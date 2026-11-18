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
	plugins.Register("linux", func(name string, config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return nil, err
		}
		return NewLinuxPlugin(name, cfg, lifetime), nil
	})
}

type Config = plugins.SSHConfig

func ParseConfig(config string) (Config, error) {
	return plugins.ParseSSHConfig("linux", config)
}

// LinuxPlugin reads the neighbor table of a Linux host, `ip -6 neigh`, over SSH.
type LinuxPlugin struct {
	plugins.Poller

	name     string
	config   Config
	lifetime time.Duration
	// Whether the unverified host key was reported.
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

	output, hostKey, err := plugins.RunSSH(ctx, p.config, "ip -6 neigh")
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
// A line is: fe80::21a:2bff:fe3c:4d5e dev eth0 lladdr 00:1a:2b:3c:4d:5e [router] STALE
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
		// entries confirmed recently count.
		switch fields[len(fields)-1] {
		case "FAILED", "INCOMPLETE", "STALE":
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
