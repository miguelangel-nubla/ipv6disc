package freebsd

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

func init() {
	plugins.Register("freebsd", func(name string, config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return nil, err
		}
		return NewFreeBSDPlugin(name, cfg, lifetime), nil
	})
}

type Config = plugins.SSHConfig

func ParseConfig(config string) (Config, error) {
	return plugins.ParseSSHConfig("freebsd", config)
}

// FreeBSDPlugin reads the neighbor table of a FreeBSD host, `ndp -an`, over SSH.
type FreeBSDPlugin struct {
	plugins.Poller

	name     string
	config   Config
	lifetime time.Duration
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
	return p.Run(ctx, p.config.Interval, func() (int, error) { return p.discover(state) }, onError)
}

func (p *FreeBSDPlugin) discover(state *ipv6disc.State) (int, error) {
	output, err := plugins.RunSSH(p.config, "ndp -an")
	if err != nil {
		return 0, err
	}
	return p.parseNDPOutput(string(output), state), nil
}

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
