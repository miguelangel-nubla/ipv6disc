package ipv6disc

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"time"
)

// Config is how a Worker discovers addresses: the same for each family.
type Config struct {
	// How long an address stays after it was last seen, unless its family says.
	Lifetime time.Duration
	// How often the active discovery runs.
	Rediscover time.Duration

	IPv6 Family
	IPv4 Family

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
	// reading the kernel's neighbor table.
	Listen bool
	// Probing every host of the local links, at every Rediscover. IPv6: multicast ping, SSDP
	// and WS-Discovery. IPv4: a sweep of the subnets, which broadcasts an ARP request for each
	// address. It needs Listen, which reads the answers.
	Active bool
	// How long the family's addresses stay after they were last seen, the plugins' too:
	// Config.Lifetime when zero.
	Lifetime time.Duration
}

// DefaultConfig discovers IPv6 addresses by every means, and no IPv4 ones.
func DefaultConfig() Config {
	return Config{
		Lifetime:   4 * time.Hour,
		Rediscover: 4 * time.Hour / 3,
		IPv6:       Family{Enabled: true, Listen: true, Active: true},
	}
}

func (c Config) validate() error {
	var errs []error
	for name, f := range map[string]Family{"IPv6": c.IPv6, "IPv4": c.IPv4} {
		if f.Enabled && f.Active && !f.Listen {
			errs = append(errs, fmt.Errorf("%s active discovery needs listening, which reads the answers", name))
		}
	}
	if c.Lifetime <= 0 || c.Rediscover <= 0 {
		errs = append(errs, fmt.Errorf("invalid lifetime %s or rediscovery interval %s: they must be positive", c.Lifetime, c.Rediscover))
	}
	if c.IPv6.Lifetime < 0 || c.IPv4.Lifetime < 0 {
		errs = append(errs, fmt.Errorf("invalid family lifetime: IPv6 %s, IPv4 %s", c.IPv6.Lifetime, c.IPv4.Lifetime))
	}
	for _, pattern := range slices.Concat(c.Interfaces, c.ExcludeInterfaces) {
		if _, err := path.Match(pattern, ""); err != nil {
			errs = append(errs, fmt.Errorf("invalid interface pattern %q: %w", pattern, err))
		}
	}
	return errors.Join(errs...)
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
