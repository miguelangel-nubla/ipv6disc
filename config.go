package ipv6disc

import (
	"errors"
	"fmt"
	"time"
)

// Config is how a Worker discovers addresses: the same for each family.
type Config struct {
	// How long an address stays after it was last seen.
	Lifetime time.Duration
	// How often the active discovery runs.
	Rediscover time.Duration

	IPv6 Family
	IPv4 Family
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
	return errors.Join(errs...)
}

// listensIPv6 and the others tell what of the configuration runs.
func (c Config) listensIPv6() bool { return c.IPv6.Enabled && c.IPv6.Listen }
func (c Config) probesIPv6() bool  { return c.IPv6.Enabled && c.IPv6.Listen && c.IPv6.Active }
func (c Config) listensIPv4() bool { return c.IPv4.Enabled && c.IPv4.Listen }
func (c Config) probesIPv4() bool  { return c.IPv4.Enabled && c.IPv4.Listen && c.IPv4.Active }
