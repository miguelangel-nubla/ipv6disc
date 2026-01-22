package freebsd

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
	"golang.org/x/crypto/ssh"
)

func init() {
	plugins.Register("freebsd", func(config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return nil, err
		}
		return NewFreeBSDPlugin(cfg, lifetime), nil
	})
}

func ParseConfig(config string) (Config, error) {
	parts := strings.Split(config, ",")
	if len(parts) < 4 {
		return Config{}, fmt.Errorf("invalid freebsd config format, expected: interval,address,username,password[,identity_file]")
	}

	interval, err := time.ParseDuration(parts[0])
	if err != nil {
		return Config{}, fmt.Errorf("invalid interval format: %w", err)
	}

	cfg := Config{
		Interval: interval,
		Address:  parts[1],
		Username: parts[2],
		Password: parts[3],
	}

	if len(parts) > 4 {
		cfg.IdentityFile = parts[4]
	}

	return cfg, nil
}

type Config struct {
	Interval     time.Duration
	Address      string
	Username     string
	Password     string
	IdentityFile string
}

type FreeBSDPlugin struct {
	config   Config
	lifetime time.Duration

	discoveryCount int
	lastRun        time.Time
	lastError      error
}

func NewFreeBSDPlugin(config Config, lifetime time.Duration) *FreeBSDPlugin {
	return &FreeBSDPlugin{
		config:   config,
		lifetime: lifetime,
	}
}

func (p *FreeBSDPlugin) Name() string {
	return "freebsd:" + p.config.Address
}

func (p *FreeBSDPlugin) Stats() map[string]any {
	lastErr := ""
	if p.lastError != nil {
		lastErr = p.lastError.Error()
	}
	return map[string]any{
		"discovery_count": p.discoveryCount,
		"last_run":        p.lastRun,
		"last_error":      lastErr,
	}
}

func (p *FreeBSDPlugin) Start(ctx context.Context, state *ipv6disc.State) error {
	ticker := time.NewTicker(p.config.Interval)
	defer ticker.Stop()

	// Initial discovery
	if err := p.discover(state); err != nil {
		p.lastError = err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := p.discover(state); err != nil {
				p.lastError = err
			}
		}
	}
}

func (p *FreeBSDPlugin) discover(state *ipv6disc.State) error {
	p.lastRun = time.Now()

	authMethods := []ssh.AuthMethod{}

	if p.config.IdentityFile != "" {
		key, err := os.ReadFile(p.config.IdentityFile)
		if err != nil {
			return fmt.Errorf("unable to read private key: %w", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return fmt.Errorf("unable to parse private key: %w", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if p.config.Password != "" {
		authMethods = append(authMethods, ssh.Password(p.config.Password))
	}

	config := &ssh.ClientConfig{
		User:            p.config.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := plugins.FormatAddress(p.config.Address, "22")

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput("ndp -an")
	if err != nil {
		return fmt.Errorf("failed to run ndp -an: %w", err)
	}
	p.lastError = nil

	p.discoveryCount += p.parseNDPOutput(string(output), state)

	return nil
}

func (p *FreeBSDPlugin) parseNDPOutput(output string, state *ipv6disc.State) int {
	scanner := bufio.NewScanner(strings.NewReader(output))
	count := 0
	// Header: Neighbor                             Linklayer Address  Netif Expire    S Flags
	// Example: 2001:db8::1                          00:11:22:33:44:55   em0 permanent R
	// Example: fe80::211:22ff:fe33:4455%em0         00:11:22:33:44:55   em0 permanent R

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// Skip header
		if fields[0] == "Neighbor" {
			continue
		}

		ipStr := fields[0]
		macStr := fields[1]
		// netif := fields[2] // Not currently used, but could be useful

		if macStr == "(incomplete)" {
			continue
		}

		hw, err := net.ParseMAC(macStr)
		if err != nil {
			continue
		}

		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}

		if _, existing := state.Register(hw, ip, p.Name(), p.lifetime, nil); !existing {
			count++
		}
	}
	return count
}
