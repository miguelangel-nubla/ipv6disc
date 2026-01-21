package linux

import (
	"bufio"
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
	plugins.Register("linux", func(config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return nil, err
		}
		return NewLinuxPlugin(cfg, lifetime), nil
	})
}

func ParseConfig(config string) (Config, error) {
	parts := strings.Split(config, ",")
	if len(parts) < 3 {
		return Config{}, fmt.Errorf("invalid linux config format, expected: address,username,password[,identity_file]")
	}

	cfg := Config{
		Address:  parts[0],
		Username: parts[1],
		Password: parts[2],
	}

	if len(parts) > 3 {
		cfg.IdentityFile = parts[3]
	}

	return cfg, nil
}

type Config struct {
	Address      string
	Username     string
	Password     string
	IdentityFile string
}

type LinuxPlugin struct {
	config   Config
	lifetime time.Duration

	discoveryCount int
	lastRun        time.Time
	lastError      error
}

func NewLinuxPlugin(config Config, lifetime time.Duration) *LinuxPlugin {
	return &LinuxPlugin{
		config:   config,
		lifetime: lifetime,
	}
}

func (p *LinuxPlugin) Name() string {
	return "linux:" + p.config.Address
}

func (p *LinuxPlugin) Stats() map[string]any {
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

func (p *LinuxPlugin) Discover(state *ipv6disc.State) error {
	p.lastRun = time.Now()

	authMethods := []ssh.AuthMethod{}

	if p.config.IdentityFile != "" {
		key, err := os.ReadFile(p.config.IdentityFile)
		if err != nil {
			p.lastError = fmt.Errorf("unable to read private key: %v", err)
			return p.lastError
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			p.lastError = fmt.Errorf("unable to parse private key: %v", err)
			return p.lastError
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
		p.lastError = fmt.Errorf("failed to dial: %v", err)
		return p.lastError
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		p.lastError = fmt.Errorf("failed to create session: %v", err)
		return p.lastError
	}
	defer session.Close()

	output, err := session.CombinedOutput("ip -6 neigh")
	if err != nil {
		p.lastError = fmt.Errorf("failed to run ip -6 neigh: %v", err)
		return p.lastError
	}
	p.lastError = nil

	p.discoveryCount += p.parseNDPOutput(string(output), state)

	return nil
}

func (p *LinuxPlugin) parseNDPOutput(output string, state *ipv6disc.State) int {
	scanner := bufio.NewScanner(strings.NewReader(output))
	count := 0
	// Example: fe80::21a:2bff:fe3c:4d5e dev eth0 lladdr 00:1a:2b:3c:4d:5e STALE
	// Minimum fields: IP dev INTERFACE lladdr MAC STATE

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		// We expect at least: [IP] dev [IFACE] lladdr [MAC] [STATE]
		// Which is 6 tokens.
		if len(fields) < 6 {
			continue
		}

		ipStr := fields[0]

		// Find "lladdr" to locate MAC
		macIndex := -1
		for i, field := range fields {
			if field == "lladdr" {
				macIndex = i + 1
				break
			}
		}

		if macIndex == -1 || macIndex >= len(fields) {
			continue
		}

		macStr := fields[macIndex]

		stateStr := fields[len(fields)-1]
		if stateStr == "FAILED" || stateStr == "INCOMPLETE" {
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
