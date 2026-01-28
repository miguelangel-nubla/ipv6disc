package mikrotik

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/go-routeros/routeros/v3"
	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

func init() {
	plugins.Register("mikrotik", func(name string, config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return nil, err
		}
		return NewMikrotikPlugin(name, cfg, lifetime), nil
	})
}

func ParseConfig(config string) (Config, error) {
	parts := strings.Split(config, ",")
	if len(parts) < 4 {
		return Config{}, fmt.Errorf("invalid mikrotik config format, expected: interval,address,username,password[,use_tls[,tls_fingerprint]]")
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
		cfg.UseTLS = strings.ToLower(parts[4]) == "true"
	}

	if len(parts) > 5 {
		cfg.TLSFingerprint = strings.ToLower(strings.ReplaceAll(parts[5], ":", ""))
	}

	return cfg, nil
}

type Config struct {
	Interval       time.Duration
	Address        string
	Username       string
	Password       string
	UseTLS         bool
	TLSFingerprint string
}

type MikrotikPlugin struct {
	name     string
	config   Config
	lifetime time.Duration

	discoveryCount int
	lastRun        time.Time
	lastError      error
}

func NewMikrotikPlugin(name string, config Config, lifetime time.Duration) *MikrotikPlugin {
	return &MikrotikPlugin{
		name:     name,
		config:   config,
		lifetime: lifetime,
	}
}

func (p *MikrotikPlugin) Name() string {
	return p.name
}

func (p *MikrotikPlugin) Stats() map[string]any {
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

func (p *MikrotikPlugin) Start(ctx context.Context, state *ipv6disc.State, onError func(error)) error {
	ticker := time.NewTicker(p.config.Interval)
	defer ticker.Stop()

	// Initial discovery
	if err := p.discover(state); err != nil {
		p.lastError = err
		if onError != nil {
			onError(err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := p.discover(state); err != nil {
				p.lastError = err
				if onError != nil {
					onError(err)
				}
			}
		}
	}
}

func (p *MikrotikPlugin) discover(state *ipv6disc.State) error {
	p.lastRun = time.Now()
	var client *routeros.Client
	var err error

	defaultPort := "8728"
	if p.config.UseTLS {
		defaultPort = "8729"
	}
	addr := plugins.FormatAddress(p.config.Address, defaultPort)

	if p.config.UseTLS {
		var tlsConfig *tls.Config
		if p.config.TLSFingerprint != "" {
			tlsConfig = &tls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return fmt.Errorf("no certificates received")
					}
					fingerprint := sha256.Sum256(rawCerts[0])
					got := hex.EncodeToString(fingerprint[:])
					if got != p.config.TLSFingerprint {
						return fmt.Errorf("tls fingerprint mismatch: expected %s, got %s", p.config.TLSFingerprint, got)
					}
					return nil
				},
			}
		}
		client, err = routeros.DialTLS(addr, p.config.Username, p.config.Password, tlsConfig)
	} else {
		client, err = routeros.Dial(addr, p.config.Username, p.config.Password)
	}

	if err != nil {
		return fmt.Errorf("error connecting to mikrotik: %w", err)
	}
	defer client.Close()

	reply, err := client.Run("/ipv6/neighbor/print")
	if err != nil {
		return fmt.Errorf("error fetching ipv6 neighbors: %w", err)
	}
	p.lastError = nil

	for _, re := range reply.Re {
		macStr := re.Map["mac-address"]
		ipStr := re.Map["address"]

		if macStr == "" || ipStr == "" {
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
			p.discoveryCount++
		}
	}

	return nil
}
