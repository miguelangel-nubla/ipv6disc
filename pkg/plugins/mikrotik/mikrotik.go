package mikrotik

import (
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
	plugins.Register("mikrotik", func(config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return nil, err
		}
		return NewMikrotikPlugin(cfg, lifetime), nil
	})
}

func ParseConfig(config string) (Config, error) {
	parts := strings.Split(config, ",")
	if len(parts) < 3 {
		return Config{}, fmt.Errorf("invalid mikrotik config format, expected: address,username,password[,use_tls[,tls_fingerprint]]")
	}

	cfg := Config{
		Address:  parts[0],
		Username: parts[1],
		Password: parts[2],
	}

	if len(parts) > 3 {
		cfg.UseTLS = strings.ToLower(parts[3]) == "true"
	}

	if len(parts) > 4 {
		cfg.TLSFingerprint = strings.ToLower(strings.ReplaceAll(parts[4], ":", ""))
	}

	return cfg, nil
}

type Config struct {
	Address        string
	Username       string
	Password       string
	UseTLS         bool
	TLSFingerprint string
}

type MikrotikPlugin struct {
	config   Config
	lifetime time.Duration

	discoveryCount int
	lastRun        time.Time
	lastError      error
}

func NewMikrotikPlugin(config Config, lifetime time.Duration) *MikrotikPlugin {
	return &MikrotikPlugin{
		config:   config,
		lifetime: lifetime,
	}
}

func (p *MikrotikPlugin) Name() string {
	return "mikrotik:" + p.config.Address
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

func (p *MikrotikPlugin) Discover(state *ipv6disc.State) error {
	p.lastRun = time.Now()
	var client *routeros.Client
	var err error

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
		client, err = routeros.DialTLS(p.config.Address, p.config.Username, p.config.Password, tlsConfig)
	} else {
		client, err = routeros.Dial(p.config.Address, p.config.Username, p.config.Password)
	}

	if err != nil {
		p.lastError = err
		return fmt.Errorf("error connecting to mikrotik: %w", err)
	}
	defer client.Close()

	reply, err := client.Run("/ipv6/neighbor/print")
	if err != nil {
		p.lastError = err
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

		// Mikrotik doesn't provide the interface name in this table in a way that is easily mapable to the local machine's interface names
		// However, the worker expects a netip.Addr which may include a zone.
		// We use the plugin name as the source to indicate which router this address was discovered on.

		if _, existing := state.Register(hw, ip, p.Name(), p.lifetime, nil); !existing {
			p.discoveryCount++
		}
	}

	return nil
}
