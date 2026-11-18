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
	plugins.Describe("mikrotik", "A Mikrotik router, over its API: `/ipv6/neighbor` for IPv6, `/ip/arp` for IPv4.")
	plugins.Register("mikrotik", func(name string, config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return nil, err
		}
		return NewMikrotikPlugin(name, cfg, lifetime), nil
	},
		plugins.Field{Name: "interval", Required: true, Description: "How often the tables are read: 60s, 5m."},
		plugins.Field{Name: "address", Required: true, Description: "The router, with its port unless the default: 8728, or 8729 with TLS."},
		plugins.Field{Name: "username", Required: true, Description: "An API user: the read and api policies are enough."},
		plugins.Field{Name: "password", Description: "Its password."},
		plugins.Field{Name: "use_tls", Description: "true: the API over TLS, the api-ssl service."},
		plugins.Field{Name: "tls_fingerprint", Description: "The SHA-256 fingerprint of the router's certificate, in hex, when it can't be verified otherwise."},
	)
}

func ParseConfig(config string) (Config, error) {
	parts := plugins.SplitParams(config)
	if len(parts) < 4 {
		return Config{}, fmt.Errorf("invalid mikrotik config format, expected: interval,address,username,password[,use_tls[,tls_fingerprint]]")
	}

	interval, err := time.ParseDuration(parts[0])
	if err != nil {
		return Config{}, fmt.Errorf("invalid interval format: %w", err)
	}
	if interval <= 0 {
		return Config{}, fmt.Errorf("invalid interval %s: it must be positive", interval)
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

// MikrotikPlugin reads the IPv6 neighbor table of a RouterOS router over its API.
type MikrotikPlugin struct {
	plugins.Poller

	name     string
	config   Config
	lifetime time.Duration
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

func (p *MikrotikPlugin) Start(ctx context.Context, state *ipv6disc.State, onError func(error)) error {
	return p.Run(ctx, p.config.Interval, func() (int, error) { return p.discover(ctx, state) }, onError)
}

func (p *MikrotikPlugin) discover(ctx context.Context, state *ipv6disc.State) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, plugins.PollTimeout)
	defer cancel()

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
		client, err = routeros.DialTLSContext(ctx, plugins.FormatAddress(p.config.Address, "8729"), p.config.Username, p.config.Password, tlsConfig)
	} else {
		client, err = routeros.DialContext(ctx, plugins.FormatAddress(p.config.Address, "8728"), p.config.Username, p.config.Password)
	}

	if err != nil {
		return 0, fmt.Errorf("error connecting to mikrotik: %w", err)
	}
	defer client.Close()

	// The tables of the families the state takes, alike.
	var tables []string
	if state.IPv6() {
		tables = append(tables, "/ipv6/neighbor/print")
	}
	if state.IPv4() {
		tables = append(tables, "/ip/arp/print")
	}

	found := 0
	for _, table := range tables {
		reply, err := client.RunContext(ctx, table)
		if err != nil {
			return found, fmt.Errorf("error fetching %s: %w", table, err)
		}

		for _, re := range reply.Re {
			macStr := re.Map["mac-address"]
			ipStr := re.Map["address"]

			if macStr == "" || ipStr == "" || !neighborInUse(re.Map["status"]) {
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
				found++
			}
		}
	}

	return found, nil
}

// neighborInUse tells whether a neighbor entry shows its host is there now. RouterOS keeps an entry
// long after the host is gone, as stale or failed, and registering it would refresh the address at
// every poll, so it would never expire.
func neighborInUse(status string) bool {
	return status != "stale" && status != "failed"
}
