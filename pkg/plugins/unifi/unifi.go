// Package unifi is a plugin of a UniFi gateway: the clients its UniFi Network knows are there,
// with their addresses and names, through the UniFi Network API.
package unifi

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
	"github.com/miguelangel-nubla/ipv6disc/pkg/unifi"
)

func init() {
	plugins.Describe("unifi", "A UniFi gateway, through the UniFi Network API: the clients connected now, of a UniFi OS console or UniFi OS Server, or of a self-hosted Network Application. Their IPv4 address, their IPv6 addresses where UniFi has them, the host name they gave, and the name you gave them in UniFi.")
	plugins.Register("unifi", func(name string, config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return nil, err
		}
		return NewUniFiPlugin(name, cfg, lifetime), nil
	},
		plugins.Field{Name: "interval", Required: true, Type: plugins.FieldDuration, Description: "How often the clients are read, as 60s or 5m."},
		plugins.Field{Name: "address", Required: true, Description: "The console, as https://192.168.1.1, or the self-hosted Network Application, as https://192.168.1.2:8443."},
		plugins.Field{Name: "api_key", Description: "An API key of UniFi OS: in the console, Settings, Control Plane, Integrations. A self-hosted Network Application has none: give username and password instead."},
		plugins.Field{Name: "username", Description: "A local user, instead of api_key, without two-factor authentication. Reading is enough."},
		plugins.Field{Name: "password", Description: "Its password."},
		plugins.Field{Name: "site", Description: "The site, by its name in the API: default unless you made others. Default: default."},
		plugins.Field{Name: "tls_fingerprint", Description: "The SHA-256 fingerprint of the console's certificate, as 64 hex digits, colons allowed. For when the system's CAs can't verify it, as with the one a console makes for itself."},
	)
}

const configFormat = "interval,address,api_key,username,password[,site[,tls_fingerprint]]"

// Config is the settings of a unifi plugin.
type Config struct {
	// How often the clients are read. It must be positive.
	Interval time.Duration
	Address  string
	// An API key, of UniFi OS; or a user, of either.
	APIKey   string
	Username string
	Password string
	// The site's name in the API: default, unless ParseConfig is given another.
	Site string
	// The SHA-256 fingerprint of the certificate: 64 lowercase hex digits, as ParseConfig leaves it.
	TLSFingerprint string
}

// ParseConfig reads interval,address,api_key,username,password[,site[,tls_fingerprint]]: an API
// key, or a username and password. The spaces around a value are dropped, but those of the
// password, which are its own.
func ParseConfig(config string) (Config, error) {
	parts := plugins.SplitParams(config)
	if len(parts) < 2 || len(parts) > 7 {
		return Config{}, fmt.Errorf("invalid unifi config format, expected: %s", configFormat)
	}
	// The params given by name leave out the empty ones at the end.
	for len(parts) < 5 {
		parts = append(parts, "")
	}
	for i := range parts {
		if i != 4 {
			parts[i] = strings.TrimSpace(parts[i])
		}
	}
	interval, err := time.ParseDuration(parts[0])
	if err != nil {
		return Config{}, fmt.Errorf("invalid interval format: %w", err)
	}
	if interval <= 0 {
		return Config{}, fmt.Errorf("invalid interval %s: it must be positive", interval)
	}
	cfg := Config{Interval: interval, Address: parts[1], APIKey: parts[2], Username: parts[3], Password: parts[4], Site: "default"}
	if len(parts) > 5 && parts[5] != "" {
		cfg.Site = parts[5]
	}
	if err := cfg.client().Check(); err != nil {
		return Config{}, fmt.Errorf("a unifi plugin: %w", err)
	}
	if len(parts) > 6 && parts[6] != "" {
		cfg.TLSFingerprint = strings.ToLower(strings.ReplaceAll(parts[6], ":", ""))
		if hash, err := hex.DecodeString(cfg.TLSFingerprint); err != nil || len(hash) != sha256.Size {
			return Config{}, fmt.Errorf("invalid tls_fingerprint %q: expected the SHA-256 fingerprint of the certificate, 64 hex digits", parts[6])
		}
	}
	return cfg, nil
}

// client is the config of the UniFi Network client.
func (c Config) client() unifi.Config {
	return unifi.Config{Address: c.Address, APIKey: c.APIKey, Username: c.Username, Password: c.Password, Site: c.Site}
}

// UniFiPlugin reads the clients a UniFi Network knows are connected now.
type UniFiPlugin struct {
	plugins.Poller

	name     string
	config   Config
	lifetime time.Duration
	// The client, which keeps the session between polls; or why there is none, of a config made
	// by hand that ParseConfig would have refused.
	client    *unifi.Client
	clientErr error
}

func NewUniFiPlugin(name string, config Config, lifetime time.Duration) *UniFiPlugin {
	tlsConfig := &tls.Config{}
	if config.TLSFingerprint != "" {
		// The certificate is checked by its fingerprint only. VerifyPeerCertificate is not called
		// for a resumed session, so this config must never get a ClientSessionCache.
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("no certificates received")
				}
				fingerprint := sha256.Sum256(rawCerts[0])
				if got := hex.EncodeToString(fingerprint[:]); got != config.TLSFingerprint {
					return fmt.Errorf("tls fingerprint mismatch: expected %s, got %s", config.TLSFingerprint, got)
				}
				return nil
			},
		}
	}
	// The poll's context bounds each request.
	client, err := unifi.New(config.client(), tlsConfig, 0)
	return &UniFiPlugin{name: name, config: config, lifetime: lifetime, client: client, clientErr: err}
}

func (p *UniFiPlugin) Name() string {
	return p.name
}

func (p *UniFiPlugin) Start(ctx context.Context, state *ipv6disc.State, onError func(error)) error {
	return p.Run(ctx, p.config.Interval, func() (int, error) { return p.discover(ctx, state) }, onError)
}

// unifiClient is a client as the Network API lists it: the fields read.
type unifiClient struct {
	MAC      string   `json:"mac"`
	IP       string   `json:"ip"`
	IPv6     []string `json:"ipv6_address"`
	Hostname string   `json:"hostname"`
	Name     string   `json:"name"`
}

func (p *UniFiPlugin) discover(ctx context.Context, state *ipv6disc.State) (int, error) {
	if p.clientErr != nil {
		return 0, p.clientErr
	}
	ctx, cancel := context.WithTimeout(ctx, plugins.PollTimeout)
	defer cancel()

	var clients []unifiClient
	if err := p.client.Call(ctx, http.MethodGet, "/clients/active?includeUnifiDevices=true", nil, &clients); err != nil {
		return 0, fmt.Errorf("error reading the unifi clients: %w", err)
	}

	found := 0
	for _, c := range clients {
		hw, err := net.ParseMAC(c.MAC)
		// A group's MAC is no host's.
		if err != nil || hw[0]&1 != 0 {
			continue
		}
		var addrs []string
		if state.IPv4() && c.IP != "" {
			addrs = append(addrs, c.IP)
		}
		if state.IPv6() {
			addrs = append(addrs, c.IPv6...)
		}
		for _, a := range addrs {
			ip, err := netip.ParseAddr(a)
			if err != nil || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			ip = ip.Unmap().WithZone("")
			if (ip.Is4() && !state.IPv4()) || (ip.Is6() && !state.IPv6()) {
				continue
			}
			if _, existing := state.Report(hw, ip, p.Name(), "unifi", ipv6disc.FromNeighbors, p.lifetime, nil); !existing {
				found++
			}
		}
		// The host name the client gave the gateway's DHCP server, and the one you gave it.
		if state.Names() {
			for _, name := range []string{c.Hostname, c.Name} {
				if name != "" {
					state.ReportName(hw, name, p.Name(), ipv6disc.FromLeases, p.lifetime)
				}
			}
		}
	}
	return found, nil
}
