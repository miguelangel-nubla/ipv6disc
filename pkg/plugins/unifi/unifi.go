// Package unifi is a plugin of a UniFi gateway: the clients its UniFi Network knows are there,
// with their addresses and names, through the UniFi Network API.
package unifi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
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
	u, err := url.Parse(cfg.Address)
	switch {
	case cfg.Address == "":
		return Config{}, errors.New("a unifi plugin needs its address")
	case err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "":
		return Config{}, fmt.Errorf("invalid address %q: give the console's, as https://192.168.1.1", cfg.Address)
	case cfg.APIKey != "" && (cfg.Username != "" || cfg.Password != ""):
		return Config{}, errors.New("a unifi plugin takes api_key or username and password, not both")
	case cfg.APIKey == "" && (cfg.Username == "" || cfg.Password == ""):
		return Config{}, errors.New("a unifi plugin needs api_key, or username and password")
	}
	if len(parts) > 6 && parts[6] != "" {
		cfg.TLSFingerprint = strings.ToLower(strings.ReplaceAll(parts[6], ":", ""))
		if hash, err := hex.DecodeString(cfg.TLSFingerprint); err != nil || len(hash) != sha256.Size {
			return Config{}, fmt.Errorf("invalid tls_fingerprint %q: expected the SHA-256 fingerprint of the certificate, 64 hex digits", parts[6])
		}
	}
	return cfg, nil
}

// UniFiPlugin reads the clients a UniFi Network knows are connected now.
type UniFiPlugin struct {
	plugins.Poller

	name     string
	config   Config
	lifetime time.Duration
	client   *http.Client

	// The session of a user, kept between polls: its cookies and CSRF token, and whether the
	// server is UniFi OS, whose Network API is under /proxy/network.
	mutex    sync.Mutex
	loggedIn bool
	unifiOS  bool
	csrf     string
}

func NewUniFiPlugin(name string, config Config, lifetime time.Duration) *UniFiPlugin {
	jar, _ := cookiejar.New(nil)
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
	return &UniFiPlugin{
		name:     name,
		config:   config,
		lifetime: lifetime,
		client:   &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment}},
		// An API key is of UniFi OS alone.
		unifiOS: config.APIKey != "",
	}
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
	ctx, cancel := context.WithTimeout(ctx, plugins.PollTimeout)
	defer cancel()
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var clients []unifiClient
	if err := p.call(ctx, "/v2/api/site/"+url.PathEscape(p.config.Site)+"/clients/active?includeUnifiDevices=true", &clients); err != nil {
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

// call reads path of the site's Network API into out: with the API key, or the session, logging
// in first, and again once when the session is refused.
func (p *UniFiPlugin) call(ctx context.Context, path string, out any) error {
	if p.config.APIKey == "" && !p.loggedIn {
		if err := p.login(ctx); err != nil {
			return err
		}
	}
	status, answer, err := p.do(ctx, http.MethodGet, p.prefix()+path, nil)
	if err == nil && status == http.StatusUnauthorized && p.config.APIKey == "" {
		p.loggedIn = false
		if err := p.login(ctx); err != nil {
			return err
		}
		status, answer, err = p.do(ctx, http.MethodGet, p.prefix()+path, nil)
	}
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return p.refused(status, answer)
	}
	if err := json.Unmarshal(answer, out); err != nil {
		return fmt.Errorf("HTTP %d: not an answer of the UniFi Network API: %w", status, err)
	}
	return nil
}

// prefix is where the Network API is: under /proxy/network on UniFi OS.
func (p *UniFiPlugin) prefix() string {
	if p.unifiOS {
		return "/proxy/network"
	}
	return ""
}

// do sends a request to path of the server, with the API key or the session, and returns the
// status and the answer. It keeps the CSRF token UniFi OS gives at its login, and renews.
func (p *UniFiPlugin) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	base, err := url.Parse(p.config.Address)
	if err != nil {
		return 0, nil, err
	}
	target, err := url.Parse(path)
	if err != nil {
		return 0, nil, err
	}
	base.Path, _ = url.JoinPath(base.Path, target.Path)
	base.RawQuery = target.RawQuery
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, base.String(), reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.config.APIKey != "" {
		req.Header.Set("X-API-KEY", p.config.APIKey)
	} else if p.csrf != "" {
		req.Header.Set("X-Csrf-Token", p.csrf)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return 0, nil, err
	}
	defer resp.Body.Close()
	for _, header := range []string{"X-Csrf-Token", "X-Updated-Csrf-Token"} {
		if token := resp.Header.Get(header); token != "" {
			p.csrf = token
		}
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("HTTP %s: reading the answer: %w", resp.Status, err)
	}
	return resp.StatusCode, answer, nil
}

// login logs the user in: at UniFi OS's login, or at a self-hosted Network Application's, which
// answers UniFi OS's with an error of its own form, with meta.
func (p *UniFiPlugin) login(ctx context.Context) error {
	p.csrf = ""
	credentials := map[string]any{"username": p.config.Username, "password": p.config.Password}
	p.unifiOS = true
	status, answer, err := p.do(ctx, http.MethodPost, "/api/auth/login", credentials)
	if err == nil && status != http.StatusOK && selfHostedAnswer(answer) {
		p.unifiOS = false
		status, answer, err = p.do(ctx, http.MethodPost, "/api/login", credentials)
	}
	switch {
	case err != nil:
		return fmt.Errorf("logging in: %w", err)
	case status == http.StatusOK:
		p.loggedIn = true
		return nil
	case status == http.StatusBadRequest || status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("logging in: HTTP %d: the username or the password is refused. A user with two-factor authentication can't log in here: use an API key, or a local user without it", status)
	}
	return fmt.Errorf("logging in: %w", p.refused(status, answer))
}

// selfHostedAnswer tells an answer of a self-hosted Network Application's API, which has meta.
func selfHostedAnswer(answer []byte) bool {
	var said struct {
		Meta *struct{} `json:"meta"`
	}
	return json.Unmarshal(answer, &said) == nil && said.Meta != nil
}

// refused is the error of an answer that isn't 200: with what UniFi says, in whichever of its
// forms, and what to do about a refused key.
func (p *UniFiPlugin) refused(status int, answer []byte) error {
	var said struct {
		Message string `json:"message"`
		Error   struct {
			Message string `json:"message"`
		} `json:"error"`
		Meta struct {
			Msg string `json:"msg"`
		} `json:"meta"`
	}
	message := ""
	if json.Unmarshal(answer, &said) == nil {
		message = said.Message
		if message == "" {
			message = said.Error.Message
		}
		if message == "" {
			message = said.Meta.Msg
		}
	}
	text := fmt.Sprintf("HTTP %d", status)
	switch {
	case status == http.StatusUnauthorized && p.config.APIKey != "":
		return fmt.Errorf("%s: the API key is refused: create one in UniFi OS, Settings, Control Plane, Integrations", text)
	case status == http.StatusNotFound && p.config.APIKey != "":
		return fmt.Errorf("%s: no site %q here: the site, or the address, is wrong. An API key is of UniFi OS alone: a self-hosted Network Application needs username and password", text, p.config.Site)
	case status == http.StatusNotFound:
		return fmt.Errorf("%s: no site %q here: the site, or the address, is wrong", text, p.config.Site)
	case status == http.StatusTooManyRequests:
		return fmt.Errorf("%s: too many requests, or logins: UniFi asks to wait", text)
	case message == "":
		return fmt.Errorf("%s: not an answer of the UniFi Network API", text)
	}
	if len(message) > 200 {
		message = message[:200]
	}
	return fmt.Errorf("%s: %s", text, message)
}
