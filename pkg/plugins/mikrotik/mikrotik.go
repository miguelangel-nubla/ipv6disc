package mikrotik

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-routeros/routeros/v3"
	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

func init() {
	plugins.Describe("mikrotik", "A Mikrotik router, over its API: `/ipv6/neighbor` for IPv6, `/ip/arp` for IPv4, and with `hostnames` the names of `/ip/dhcp-server/lease`.")
	plugins.Register("mikrotik", func(name string, config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return nil, err
		}
		return NewMikrotikPlugin(name, cfg, lifetime), nil
	},
		plugins.Field{Name: "interval", Required: true, Type: plugins.FieldDuration, Description: "How often the tables are read: 60s, 5m."},
		plugins.Field{Name: "address", Required: true, Description: "The router, with its port unless the default: 8728, or 8729 with TLS."},
		plugins.Field{Name: "username", Required: true, Description: "An API user: the read and api policies are enough."},
		plugins.Field{Name: "password", Description: "Its password."},
		plugins.Field{Name: "use_tls", Type: plugins.FieldBoolean, Description: "true or false: the API over TLS, the api-ssl service. Without it, the password crosses the network in the clear."},
		plugins.Field{Name: "tls_fingerprint", Description: "The SHA-256 fingerprint of the router's certificate, 64 hex digits, colons allowed, when the system's CAs can't verify it, as the self-signed one RouterOS makes. It needs use_tls."},
	)
}

const configFormat = "interval,address,username,password[,use_tls[,tls_fingerprint]]"

// ParseConfig reads interval,address,username,password[,use_tls[,tls_fingerprint]]. The spaces
// around a value are dropped, as after a comma, but those of the password, which are its own.
func ParseConfig(config string) (Config, error) {
	parts := plugins.SplitParams(config)
	if len(parts) < 4 || len(parts) > 6 {
		return Config{}, fmt.Errorf("invalid mikrotik config format, expected: %s", configFormat)
	}
	for i := range parts {
		if i != 3 {
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

	cfg := Config{
		Interval: interval,
		Address:  parts[1],
		Username: parts[2],
		Password: parts[3],
	}
	// An empty address would be this machine.
	if cfg.Address == "" || cfg.Username == "" {
		return Config{}, fmt.Errorf("a mikrotik plugin needs its address and username")
	}

	// Anything but true must not pass for it, as yes would: without TLS the password is sent in
	// the clear.
	if len(parts) > 4 && parts[4] != "" {
		useTLS, err := strconv.ParseBool(strings.ToLower(parts[4]))
		if err != nil {
			return Config{}, fmt.Errorf("invalid use_tls %q: it is true or false", parts[4])
		}
		cfg.UseTLS = useTLS
	}

	if len(parts) > 5 && parts[5] != "" {
		cfg.TLSFingerprint = strings.ToLower(strings.ReplaceAll(parts[5], ":", ""))
		if hash, err := hex.DecodeString(cfg.TLSFingerprint); err != nil || len(hash) != sha256.Size {
			return Config{}, fmt.Errorf("invalid tls_fingerprint %q: expected the SHA-256 fingerprint of the certificate, 64 hex digits", parts[5])
		}
		if !cfg.UseTLS {
			return Config{}, fmt.Errorf("tls_fingerprint needs use_tls=true: without TLS there is no certificate to check")
		}
	}

	return cfg, nil
}

type Config struct {
	// How often the tables are read. It must be positive: Start returns an error otherwise.
	Interval time.Duration
	Address  string
	Username string
	Password string
	UseTLS   bool
	// The SHA-256 fingerprint of the router's certificate: 64 lowercase hex digits, as ParseConfig
	// leaves it. Only with UseTLS.
	TLSFingerprint string
}

// MikrotikPlugin reads the neighbor tables of a RouterOS router over its API, and the names of its
// DHCP leases.
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

	// The connection is ours, to close it when ctx is done: routeros takes a context, but once
	// connected it waits for a router that stays silent without looking at it.
	var conn net.Conn
	var err error
	if p.config.UseTLS {
		var tlsConfig *tls.Config
		if p.config.TLSFingerprint != "" {
			// The certificate is checked by its fingerprint only, in VerifyPeerCertificate. That is
			// not called for a resumed session, so this config must never get a ClientSessionCache.
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
		conn, err = (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, "tcp", plugins.FormatAddress(p.config.Address, "8729"))
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", plugins.FormatAddress(p.config.Address, "8728"))
	}
	if err != nil {
		return 0, fmt.Errorf("error connecting to mikrotik: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	// The error of a connection closed for ctx is that of ctx.
	cause := func(err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}

	client, err := routeros.NewClient(conn)
	if err != nil {
		return 0, fmt.Errorf("error connecting to mikrotik: %w", cause(err))
	}
	defer client.Close()
	if err := client.LoginContext(ctx, p.config.Username, p.config.Password); err != nil {
		return 0, fmt.Errorf("error connecting to mikrotik: %w", cause(err))
	}

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
			return found, fmt.Errorf("error fetching %s: %w", table, cause(err))
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

			// RouterOS lists the multicast groups the router joined, as noarp entries with a group
			// MAC, ff02::1 at 33:33:00:00:00:01: not hosts, and refreshed at every poll they would
			// never expire.
			if ip.IsMulticast() || hw[0]&1 != 0 {
				continue
			}

			// A link-local address comes with the router's interface as its zone, fe80::2%bridge:
			// the state keys and shows addresses without their zone, so it is never taken for an
			// interface of this machine.
			if _, existing := state.Register(hw, ip, p.Name(), p.lifetime, nil); !existing {
				found++
			}
		}
	}

	// The names the hosts gave the router's DHCP server, of the leases bound now: one that
	// waits, as a static lease of a host that isn't there, names nobody. A lease is of a MAC,
	// so its name is the host's whatever the families read. The bindings of the DHCPv6 server
	// have no name to read.
	if state.Names() {
		const table = "/ip/dhcp-server/lease/print"
		reply, err := client.RunContext(ctx, table)
		if err != nil {
			return found, fmt.Errorf("error fetching %s: %w", table, cause(err))
		}
		var leases []plugins.Lease
		for _, re := range reply.Re {
			if re.Map["status"] != "bound" || re.Map["host-name"] == "" {
				continue
			}
			// The MAC the lease is bound to now, where the router tells it apart.
			hw, err := net.ParseMAC(cmp.Or(re.Map["active-mac-address"], re.Map["mac-address"]))
			if err != nil {
				continue
			}
			leases = append(leases, plugins.Lease{MAC: hw, Name: re.Map["host-name"]})
		}
		plugins.RegisterLeases(state, leases, nil, p.Name(), p.lifetime)
	}

	return found, nil
}

// neighborInUse tells whether a neighbor entry shows its host is there now. RouterOS keeps an entry
// long after the host is gone, as stale or failed, and registering it would refresh the address at
// every poll, so it would never expire.
func neighborInUse(status string) bool {
	return status != "stale" && status != "failed"
}
