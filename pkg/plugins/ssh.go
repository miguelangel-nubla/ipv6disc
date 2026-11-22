package plugins

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHConfig is the configuration of the plugins that run a command over SSH.
type SSHConfig struct {
	// How often the table is read. It must be positive: Start returns an error otherwise.
	Interval     time.Duration
	Address      string
	Username     string
	Password     string
	IdentityFile string
	// The fingerprint of a key of the host, any of them, as ssh-keygen -l shows it: SHA256:...
	// Empty accepts any key, so anyone between can impersonate the host.
	HostKey string
}

const sshConfigFormat = "interval,address,username,password[,identity_file[,host_key]]"

// SSHFields are the params of the plugins over SSH, by name. A password or an identity file is
// needed, which ParseSSHConfig checks.
var SSHFields = []Field{
	{Name: "interval", Required: true, Type: FieldDuration, Description: "How often the table is read: 60s, 5m."},
	{Name: "address", Required: true, Description: "The host, with its port unless 22: 192.168.1.1, [2001:db8::1]:2222."},
	{Name: "username", Required: true, Description: "The SSH user."},
	{Name: "password", Description: "Its password. Or an identity_file, or both."},
	{Name: "identity_file", Description: "The SSH private key file."},
	{Name: "host_key", Description: "The fingerprint of the host's SSH key, any of them when it has several, SHA256:..., as ssh-keygen -l shows it. Recommended: without it, any key is accepted, and the log warns with the fingerprint seen."},
}

// ParseSSHConfig reads interval,address,username,password[,identity_file[,host_key]]. kind names
// the plugin in errors. The spaces around a value are dropped, as after a comma, but those of the
// password, which are its own.
func ParseSSHConfig(kind string, config string) (SSHConfig, error) {
	parts := SplitParams(config)
	if len(parts) < 4 || len(parts) > 6 {
		return SSHConfig{}, fmt.Errorf("invalid %s config format, expected: %s", kind, sshConfigFormat)
	}

	for i := range parts {
		if i != 3 {
			parts[i] = strings.TrimSpace(parts[i])
		}
	}

	interval, err := time.ParseDuration(parts[0])
	if err != nil {
		return SSHConfig{}, fmt.Errorf("invalid interval format: %w", err)
	}
	if interval <= 0 {
		return SSHConfig{}, fmt.Errorf("invalid interval %s: it must be positive", interval)
	}

	cfg := SSHConfig{
		Interval: interval,
		Address:  parts[1],
		Username: parts[2],
		Password: parts[3],
	}
	if cfg.Address == "" || cfg.Username == "" {
		return SSHConfig{}, fmt.Errorf("a %s plugin needs its address and username", kind)
	}

	if len(parts) > 4 {
		cfg.IdentityFile = parts[4]
	}
	if len(parts) > 5 {
		cfg.HostKey = parts[5]
		if !strings.HasPrefix(cfg.HostKey, "SHA256:") {
			return SSHConfig{}, fmt.Errorf("invalid host key %q: expected its SHA256:... fingerprint, as ssh-keygen -l shows it", cfg.HostKey)
		}
	}

	if cfg.Password == "" && cfg.IdentityFile == "" {
		return SSHConfig{}, fmt.Errorf("a %s plugin needs a password or an identity file", kind)
	}
	return cfg, nil
}

// RunSSH runs command on the host and returns its output, and the fingerprint of the key the host
// showed. A host key in cfg must be one of the host's: see dialSSHHost. The connection closes when
// ctx is done.
//
// The output is the command's stdout and stderr together, and the error that of its exit status:
// of the last command, when they are several. So the parsers of the plugins skip the lines that
// are not of a table, as a warning.
func RunSSH(ctx context.Context, cfg SSHConfig, command string) ([]byte, string, error) {
	var authMethods []ssh.AuthMethod

	if cfg.IdentityFile != "" {
		key, err := os.ReadFile(cfg.IdentityFile)
		if err != nil {
			return nil, "", fmt.Errorf("unable to read private key: %w", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, "", fmt.Errorf("unable to parse private key: %w", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Password))
	}

	client, hostKey, err := dialSSHHost(ctx, cfg, authMethods)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return nil, hostKey, fmt.Errorf("failed to dial: %w", err)
	}
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()

	session, err := client.NewSession()
	if err != nil {
		return nil, hostKey, fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return nil, hostKey, fmt.Errorf("failed to run %s: %w", command, err)
	}
	return output, hostKey, nil
}

type hostKeyFamily struct {
	keyTypes   []string
	algorithms []string
}

// hostKeyFamilies are the kinds of host key, with the algorithms that make a host show its key of
// that kind.
var hostKeyFamilies = []hostKeyFamily{
	{[]string{ssh.KeyAlgoED25519}, []string{ssh.KeyAlgoED25519}},
	{[]string{ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521}, []string{ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521}},
	{[]string{ssh.KeyAlgoRSA}, []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}},
}

// pinnedAlgorithms remembers, by address and host key, the algorithms that made the host show the
// key pinned, so that the next polls connect once.
var pinnedAlgorithms sync.Map

// dialSSHHost connects to the host of cfg, and returns the fingerprint of the key it showed.
//
// A host with several keys shows one only, the one of the algorithm the client prefers, and a
// fingerprint doesn't tell of which kind its key is. So, as OpenSSH with its known_hosts, a host
// key in cfg can be any of the host's: when the host shows another key, it is asked for its key of
// each other kind. Nothing but the handshake reaches a host that showed another key: neither the
// password nor the command.
func dialSSHHost(ctx context.Context, cfg SSHConfig, auth []ssh.AuthMethod) (*ssh.Client, string, error) {
	address := FormatAddress(cfg.Address, "22")
	var seen []string
	var keyTypes []string
	dial := func(algorithms []string) (*ssh.Client, error) {
		var fingerprint string
		check := HostKeyCallback(cfg.HostKey, &fingerprint)
		client, err := dialSSH(ctx, address, &ssh.ClientConfig{
			User: cfg.Username,
			Auth: auth,
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				keyTypes = append(keyTypes, key.Type())
				return check(hostname, remote, key)
			},
			HostKeyAlgorithms: algorithms,
			Timeout:           10 * time.Second,
		})
		if fingerprint != "" && !slices.Contains(seen, fingerprint) {
			seen = append(seen, fingerprint)
		}
		return client, err
	}
	// The fingerprint of the first key shown: the one the host shows by default.
	shown := func() string {
		if len(seen) == 0 {
			return ""
		}
		return seen[0]
	}

	if cfg.HostKey == "" {
		// Any key: the one the host shows by default, always the same.
		client, err := dial(nil)
		return client, shown(), err
	}

	cacheKey := address + " " + cfg.HostKey
	// The default first: a key pinned from the warning, the one shown by default, takes one connection.
	attempts := []hostKeyFamily{{}}
	if remembered, ok := pinnedAlgorithms.Load(cacheKey); ok {
		attempts = []hostKeyFamily{{algorithms: remembered.([]string)}, {}}
	}
	attempts = append(attempts, hostKeyFamilies...)

	var lastErr error
	for _, attempt := range attempts {
		if slices.ContainsFunc(attempt.keyTypes, func(keyType string) bool { return slices.Contains(keyTypes, keyType) }) {
			continue // its key of this kind was already shown
		}
		client, err := dial(attempt.algorithms)
		if err == nil {
			if attempt.algorithms != nil {
				pinnedAlgorithms.Store(cacheKey, attempt.algorithms)
			} else {
				pinnedAlgorithms.Delete(cacheKey)
			}
			return client, cfg.HostKey, nil
		}
		var noAlgorithm *ssh.AlgorithmNegotiationError
		switch {
		case errors.Is(err, ErrHostKeyMismatch):
			lastErr = err
		case attempt.algorithms != nil && errors.As(err, &noAlgorithm):
			// It has no key of this kind.
			if lastErr == nil {
				lastErr = err
			}
		default:
			// Past the host key, as a password refused: not to be tried again with another key,
			// and the key it showed this time was the one expected.
			if slices.Contains(seen, cfg.HostKey) {
				return nil, cfg.HostKey, err
			}
			return nil, shown(), err
		}
	}
	if len(seen) > 1 {
		lastErr = fmt.Errorf("%w: the host shows %s, expected %s", ErrHostKeyMismatch, strings.Join(seen, ", "), cfg.HostKey)
	}
	return nil, shown(), lastErr
}

func dialSSH(ctx context.Context, address string, config *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := (&net.Dialer{Timeout: config.Timeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	// The timeout of the handshake too, as ssh.Dial does.
	if err := conn.SetDeadline(time.Now().Add(config.Timeout)); err != nil {
		conn.Close()
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Left on, the deadline would cut the command short.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		c.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// ErrHostKeyMismatch is the error of a host that shows another key than the one expected.
var ErrHostKeyMismatch = errors.New("host key mismatch")

// HostKeyCallback accepts the host key with the fingerprint expected, or any key when expected is
// empty. It stores the fingerprint of the key shown in seen. Its error is an ErrHostKeyMismatch.
func HostKeyCallback(expected string, seen *string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		*seen = ssh.FingerprintSHA256(key)
		if expected != "" && *seen != expected {
			return fmt.Errorf("%w: the host shows %s, expected %s", ErrHostKeyMismatch, *seen, expected)
		}
		return nil
	}
}

// HostKeyWarning is the warning for a host key that was not checked, telling what to pin it with.
func HostKeyWarning(address, hostKey string) error {
	return fmt.Errorf("the host key of %s is not verified, so anyone between can impersonate it: add its fingerprint, %s, as the last plugin param (%s)", address, hostKey, sshConfigFormat)
}
