package plugins

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHConfig is the configuration of the plugins that run a command over SSH.
type SSHConfig struct {
	Interval     time.Duration
	Address      string
	Username     string
	Password     string
	IdentityFile string
	// The fingerprint of the host's key, as ssh-keygen -l shows it: SHA256:... Empty accepts any
	// key, so anyone between can impersonate the host.
	HostKey string
}

const sshConfigFormat = "interval,address,username,password[,identity_file[,host_key]]"

// SSHFields are the params of the plugins over SSH, by name. A password or an identity file is
// needed, which ParseSSHConfig checks.
var SSHFields = []Field{
	{Name: "interval", Required: true}, {Name: "address", Required: true}, {Name: "username", Required: true},
	{Name: "password"}, {Name: "identity_file"}, {Name: "host_key"},
}

// ParseSSHConfig reads interval,address,username,password[,identity_file[,host_key]]. kind names
// the plugin in errors.
func ParseSSHConfig(kind string, config string) (SSHConfig, error) {
	parts := SplitParams(config)
	if len(parts) < 4 || len(parts) > 6 {
		return SSHConfig{}, fmt.Errorf("invalid %s config format, expected: %s", kind, sshConfigFormat)
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
// showed. A host key in cfg must be that one. The connection closes when ctx is done.
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

	var hostKey string
	clientConfig := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            authMethods,
		HostKeyCallback: HostKeyCallback(cfg.HostKey, &hostKey),
		Timeout:         10 * time.Second,
	}

	client, err := dialSSH(ctx, FormatAddress(cfg.Address, "22"), clientConfig)
	if err != nil {
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

func dialSSH(ctx context.Context, address string, config *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := (&net.Dialer{Timeout: config.Timeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	// The timeout of the handshake too, as ssh.Dial does.
	conn.SetDeadline(time.Now().Add(config.Timeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// HostKeyCallback accepts the host key with the fingerprint expected, or any key when expected is
// empty. It stores the fingerprint of the key shown in seen.
func HostKeyCallback(expected string, seen *string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		*seen = ssh.FingerprintSHA256(key)
		if expected != "" && *seen != expected {
			return fmt.Errorf("host key mismatch: the host shows %s, expected %s", *seen, expected)
		}
		return nil
	}
}

// HostKeyWarning is the warning for a host key that was not checked, telling what to pin it with.
func HostKeyWarning(address, hostKey string) error {
	return fmt.Errorf("the host key of %s is not verified, so anyone between can impersonate it: add its fingerprint, %s, as the last plugin param (%s)", address, hostKey, sshConfigFormat)
}
