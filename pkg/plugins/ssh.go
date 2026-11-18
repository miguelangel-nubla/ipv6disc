package plugins

import (
	"fmt"
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
}

// ParseSSHConfig reads interval,address,username,password[,identity_file]. kind names the plugin
// in errors.
func ParseSSHConfig(kind string, config string) (SSHConfig, error) {
	parts := strings.Split(config, ",")
	if len(parts) < 4 {
		return SSHConfig{}, fmt.Errorf("invalid %s config format, expected: interval,address,username,password[,identity_file]", kind)
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

	if len(parts) > 4 {
		cfg.IdentityFile = parts[4]
	}

	return cfg, nil
}

// RunSSH runs command on the host and returns its output.
func RunSSH(cfg SSHConfig, command string) ([]byte, error) {
	var authMethods []ssh.AuthMethod

	if cfg.IdentityFile != "" {
		key, err := os.ReadFile(cfg.IdentityFile)
		if err != nil {
			return nil, fmt.Errorf("unable to read private key: %w", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key: %w", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Password))
	}

	clientConfig := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", FormatAddress(cfg.Address, "22"), clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return nil, fmt.Errorf("failed to run %s: %w", command, err)
	}
	return output, nil
}
