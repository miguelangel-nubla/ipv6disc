package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/internal/sshtest"
	"github.com/stretchr/testify/assert"
)

func TestParseNDPOutput(t *testing.T) {
	output := `fe80::20c:29ff:fe2c:2b08 dev eth0 lladdr 00:1a:2b:3c:4d:08 STALE
2001:db8::1 dev eth0 lladdr 00:1a:2b:3c:4d:09 REACHABLE
2001:db8::2 dev eth0  FAILED
2001:db8::3 dev eth0 lladdr 00:1a:2b:3c:4d:0a DELAY
`
	state := ipv6disc.NewState()

	plugin := &LinuxPlugin{
		config:   Config{Address: "test"},
		lifetime: time.Hour,
	}

	count := plugin.parseNDPOutput(output, state)

	assert.Equal(t, 2, count)

	// Verify the valid entries were registered

	// 1. fe80::20c:29ff:fe2c:2b08
	ip1, _ := netip.ParseAddr("fe80::20c:29ff:fe2c:2b08")
	mac1, _ := net.ParseMAC("00:1a:2b:3c:4d:08")
	_, existing1 := state.Register(mac1, ip1, plugin.Name(), time.Hour, nil)
	assert.False(t, existing1, "fe80::... is stale: it must not be registered")

	// 2. 2001:db8::1
	ip2, _ := netip.ParseAddr("2001:db8::1")
	mac2, _ := net.ParseMAC("00:1a:2b:3c:4d:09")
	_, existing2 := state.Register(mac2, ip2, plugin.Name(), time.Hour, nil)
	assert.True(t, existing2, "2001:db8::1 should be registered")

	// 3. 2001:db8::3
	ip3, _ := netip.ParseAddr("2001:db8::3")
	mac3, _ := net.ParseMAC("00:1a:2b:3c:4d:0a")
	_, existing3 := state.Register(mac3, ip3, plugin.Name(), time.Hour, nil)
	assert.True(t, existing3, "2001:db8::3 should be registered")
}

func TestParseConfig(t *testing.T) {
	// 1. Basic config
	cfg, err := ParseConfig("60s,192.168.1.1,user,pass")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1", cfg.Address)
	assert.Equal(t, "user", cfg.Username)
	assert.Equal(t, "pass", cfg.Password)
	assert.Empty(t, cfg.IdentityFile)

	// 2. Config with identity file
	cfg, err = ParseConfig("60s,192.168.1.1,user,pass,/path/to/key")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1", cfg.Address)
	assert.Equal(t, "user", cfg.Username)
	assert.Equal(t, "pass", cfg.Password)
	assert.Equal(t, "/path/to/key", cfg.IdentityFile)

	// 3. Invalid config
	_, err = ParseConfig("192.168.1.1,user")
	assert.Error(t, err)
}

func TestPluginName(t *testing.T) {
	plugin := NewLinuxPlugin("my-router", Config{Address: "192.168.1.1"}, time.Hour)
	assert.Equal(t, "my-router", plugin.Name())
}

func TestDiscoverOverSSH(t *testing.T) {
	server := sshtest.Start(t, "root", "secret", func(command string) ([]byte, error) {
		if command != "ip -6 neigh" {
			return nil, errors.New("unexpected command")
		}
		return []byte("2001:db8::1 dev eth0 lladdr 00:1a:2b:3c:4d:09 REACHABLE\n2001:db8::2 dev eth0  FAILED\n"), nil
	})
	var warnings []error
	onError := func(err error) { warnings = append(warnings, err) }

	plugin := NewLinuxPlugin("router", Config{Interval: time.Minute, Address: server.Address, Username: "root", Password: "secret"}, time.Hour)
	state := ipv6disc.NewState()
	for range 2 {
		if _, err := plugin.discover(context.Background(), state, onError); err != nil {
			t.Fatal(err)
		}
	}
	if len(state.GetAll()) != 1 {
		t.Errorf("got %v, want the one reachable neighbor", state.GetAll())
	}
	// An unpinned key: one warning, telling its fingerprint.
	if len(warnings) != 1 || !strings.Contains(warnings[0].Error(), server.HostKey) {
		t.Errorf("got warnings %v, want one with %s", warnings, server.HostKey)
	}

	warnings = nil
	pinned := NewLinuxPlugin("router", Config{Interval: time.Minute, Address: server.Address, Username: "root", Password: "secret", HostKey: server.HostKey}, time.Hour)
	if _, err := pinned.discover(context.Background(), ipv6disc.NewState(), onError); err != nil || len(warnings) != 0 {
		t.Errorf("pinned: %v, warnings %v", err, warnings)
	}
}

func TestDiscoverIPv4(t *testing.T) {
	const table = "192.168.1.10 dev eth0 lladdr 00:1a:2b:3c:4d:10 REACHABLE\n192.168.1.11 dev eth0 lladdr 00:1a:2b:3c:4d:11 STALE\n192.168.1.12 dev eth0  FAILED\n2001:db8::1 dev eth0 lladdr 00:1a:2b:3c:4d:09 REACHABLE\n"
	server := sshtest.Start(t, "root", "secret", func(command string) ([]byte, error) {
		switch command {
		case "ip neigh":
			return []byte(table), nil
		case "ip -6 neigh":
			return []byte("2001:db8::1 dev eth0 lladdr 00:1a:2b:3c:4d:09 REACHABLE\n"), nil
		}
		return nil, errors.New("unexpected command")
	})
	cfg := Config{Interval: time.Minute, Address: server.Address, Username: "root", Password: "secret", HostKey: server.HostKey}

	// Without IPv4, the IPv6 table only.
	state := ipv6disc.NewState()
	if found, err := NewLinuxPlugin("router", cfg, time.Hour).discover(context.Background(), state, nil); err != nil || found != 1 {
		t.Errorf("IPv6 only: found %d, %v", found, err)
	}

	state = ipv6disc.NewState()
	state.SetFamilies(true, true)
	found, err := NewLinuxPlugin("router", cfg, time.Hour).discover(context.Background(), state, nil)
	if err != nil || found != 2 {
		t.Errorf("with IPv4: found %d, %v, want the reachable IPv4 and the IPv6", found, err)
	}
	if got := state.GetAll()["00:1a:2b:3c:4d:10"]; got == nil || got.Strings()[0] != "192.168.1.10" {
		t.Errorf("the IPv4 neighbor: %v", got)
	}
	if got := server.Commands(); got[0] != "ip -6 neigh" || got[1] != "ip neigh" {
		t.Errorf("commands: %v", got)
	}
}

func TestDiscoverIPv4Only(t *testing.T) {
	server := sshtest.Start(t, "root", "secret", func(command string) ([]byte, error) {
		if command != "ip -4 neigh" {
			return nil, errors.New("unexpected command " + command)
		}
		return []byte("192.168.1.10 dev eth0 lladdr 00:1a:2b:3c:4d:10 REACHABLE\n"), nil
	})
	state := ipv6disc.NewState()
	state.SetFamilies(false, true)
	cfg := Config{Interval: time.Minute, Address: server.Address, Username: "root", Password: "secret", HostKey: server.HostKey}
	if found, err := NewLinuxPlugin("router", cfg, time.Hour).discover(context.Background(), state, nil); err != nil || found != 1 {
		t.Errorf("IPv4 only: found %d, %v", found, err)
	}

	// No family on: nothing to read, no connection.
	state.SetFamilies(false, false)
	if found, err := NewLinuxPlugin("router", cfg, time.Hour).discover(context.Background(), state, nil); err != nil || found != 0 {
		t.Errorf("no family: found %d, %v", found, err)
	}
	if got := server.Commands(); len(got) != 1 {
		t.Errorf("commands: %v", got)
	}
}
