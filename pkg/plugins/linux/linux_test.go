package linux

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
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

	assert.Equal(t, 3, count)

	// Verify the valid entries were registered

	// 1. fe80::20c:29ff:fe2c:2b08
	ip1, _ := netip.ParseAddr("fe80::20c:29ff:fe2c:2b08")
	mac1, _ := net.ParseMAC("00:1a:2b:3c:4d:08")
	_, existing1 := state.Register(mac1, ip1, plugin.Name(), time.Hour, nil)
	assert.True(t, existing1, "fe80::... should be registered")

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
