package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/internal/sshtest"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

func TestParseNDPOutput(t *testing.T) {
	output := `fe80::20c:29ff:fe2c:2b08 dev eth0 lladdr 00:1a:2b:3c:4d:08 STALE
2001:db8::1 dev eth0 lladdr 00:1a:2b:3c:4d:09 REACHABLE
2001:db8::2 dev eth0  FAILED
2001:db8::3 dev eth0 lladdr 00:1a:2b:3c:4d:0a DELAY
2001:db8::4 dev vxlan0 lladdr 00:1a:2b:3c:4d:0b extern_learn STALE proto zebra
2001:db8::5 dev eth0 lladdr 00:1a:2b:3c:4d:0c router FAILED proto static
ip: a warning of the command, lladdr or not, is not a neighbor
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

	// The state is not the last field of an entry with a protocol.
	assert.NotContains(t, state.GetAll(), "00:1a:2b:3c:4d:0b", "stale, with a protocol after")
	assert.NotContains(t, state.GetAll(), "00:1a:2b:3c:4d:0c", "failed, with a protocol after")
	assert.Equal(t, 1, plugin.parseNDPOutput("2001:db8::6 dev vxlan0 lladdr 00:1a:2b:3c:4d:0d extern_learn REACHABLE proto zebra\n", state))
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
		if strings.TrimSuffix(command, leasesCommand) != "ip -6 neigh" {
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
		switch strings.TrimSuffix(command, leasesCommand) {
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
	if got := server.Commands(); got[0] != "ip -6 neigh"+leasesCommand || got[1] != "ip neigh"+leasesCommand {
		t.Errorf("commands: %v", got)
	}
}

func TestDiscoverIPv4Only(t *testing.T) {
	server := sshtest.Start(t, "root", "secret", func(command string) ([]byte, error) {
		if strings.TrimSuffix(command, leasesCommand) != "ip -4 neigh" {
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

// The params by name, as a program with them as fields gives them, reach the parser whole: a
// password with a comma and a backslash, and a host key without an identity file before it.
func TestParamsByName(t *testing.T) {
	values := map[string]string{"interval": "60s", "address": "192.0.2.1", "username": "root", "password": `p,a\\,s=s `, "host_key": "SHA256:abc"}
	params, err := plugins.FieldParams("linux", values)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(params)
	if err != nil || cfg.Password != values["password"] || cfg.IdentityFile != "" || cfg.HostKey != "SHA256:abc" || cfg.Address != "192.0.2.1" {
		t.Errorf("%q: got %+v, %v", params, cfg, err)
	}

	// The optional ones left out: the four first only.
	delete(values, "host_key")
	if params, err := plugins.FieldParams("linux", values); err != nil || len(plugins.SplitParams(params)) != 4 {
		t.Errorf("got %q, %v", params, err)
	}

	if _, err := plugins.Create("linux", "router", `interval=60s, address=192.0.2.1, username=root, password=p\,a, host_key=SHA256:abc`, time.Hour); err != nil {
		t.Error(err)
	}
	// Neither a password nor an identity file: the parser's own check.
	if _, err := plugins.Create("linux", "router", "interval=60s,address=192.0.2.1,username=root", time.Hour); err == nil {
		t.Error("no password and no identity file: want an error")
	}
}

// A host that refuses the login: no warning of its key, which is told once a poll succeeds.
func TestDiscoverWrongPassword(t *testing.T) {
	server := sshtest.Start(t, "root", "secret", func(string) ([]byte, error) { return nil, nil })
	var warnings []error
	plugin := NewLinuxPlugin("router", Config{Interval: time.Minute, Address: server.Address, Username: "root", Password: "wrong"}, time.Hour)
	if _, err := plugin.discover(context.Background(), ipv6disc.NewState(), func(err error) { warnings = append(warnings, err) }); err == nil || len(warnings) != 0 {
		t.Errorf("got %v, warnings %v, want the error only", err, warnings)
	}
}

func TestStartNeedsAnInterval(t *testing.T) {
	plugin := NewLinuxPlugin("router", Config{Address: "192.0.2.1", Username: "root", Password: "secret"}, time.Hour)
	if err := plugin.Start(context.Background(), ipv6disc.NewState(), nil); err == nil {
		t.Error("no interval: want an error")
	}
}

// With names, the leases of dnsmasq and the hosts of odhcpd are read in the same session, and
// their names registered: a DHCPv4 lease's at its MAC, a DHCPv6 one's at the MAC the table has its
// address at, when it is in use. Without, the command is the table's alone.
func TestDiscoverNames(t *testing.T) {
	const table = "192.168.1.50 dev br-lan lladdr 00:1a:2b:3c:4d:50 REACHABLE\nfd00::1c3 dev br-lan lladdr 00:1a:2b:3c:4d:60 REACHABLE\nfd00::1c4 dev br-lan lladdr 00:1a:2b:3c:4d:61 STALE\n"
	const leases = "1700003600 00:1a:2b:3c:4d:50 192.168.1.50 Laptop 01:00:1a:2b:3c:4d:50\n1700003600 00:1a:2b:3c:4d:51 192.168.1.51 * *\n1700003600 00:1a:2b:3c:4d:52 192.168.1.52 ESP_1A2B3C *\n"
	const hosts = "# br-lan 0001 1052436 phone 1700003600 1c3 128 fd00::1c3/128\nfd00::1c3\tphone.lan\tphone\nfd00::1c4\tleft.lan\n"
	server := sshtest.Start(t, "root", "secret", func(command string) ([]byte, error) {
		switch command {
		case "ip neigh" + leasesCommand:
			return []byte(table + leasesMarker + "\n" + leases + hostsMarker + "\n" + hosts), nil
		case "ip -6 neigh" + leasesCommand:
			// A host with neither file: the markers alone.
			return []byte("fd00::1c3 dev br-lan lladdr 00:1a:2b:3c:4d:60 REACHABLE\n" + leasesMarker + "\n" + hostsMarker + "\n"), nil
		case "ip neigh":
			return []byte(table), nil
		}
		return nil, errors.New("unexpected command " + command)
	})
	cfg := Config{Interval: time.Minute, Address: server.Address, Username: "root", Password: "secret", HostKey: server.HostKey}
	names := func(state *ipv6disc.State) []string {
		var got []string
		for mac, names := range state.AllNames() {
			for _, n := range names {
				got = append(got, mac+" "+n.Name+" "+strings.Join(n.Sources, ","))
			}
		}
		slices.Sort(got)
		return got
	}

	state := ipv6disc.NewState()
	defer state.Close()
	state.SetFamilies(true, true)
	state.SetNames(true, 0)
	found, err := NewLinuxPlugin("router", cfg, time.Hour).discover(context.Background(), state, nil)
	if err != nil || found != 2 {
		t.Errorf("found %d, %v, want the two neighbors in use", found, err)
	}
	want := []string{
		"00:1a:2b:3c:4d:50 laptop router",
		// A lease of a host the table doesn't have: its name waits for its address.
		"00:1a:2b:3c:4d:52 esp-1a2b3c router",
		"00:1a:2b:3c:4d:60 phone router",
	}
	if got := names(state); !slices.Equal(got, want) {
		t.Errorf("names %q\nwant %q", got, want)
	}
	if got := state.GetAll(); len(got) != 2 {
		t.Errorf("the leases registered addresses: %v", got)
	}

	// No lease file there: the neighbors all the same.
	ipv6Only := ipv6disc.NewState()
	defer ipv6Only.Close()
	ipv6Only.SetNames(true, 0)
	if found, err := NewLinuxPlugin("router", cfg, time.Hour).discover(context.Background(), ipv6Only, nil); err != nil || found != 1 || len(ipv6Only.AllNames()) != 0 {
		t.Errorf("without lease files: found %d, %v, names %v", found, err, ipv6Only.AllNames())
	}

	// Without names, the leases are read all the same: their addresses.
	without := ipv6disc.NewState()
	defer without.Close()
	without.SetFamilies(true, true)
	if found, err := NewLinuxPlugin("router", cfg, time.Hour).discover(context.Background(), without, nil); err != nil || found != 2 || len(without.AllNames()) != 0 {
		t.Errorf("without names: found %d, %v, names %v", found, err, without.AllNames())
	}
	if got := server.Commands(); len(got) != 3 || got[2] != "ip neigh"+leasesCommand {
		t.Errorf("commands: %q", got)
	}
}

// The command that reads the leases says nothing of a file that isn't there, and succeeds
// whatever the last file: its exit status would otherwise fail the poll.
func TestLeasesCommand(t *testing.T) {
	if !strings.HasSuffix(leasesCommand, "; true") || strings.Count(leasesCommand, "2>/dev/null") != 2 || !strings.Contains(leasesCommand, "/tmp/dhcp.leases") || !strings.Contains(leasesCommand, "/tmp/hosts/odhcpd") {
		t.Errorf("the command: %s", leasesCommand)
	}
}
