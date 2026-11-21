package freebsd

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
	"github.com/stretchr/testify/assert"
)

func TestParseNDPOutput(t *testing.T) {
	output := `Neighbor                             Linklayer Address  Netif Expire    S Flags
2001:db8::1                          00:11:22:33:44:55   em0 permanent R 
fe80::211:22ff:fe33:4455%em0         00:11:22:33:44:55   em0 permanent R 
2001:db8::2                          (incomplete)        em0 expired   N 
2001:db8::4                          00:11:22:33:44:66   em0 expired   S 
invalid-ip                           00:11:22:33:44:55   em0 permanent R 
2001:db8::3                          invalid-mac         em0 permanent R 
`
	state := ipv6disc.NewState()
	// Optionally set a nop logger if needed, but nil is fine for tests as per State implementation checks

	plugin := &FreeBSDPlugin{
		config:   Config{Address: "test"},
		lifetime: time.Hour,
	}

	count := plugin.parseNDPOutput(output, state)

	assert.Equal(t, 2, count)

	// Verify the valid entries were registered by trying to register them again

	// 1. 2001:db8::1
	ip1, _ := netip.ParseAddr("2001:db8::1")
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")

	// Check if it exists by registering again.
	// If it was registered by parseNDPOutput, existing should be true.
	_, existing1 := state.Register(mac1, ip1, plugin.Name(), time.Hour, nil)
	assert.True(t, existing1, "2001:db8::1 should be registered")

	// 2. fe80::211:22ff:fe33:4455%em0
	// netip.ParseAddr handles zone.
	ip2, _ := netip.ParseAddr("fe80::211:22ff:fe33:4455%em0")
	_, existing2 := state.Register(mac1, ip2, plugin.Name(), time.Hour, nil)
	assert.True(t, existing2, "fe80::...%em0 should be registered")
}

func TestDiscoverOverSSH(t *testing.T) {
	server := sshtest.Start(t, "root", "secret", func(command string) ([]byte, error) {
		if strings.TrimSuffix(command, leasesCommand) != "ndp -an" {
			return nil, errors.New("unexpected command")
		}
		return []byte("Neighbor Linklayer Address Netif Expire S Flags\n2001:db8::1 00:11:22:33:44:55 em0 permanent R\n"), nil
	})
	plugin := NewFreeBSDPlugin("firewall", Config{Interval: time.Minute, Address: server.Address, Username: "root", Password: "secret", HostKey: server.HostKey}, time.Hour)
	found, err := plugin.discover(context.Background(), ipv6disc.NewState(), func(err error) { t.Errorf("warning: %v", err) })
	if err != nil || found != 1 {
		t.Errorf("found %d, %v", found, err)
	}
}

func TestDiscoverIPv4OverSSH(t *testing.T) {
	server := sshtest.Start(t, "root", "secret", func(command string) ([]byte, error) {
		if strings.TrimSuffix(command, leasesCommand) != "ndp -an; echo "+arpMarker+"; arp -an" {
			return nil, errors.New("unexpected command")
		}
		return []byte("Neighbor Linklayer Address Netif Expire S Flags\n2001:db8::1 00:11:22:33:44:55 em0 permanent R\n" + arpMarker + "\n? (192.168.1.10) at 00:11:22:33:44:10 on em0 expires in 1189 seconds [ethernet]\n? (192.168.1.12) at (incomplete) on em0 expired [ethernet]\n"), nil
	})
	state := ipv6disc.NewState()
	state.SetFamilies(true, true)
	plugin := NewFreeBSDPlugin("firewall", Config{Interval: time.Minute, Address: server.Address, Username: "root", Password: "secret", HostKey: server.HostKey}, time.Hour)
	found, err := plugin.discover(context.Background(), state, nil)
	if err != nil || found != 2 {
		t.Errorf("found %d, %v, want the IPv6 and the IPv4 neighbor", found, err)
	}
	if got := state.GetAll()["00:11:22:33:44:10"]; got == nil || got.Strings()[0] != "192.168.1.10" {
		t.Errorf("the IPv4 neighbor: %v", got)
	}
}

func TestDiscoverIPv4Only(t *testing.T) {
	server := sshtest.Start(t, "root", "secret", func(command string) ([]byte, error) {
		if strings.TrimSuffix(command, leasesCommand) != "echo "+arpMarker+"; arp -an" {
			return nil, errors.New("unexpected command " + command)
		}
		// With a line of stderr, which comes with the output: not a neighbor.
		return []byte(arpMarker + "\narp: a warning\n? (192.168.1.10) at 00:11:22:33:44:10 on em0 expires in 1189 seconds [ethernet]\n"), nil
	})
	state := ipv6disc.NewState()
	state.SetFamilies(false, true)
	plugin := NewFreeBSDPlugin("firewall", Config{Interval: time.Minute, Address: server.Address, Username: "root", Password: "secret", HostKey: server.HostKey}, time.Hour)
	if found, err := plugin.discover(context.Background(), state, nil); err != nil || found != 1 {
		t.Errorf("IPv4 only: found %d, %v", found, err)
	}

	// No family on: nothing to read, no connection.
	state.SetFamilies(false, false)
	if found, err := plugin.discover(context.Background(), state, nil); err != nil || found != 0 {
		t.Errorf("no family: found %d, %v", found, err)
	}
	if got := server.Commands(); len(got) != 1 {
		t.Errorf("commands: %v", got)
	}
}

// What is not a line of the table, as a warning on stderr or the error of an ndp that failed
// before arp ran, is skipped.
func TestDiscoverSkipsOtherLines(t *testing.T) {
	server := sshtest.Start(t, "root", "secret", func(string) ([]byte, error) {
		return []byte("ndp: ioctl(SIOCGNBRINFO_IN6): Operation not permitted\n" + arpMarker + "\n? (192.168.1.10) at 00:11:22:33:44:10 on em0 expires in 1189 seconds [ethernet]\n"), nil
	})
	state := ipv6disc.NewState()
	state.SetFamilies(true, true)
	plugin := NewFreeBSDPlugin("firewall", Config{Interval: time.Minute, Address: server.Address, Username: "root", Password: "secret", HostKey: server.HostKey}, time.Hour)
	if found, err := plugin.discover(context.Background(), state, nil); err != nil || found != 1 || len(state.GetAll()) != 1 {
		t.Errorf("found %d, %v, state %v", found, err, state.GetAll())
	}
}

func TestStartNeedsAnInterval(t *testing.T) {
	plugin := NewFreeBSDPlugin("firewall", Config{Address: "192.0.2.1", Username: "root", Password: "secret"}, time.Hour)
	if err := plugin.Start(context.Background(), ipv6disc.NewState(), nil); err == nil {
		t.Error("no interval: want an error")
	}
}

// With names, the leases of the DHCP servers the host may run are read in the same session: those
// of ISC dhcpd, of Kea and of dnsmasq, each registered at its MAC, or at the MAC the tables have
// its address at. Without, the command is the tables' alone.
func TestDiscoverNames(t *testing.T) {
	const tables = "Neighbor Linklayer Address Netif Expire S Flags\nfd00::1c3 00:11:22:33:44:60 em0 23s R\nfe80::1%em0 00:11:22:33:44:61 em0 permanent R\n" + arpMarker + "\n? (192.168.1.50) at 00:11:22:33:44:50 on em0 expires in 1189 seconds [ethernet]\n"
	const isc = "lease 192.168.1.50 {\n  binding state active;\n  hardware ethernet 00:11:22:33:44:50;\n  client-hostname \"Laptop\";\n}\n"
	const kea = "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state\nfd00::1c3,00:01,7200,1700003600,1,3600,0,1052436,128,0,0,phone.lan.,,0\n"
	const dnsmasq = "1700003600 00:11:22:33:44:52 192.168.1.52 ESP_1A2B3C *\n"
	server := sshtest.Start(t, "root", "secret", func(command string) ([]byte, error) {
		switch command {
		case "ndp -an; echo " + arpMarker + "; arp -an" + leasesCommand:
			return []byte(tables + leasesMarker + "\n" + isc + keaMarker + "\n" + kea + dnsmasqMarker + "\n" + dnsmasq), nil
		case "ndp -an" + leasesCommand:
			// A host that runs none of them: the markers alone.
			return []byte("Neighbor Linklayer Address Netif Expire S Flags\nfd00::1c3 00:11:22:33:44:60 em0 23s R\n" + leasesMarker + "\n" + keaMarker + "\n" + dnsmasqMarker + "\n"), nil
		case "ndp -an; echo " + arpMarker + "; arp -an":
			return []byte(tables), nil
		}
		return nil, errors.New("unexpected command " + command)
	})
	cfg := Config{Interval: time.Minute, Address: server.Address, Username: "root", Password: "secret", HostKey: server.HostKey}

	state := ipv6disc.NewState()
	defer state.Close()
	state.SetFamilies(true, true)
	state.SetNames(true, 0)
	found, err := NewFreeBSDPlugin("firewall", cfg, time.Hour).discover(context.Background(), state, nil)
	if err != nil || found != 3 {
		t.Errorf("found %d, %v, want the three neighbors", found, err)
	}
	var got []string
	for mac, names := range state.AllNames() {
		for _, n := range names {
			got = append(got, mac+" "+n.Name+" "+strings.Join(n.Sources, ","))
		}
	}
	slices.Sort(got)
	want := []string{
		"00:11:22:33:44:50 laptop firewall",
		"00:11:22:33:44:52 esp-1a2b3c firewall",
		// A DHCPv6 lease, which has no MAC: the neighbor table's, of its address.
		"00:11:22:33:44:60 phone firewall",
	}
	if !slices.Equal(got, want) {
		t.Errorf("names %q\nwant %q", got, want)
	}
	if got := state.GetAll(); len(got) != 3 {
		t.Errorf("the leases registered addresses: %v", got)
	}

	ipv6Only := ipv6disc.NewState()
	defer ipv6Only.Close()
	ipv6Only.SetNames(true, 0)
	if found, err := NewFreeBSDPlugin("firewall", cfg, time.Hour).discover(context.Background(), ipv6Only, nil); err != nil || found != 1 || len(ipv6Only.AllNames()) != 0 {
		t.Errorf("without lease files: found %d, %v, names %v", found, err, ipv6Only.AllNames())
	}

	without := ipv6disc.NewState()
	defer without.Close()
	without.SetFamilies(true, true)
	if found, err := NewFreeBSDPlugin("firewall", cfg, time.Hour).discover(context.Background(), without, nil); err != nil || found != 3 || len(without.AllNames()) != 0 {
		t.Errorf("without names: found %d, %v, names %v", found, err, without.AllNames())
	}
	if !strings.HasSuffix(leasesCommand, "; true") || strings.Count(leasesCommand, "2>/dev/null") != 3 {
		t.Errorf("the command: %s", leasesCommand)
	}
}
