package freebsd

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
		if command != "ndp -an" {
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
		if command != "ndp -an; echo "+arpMarker+"; arp -an" {
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
