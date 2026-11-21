package plugins

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

// leaseStrings is the leases as "mac ip name", a lease without a MAC with a -.
func leaseStrings(leases []Lease) []string {
	var result []string
	for _, l := range leases {
		mac := "-"
		if len(l.MAC) > 0 {
			mac = l.MAC.String()
		}
		result = append(result, mac+" "+l.IP.String()+" "+l.Name)
	}
	return result
}

func TestParseDnsmasqLeases(t *testing.T) {
	got := leaseStrings(ParseDnsmasqLeases(`1700003600 00:1a:2b:3c:4d:5e 192.168.1.50 laptop 01:00:1a:2b:3c:4d:5e
1700003600 00:1a:2b:3c:4d:5f 192.168.1.51 * *
0 00:1a:2b:3c:4d:60 192.168.1.52 ESP_1A2B3C ff:11:22:33:44
duid 00:01:00:01:2c:5b:8f:6e:00:1a:2b:3c:4d:01
1700003600 1052436 fd00::1c3 phone 00:01:00:01:2b:11:22:33:00:1a:2b:3c:4d:60
1700003600 not-a-mac 192.168.1.53 broken *
1700003600 00:1a:2b:3c:4d:61 not-an-address broken *
cat: can't open '/var/lib/misc/dnsmasq.leases': No such file or directory
1700003600 00:1a:2b:3c:4d:62

`))
	want := []string{
		"00:1a:2b:3c:4d:5e 192.168.1.50 laptop",
		"00:1a:2b:3c:4d:5f 192.168.1.51 *",
		"00:1a:2b:3c:4d:60 192.168.1.52 ESP_1A2B3C",
		"- fd00::1c3 phone",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestParseHosts(t *testing.T) {
	got := leaseStrings(ParseHosts(`# br-lan 00010001... 1052436 phone 1700003600 1c3 128 fd00::1c3/128
fd00::1c3	phone.lan	phone
fd00::1c4 tablet # as it gave it
192.168.1.60   nas.lan
not-an-address name
fd00::1c5
`))
	want := []string{"- fd00::1c3 phone.lan", "- fd00::1c4 tablet", "- 192.168.1.60 nas.lan"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestParseISCLeases(t *testing.T) {
	got := leaseStrings(ParseISCLeases(`# The format of this file is documented in the dhcpd.leases(5) manual page.
authoring-byte-order little-endian;
server-duid "\000\001\000\001";

lease 192.168.1.50 {
  starts 4 2024/01/04 10:00:00;
  ends 4 2024/01/04 12:00:00;
  binding state active;
  next binding state free;
  hardware ethernet 00:1a:2b:3c:4d:5e;
  uid "\001\000\032+<M^";
  client-hostname "old-name";
}
lease 192.168.1.51 {
  binding state free;
  hardware ethernet 00:1a:2b:3c:4d:5f;
  client-hostname "left";
}
lease 192.168.1.52 {
  binding state active;
  hardware ethernet 00:1a:2b:3c:4d:60;
}
lease 192.168.1.53 {
  binding state active;
  hardware ethernet 00:1a:2b:3c:4d:61;
  client-hostname "Living Room";
}
lease 192.168.1.54 {
  binding state active;
  hardware ethernet 00:1a:2b:3c:4d:62;
  client-hostname "was-here";
}
lease 192.168.1.50 {
  binding state active;
  hardware ethernet 00:1a:2b:3c:4d:5e;
  client-hostname "laptop";
}
lease 192.168.1.54 {
  binding state expired;
  hardware ethernet 00:1a:2b:3c:4d:62;
  client-hostname "was-here";
}
lease not-an-address {
  binding state active;
  hardware ethernet 00:1a:2b:3c:4d:63;
  client-hostname "broken";
}
  client-hostname "outside";
lease 192.168.1.55 {
  binding state active;
  hardware ethernet 00:1a:2b:3c:4d:64;
  client-hostname "unfinished";
`))
	want := []string{
		"00:1a:2b:3c:4d:5e 192.168.1.50 laptop",
		"00:1a:2b:3c:4d:61 192.168.1.53 Living Room",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestParseKeaLeases(t *testing.T) {
	got := leaseStrings(ParseKeaLeases(`address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
192.168.1.50,00:1a:2b:3c:4d:5e,01:00:1a:2b:3c:4d:5e,7200,1700003600,1,0,0,old-name,0,,0
192.168.1.51,00:1a:2b:3c:4d:5f,,7200,1700003600,1,0,0,declined,1,,0
192.168.1.52,00:1a:2b:3c:4d:60,,7200,1700003600,1,0,0,,0,,0
192.168.1.54,00:1a:2b:3c:4d:62,,7200,1700003600,1,0,0,was-here,0,,0
192.168.1.50,00:1a:2b:3c:4d:5e,01:00:1a:2b:3c:4d:5e,7200,1700007200,1,0,0,laptop.lan.,0,{ "a": 1, "b": 2 },0
192.168.1.54,00:1a:2b:3c:4d:62,,0,1700003600,1,0,0,was-here,2,,0
not-an-address,00:1a:2b:3c:4d:63,,7200,1700003600,1,0,0,broken,0,,0
short
address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,hwtype,hwaddr_source,pool_id
fd00::1c3,00:01:00:01:2b:11:22:33:00:1a:2b:3c:4d:60,7200,1700003600,1,3600,0,1052436,128,0,0,phone.lan.,00:1a:2b:3c:4d:65,0,,1,2,0
fd00::1c4,00:01:00:01:2b:11:22:33:00:1a:2b:3c:4d:61,7200,1700003600,1,3600,0,1052437,128,0,0,tablet,,0,,,,0
`))
	want := []string{
		"00:1a:2b:3c:4d:5e 192.168.1.50 laptop.lan.",
		"00:1a:2b:3c:4d:65 fd00::1c3 phone.lan.",
		"- fd00::1c4 tablet",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
	// A line before any header has no columns to tell its name by.
	if got := ParseKeaLeases("192.168.1.50,00:1a:2b:3c:4d:5e,,7200,1700003600,1,0,0,laptop,0,,0\n"); len(got) != 0 {
		t.Errorf("without a header: %v", got)
	}
}

// The names of the leases are registered at their MAC, or at the MAC the neighbor table read with
// them has their address at; cleaned by the state, which leaves out those that are none; and not
// at all when the state takes no names.
func TestRegisterLeases(t *testing.T) {
	mac := func(s string) net.HardwareAddr {
		hw, err := net.ParseMAC(s)
		if err != nil {
			t.Fatal(err)
		}
		return hw
	}
	leases := []Lease{
		{MAC: mac("00:1a:2b:3c:4d:5e"), IP: netip.MustParseAddr("192.168.1.50"), Name: "Laptop.lan."},
		{MAC: mac("00:1a:2b:3c:4d:5f"), IP: netip.MustParseAddr("192.168.1.51"), Name: "*"},
		{MAC: mac("00:1a:2b:3c:4d:60"), Name: "ESP_1A2B3C"},
		{IP: netip.MustParseAddr("fd00::1c3"), Name: "phone"},
		{IP: netip.MustParseAddr("fd00::1c4"), Name: "nobody"}, // no neighbor has it
		{MAC: mac("01:00:5e:00:00:fb"), Name: "group"},
		{Name: "nothing"},
	}
	neighbors := map[netip.Addr]net.HardwareAddr{netip.MustParseAddr("fd00::1c3"): mac("00:1a:2b:3c:4d:61")}

	state := ipv6disc.NewState()
	defer state.Close()
	RegisterLeases(state, leases, neighbors, "router", "linux", time.Hour)
	if got := state.AllNames(); len(got) != 0 {
		t.Errorf("names in a state that takes none: %v", got)
	}

	state.SetNames(true, 0)
	RegisterLeases(state, leases, neighbors, "router", "linux", time.Hour)
	var got []string
	for mac, names := range state.AllNames() {
		for _, n := range names {
			got = append(got, mac+" "+n.Name+" "+strings.Join(n.Sources, ","))
		}
	}
	slices.Sort(got)
	want := []string{
		"00:1a:2b:3c:4d:5e laptop router",
		"00:1a:2b:3c:4d:60 esp-1a2b3c router",
		"00:1a:2b:3c:4d:61 phone router",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

// The addresses of the leases: a lease finds no host, and says of an address something else found
// that it is leased, until the lease is gone. It keeps the address no longer than the others do.
func TestRegisterLeasesAttach(t *testing.T) {
	state := ipv6disc.NewState()
	defer state.Close()
	state.SetFamilies(true, true)
	laptop, _ := net.ParseMAC("00:1a:2b:3c:4d:5e")
	phone, _ := net.ParseMAC("00:1a:2b:3c:4d:61")
	leases := []Lease{
		{MAC: laptop, IP: netip.MustParseAddr("192.168.1.50")},
		{MAC: laptop, IP: netip.MustParseAddr("192.168.1.99")}, // nothing found it
		{IP: netip.MustParseAddr("fd00::1c3")},
	}
	neighbors := map[netip.Addr]net.HardwareAddr{netip.MustParseAddr("fd00::1c3"): phone}
	a, _ := state.Report(laptop, netip.MustParseAddr("192.168.1.50"), "router", "linux", ipv6disc.FromNeighbors, 50*time.Millisecond, nil)
	b, _ := state.Report(phone, netip.MustParseAddr("fd00::1c3"), "router", "linux", ipv6disc.FromNeighbors, time.Hour, nil)
	RegisterLeases(state, leases, neighbors, "router", "linux", time.Hour)

	leased := func(addr *ipv6disc.Addr) bool {
		return slices.ContainsFunc(addr.Records(), func(r ipv6disc.Record) bool {
			return r.From == ipv6disc.FromLeases && r.By == "router" && r.Type == "linux" && r.Attached()
		})
	}
	if !leased(a) || !leased(b) {
		t.Errorf("the leased addresses: %v, %v", a.Records(), b.Records())
	}
	if got := state.GetAll()[laptop.String()].Get(); len(got) != 1 {
		t.Errorf("the laptop's addresses: %v: a lease of an address nothing found found it", got)
	}
	// The lease, of an hour, keeps the laptop's address no longer than its report.
	if until := a.GetExpiration(); time.Until(until) > time.Second {
		t.Errorf("the laptop's address, leased, stays until %s", until)
	}
	time.Sleep(100 * time.Millisecond)
	if a.Valid() {
		t.Error("the laptop's address is valid after its report expired: its lease kept it")
	}
	RegisterLeases(state, leases, neighbors, "router", "linux", time.Hour)
	if a.Valid() {
		t.Error("a lease brought an expired address back")
	}
}

func FuzzParseLeases(f *testing.F) {
	f.Add("1700003600 00:1a:2b:3c:4d:5e 192.168.1.50 laptop 01:00:1a:2b:3c:4d:5e\nduid 00:01\n1700003600 1052436 fd00::1c3 phone 00:01\n")
	f.Add("lease 192.168.1.50 {\n  binding state active;\n  hardware ethernet 00:1a:2b:3c:4d:5e;\n  client-hostname \"laptop\";\n}\n")
	f.Add("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n192.168.1.50,00:1a:2b:3c:4d:5e,,7200,1700003600,1,0,0,laptop,0\n")
	f.Add("fd00::1c3\tphone.lan\tphone\n# comment\n")
	f.Fuzz(func(t *testing.T, output string) {
		lines := strings.Count(output, "\n") + 1
		for parser, parse := range map[string]func(string) []Lease{
			"dnsmasq": ParseDnsmasqLeases, "hosts": ParseHosts, "ISC": ParseISCLeases, "Kea": ParseKeaLeases,
		} {
			leases := parse(output)
			if len(leases) > lines {
				t.Errorf("%s: %d leases from %d lines", parser, len(leases), lines)
			}
			for _, l := range leases {
				if !l.IP.IsValid() || l.Name == "" {
					t.Errorf("%s: lease %+v", parser, l)
				}
			}
			// Whatever the names, the state takes labels only.
			state := ipv6disc.NewState()
			state.SetNames(true, 0)
			RegisterLeases(state, leases, nil, "test", "linux", time.Hour)
			for _, names := range state.AllNames() {
				for _, n := range names {
					if clean, ok := ipv6disc.CleanName(n.Name); !ok || clean != n.Name {
						t.Errorf("%s: the name %q registered", parser, n.Name)
					}
				}
			}
			state.Close()
		}
	})
}
