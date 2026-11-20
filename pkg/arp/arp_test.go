package arp

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestParseBSD(t *testing.T) {
	output := `? (192.168.1.10) at 00:11:22:33:44:55 on em0 expires in 1189 seconds [ethernet]
? (192.168.1.1) at 0:11:22:3:44:66 on en0 ifscope [ethernet]
gateway.lan (192.168.1.254) at 00:11:22:33:44:77 on em0 permanent [ethernet]
? (192.168.1.12) at (incomplete) on em0 expired [ethernet]
? (192.168.1.13) at 00:11:22:33:44:88 on em0 expired [ethernet]
? (224.0.0.251) at 01:00:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (192.168.1.14) at 0:0:0:0:0:0 on en0 [ethernet]
? (10.2.3.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (255.255.255.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (239.255.255.250) at 1:0:5e:7f:ff:fa on en0 ifscope permanent [ethernet]
? (192.168.1.15) at 80:00:00:48:fe:80:00:00:00:00:00:00:00:02:c9:03:00:1a:2b:3c on ib0 [infiniband]
? (192.168.1.16) at 00:11:22:33:44:99 [ether] on eth0
not an entry
`
	got := ParseBSD(output)
	want := []struct{ ip, mac, iface string }{
		{"192.168.1.10", "00:11:22:33:44:55", "em0"},
		{"192.168.1.1", "00:11:22:03:44:66", "en0"},
		{"192.168.1.254", "00:11:22:33:44:77", "em0"},
		{"192.168.1.16", "00:11:22:33:44:99", "eth0"}, // as Linux's net-tools write it
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i].IP.String() != w.ip || got[i].MAC.String() != w.mac || got[i].Interface != w.iface {
			t.Errorf("%d: got %v, want %v", i, got[i], w)
		}
	}
}

func TestParseMAC(t *testing.T) {
	for in, want := range map[string]string{
		"00:11:22:33:44:55": "00:11:22:33:44:55",
		"0:1:22:3:44:5":     "00:01:22:03:44:05",
	} {
		if got, err := ParseMAC(in); err != nil || got.String() != want {
			t.Errorf("ParseMAC(%q) = %v, %v, want %s", in, got, err, want)
		}
	}
	// As net.ParseMAC: longer ones, and a group's, which ParseBSD leaves out.
	for in, length := range map[string]int{"00:11:22:33:44:55:66:77": 8, "ff:ff:ff:ff:ff:ff": 6, "0011.2233.4455": 6} {
		if got, err := ParseMAC(in); err != nil || len(got) != length {
			t.Errorf("ParseMAC(%q) = %v, %v, want %d bytes", in, got, err, length)
		}
	}
	for _, bad := range []string{"(incomplete)", "0:0:0:0:0:0", "nope"} {
		if _, err := ParseMAC(bad); err == nil {
			t.Errorf("ParseMAC(%q): want an error", bad)
		}
	}
}

func FuzzParseBSD(f *testing.F) {
	f.Add("? (192.168.1.10) at 00:11:22:33:44:55 on em0 expires in 1189 seconds [ethernet]\n")
	f.Add("? () at on\n? (1.2.3.4) at 0:0:0:0:0:1\n")
	f.Add("? (10.2.3.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n? (224.0.0.251) at 1:0:5e:0:0:fb on en0\n")
	f.Add("? (0.0.0.0) at 0:1:2:3:4:5 on en0\n? (1.2.3.4) at 00:11:22:33:44:55:66:77 on en0\n")
	broadcast := netip.AddrFrom4([4]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, output string) {
		for _, n := range ParseBSD(output) {
			if !n.IP.Is4() || n.IP.IsMulticast() || n.IP.IsUnspecified() || n.IP == broadcast || len(n.MAC) != 6 || n.MAC[0]&1 != 0 {
				t.Errorf("%q gives %v", output, n)
			}
		}
	})
}

// The arp -an of a Mac and of a FreeBSD router, as they write it: only the hosts are neighbors,
// their own addresses among them, not the broadcast addresses, the multicast groups nor the
// incomplete and expired entries.
func TestParseBSDSamples(t *testing.T) {
	for file, want := range map[string][]string{
		"testdata/arp-an-macos.txt": {
			"10.2.3.1 00:11:22:33:44:01 en0",
			"10.2.3.20 00:11:22:03:04:05 en0",
			"10.2.3.75 3c:22:fb:00:0a:0b en0", // its own, permanent
			"10.2.3.90 a0:b1:c2:d3:e4:f5 en0",
			"192.168.64.1 52:ed:3c:00:00:64 bridge100",
			"192.168.64.7 0e:1f:2a:3b:4c:5d bridge100",
		},
		"testdata/arp-an-freebsd.txt": {
			"192.168.1.1 00:11:22:33:44:01 em0", // its own, permanent
			"192.168.1.10 00:11:22:33:44:55 em0",
			"192.168.1.22 a0:b1:c2:d3:e4:f5 em0",
			"10.10.0.1 00:11:22:33:44:02 em1.10",
			"10.10.0.5 0e:1f:2a:3b:4c:5d em1.10",
		},
	} {
		output, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, n := range ParseBSD(string(output)) {
			got = append(got, n.IP.String()+" "+n.MAC.String()+" "+n.Interface)
		}
		if len(got) != len(want) {
			t.Errorf("%s: got %v, want %v", file, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s: got %v, want %v", file, got[i], want[i])
			}
		}
	}
}

func TestIsHost(t *testing.T) {
	host := net.HardwareAddr{0, 0x11, 0x22, 0x33, 0x44, 0x55}
	for _, c := range []struct {
		ip   string
		mac  net.HardwareAddr
		want bool
	}{
		{"192.168.1.10", host, true},
		{"192.168.1.10", net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, true},               // locally administered
		{"10.2.3.255", net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false}, // a subnet's broadcast, by its MAC
		{"255.255.255.255", host, false},
		{"224.0.0.251", host, false},
		{"192.168.1.10", net.HardwareAddr{0x01, 0, 0x5e, 0, 0, 0xfb}, false},
		{"0.0.0.0", host, false},
		{"192.168.1.10", net.HardwareAddr{0, 1, 2, 3}, false},
		{"192.168.1.10", make(net.HardwareAddr, 20), false},
	} {
		if got := isHost(netip.MustParseAddr(c.ip), c.mac); got != c.want {
			t.Errorf("isHost(%s, %s) = %v, want %v", c.ip, c.mac, got, c.want)
		}
	}
}
