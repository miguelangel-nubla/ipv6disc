package arp

import (
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
not an entry
`
	got := ParseBSD(output)
	want := []struct{ ip, mac, iface string }{
		{"192.168.1.10", "00:11:22:33:44:55", "em0"},
		{"192.168.1.1", "00:11:22:03:44:66", "en0"},
		{"192.168.1.254", "00:11:22:33:44:77", "em0"},
		{"224.0.0.251", "01:00:5e:00:00:fb", "en0"},
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
	for _, bad := range []string{"(incomplete)", "0:0:0:0:0:0", "nope"} {
		if _, err := ParseMAC(bad); err == nil {
			t.Errorf("ParseMAC(%q): want an error", bad)
		}
	}
}

func FuzzParseBSD(f *testing.F) {
	f.Add("? (192.168.1.10) at 00:11:22:33:44:55 on em0 expires in 1189 seconds [ethernet]\n")
	f.Add("? () at on\n? (1.2.3.4) at 0:0:0:0:0:1\n")
	f.Fuzz(func(t *testing.T, output string) {
		for _, n := range ParseBSD(output) {
			if !n.IP.Is4() || len(n.MAC) == 0 {
				t.Errorf("%q gives %v", output, n)
			}
		}
	})
}
