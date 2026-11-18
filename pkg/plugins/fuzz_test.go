package plugins

import (
	"net"
	"strings"
	"testing"
)

func FuzzFormatAddress(f *testing.F) {
	for _, s := range []string{"router", "router:22", "2001:db8::1", "[2001:db8::1]", "[2001:db8::1]:2222", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, address string) {
		result := FormatAddress(address, "22")
		if strings.ContainsAny(address, "[]:") {
			return // a malformed address can stay malformed
		}
		if host, port, err := net.SplitHostPort(result); err != nil || host != address || port != "22" {
			t.Errorf("FormatAddress(%q) = %q", address, result)
		}
	})
}

func FuzzParseSSHConfig(f *testing.F) {
	f.Add("60s,192.0.2.1,user,pass,/key")
	f.Add("0s,,,")
	f.Fuzz(func(t *testing.T, config string) {
		cfg, err := ParseSSHConfig("linux", config)
		if err == nil && cfg.Interval <= 0 {
			t.Errorf("%q: interval %s accepted", config, cfg.Interval)
		}
	})
}
