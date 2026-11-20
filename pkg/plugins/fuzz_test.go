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
	f.Add("60s, 192.0.2.1, user, pass")
	f.Fuzz(func(t *testing.T, config string) {
		cfg, err := ParseSSHConfig("linux", config)
		if err != nil {
			return
		}
		if cfg.Interval <= 0 {
			t.Errorf("%q: interval %s accepted", config, cfg.Interval)
		}
		if cfg.Address == "" || cfg.Username == "" || cfg.Address != strings.TrimSpace(cfg.Address) || cfg.Username != strings.TrimSpace(cfg.Username) {
			t.Errorf("%q: address %q and username %q accepted", config, cfg.Address, cfg.Username)
		}
	})
}

func TestFormatAddress(t *testing.T) {
	for address, want := range map[string]string{
		"router":             "router:22",
		"router:2222":        "router:2222",
		"192.0.2.1":          "192.0.2.1:22",
		"2001:db8::1":        "[2001:db8::1]:22",
		"[2001:db8::1]":      "[2001:db8::1]:22",
		"[2001:db8::1]:2222": "[2001:db8::1]:2222",
		"fe80::1%eth0":       "[fe80::1%eth0]:22",
		"[fe80::1%eth0]:23":  "[fe80::1%eth0]:23",
		// What can't be told apart stays as it is: an IPv6 address with a port needs its brackets,
		// and an empty host or port is left for the dial to refuse.
		"2001:db8::1:2222": "[2001:db8::1:2222]:22",
		"router:":          "router:",
		":2222":            ":2222",
		"":                 ":22",
	} {
		if got := FormatAddress(address, "22"); got != want {
			t.Errorf("FormatAddress(%q) = %q, want %q", address, got, want)
		}
	}
}
