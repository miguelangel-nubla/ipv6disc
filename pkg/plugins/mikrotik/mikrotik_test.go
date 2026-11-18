package mikrotik

import "testing"

func TestNeighborInUse(t *testing.T) {
	for status, want := range map[string]bool{
		"reachable": true, "delay": true, "probe": true, "noarp": true, "": true,
		"stale": false, "failed": false,
	} {
		if got := neighborInUse(status); got != want {
			t.Errorf("neighborInUse(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig("60s,192.0.2.1,admin,secret,TRUE,AB:cd:01")
	if err != nil || !cfg.UseTLS || cfg.TLSFingerprint != "abcd01" || cfg.Address != "192.0.2.1" || cfg.Password != "secret" {
		t.Errorf("got %+v, %v", cfg, err)
	}
	if cfg, err := ParseConfig("60s,192.0.2.1,admin,secret"); err != nil || cfg.UseTLS {
		t.Errorf("without TLS: got %+v, %v", cfg, err)
	}
	for _, bad := range []string{"60s,192.0.2.1,admin", "never,192.0.2.1,admin,secret", "0s,192.0.2.1,admin,secret"} {
		if _, err := ParseConfig(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}
