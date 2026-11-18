package plugins

import (
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

func TestParamsByName(t *testing.T) {
	var got string
	Register("fake", func(name, config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
		got = config
		return nil, nil
	}, "interval", "address", "username", "password", "use_tls", "fingerprint")
	defer func() {
		mu.Lock()
		delete(registry, "fake")
		mu.Unlock()
	}()

	for config, want := range map[string]string{
		// In order, as they are.
		"60s,192.0.2.1,admin,pass=word": "60s,192.0.2.1,admin,pass=word",
		// By name, in any order; the optional ones left out; a value with = and an escaped comma.
		`password=p\,w=d,interval=60s,username=admin,address=192.0.2.1`: `60s,192.0.2.1,admin,p\,w=d`,
		"interval=60s,address=a,username=u,password=p,fingerprint=ab":   "60s,a,u,p,,ab",
		// The first four always there.
		"interval=60s": "60s,,,",
	} {
		got = ""
		if _, err := Create("fake", "test", config, time.Hour); err != nil || got != want {
			t.Errorf("%s: got %q, %v, want %q", config, got, err, want)
		}
	}

	for config, wantErr := range map[string]string{
		"interval=60s,port=22":      "has no port",
		"interval=60s,192.0.2.1":    "isn't name=value",
		"interval=60s,interval=30s": "given twice",
	} {
		if _, err := Create("fake", "test", config, time.Hour); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("%s: got %v, want %q", config, err, wantErr)
		}
	}

	if fields, err := Fields("fake"); err != nil || len(fields) != 6 {
		t.Errorf("fields: %v, %v", fields, err)
	}
	if _, err := Fields("nope"); err == nil {
		t.Error("an unknown type: want an error")
	}
}
