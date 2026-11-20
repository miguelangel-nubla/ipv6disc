package plugins

import (
	"slices"
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
	}, Field{Name: "interval", Required: true}, Field{Name: "address"}, Field{Name: "username"}, Field{Name: "password"}, Field{Name: "use_tls"}, Field{Name: "fingerprint"})
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
		// Spaces around the names and the values, as after a comma, and capitals in the names:
		// dropped, but the spaces of the password.
		"interval=60s, address=a, username = u , password= p ":    "60s,a,u, p ",
		" Interval=60s,Address=a,USERNAME=u,password=p,Use_TLS=1": "60s,a,u,p,1",
		// The first four always there.
		"interval=60s": "60s,,,",
	} {
		got = ""
		if _, err := Create("fake", "test", config, time.Hour); err != nil || got != want {
			t.Errorf("%s: got %q, %v, want %q", config, got, err, want)
		}
	}

	for config, wantErr := range map[string]string{
		"interval=60s,port=22":       "has no port",
		"interval=60s,192.0.2.1":     "isn't name=value",
		"interval=60s,interval=30s":  "given twice",
		"intreval=60s,address=a":     "has no intreval",
		"address=a":                  "needs interval",
		"interval=60s, port=22":      "has no port:",
		"interval=60s, Interval=30s": "given twice",
		"Intreval=60s,address=a":     "has no intreval",
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

// A type that is described and not registered, as with a typo in one of the names, is not a type.
func TestDescribedOnly(t *testing.T) {
	Describe("ghost", "x")
	defer func() {
		mu.Lock()
		delete(registry, "ghost")
		mu.Unlock()
	}()

	if _, err := Create("ghost", "test", "60s,a,u,p", time.Hour); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("Create: got %v, want not found", err)
	}
	if _, err := Fields("ghost"); err == nil {
		t.Error("Fields: want an error")
	}
	if _, err := FieldParams("ghost", map[string]string{"interval": "60s"}); err == nil {
		t.Error("FieldParams: want an error")
	}
	if slices.Contains(Types(), "ghost") {
		t.Errorf("Types: %v", Types())
	}
	if got := Description("ghost"); got != "x" {
		t.Errorf("Description: %q", got)
	}

	// Registered without a factory: the same.
	Register("ghost", nil)
	if _, err := Create("ghost", "test", "60s,a,u,p", time.Hour); err == nil || slices.Contains(Types(), "ghost") {
		t.Errorf("without a factory: Create %v, Types %v", err, Types())
	}

	// Registered after: a type, with its description.
	Register("ghost", func(string, string, time.Duration) (ipv6disc.Plugin, error) { return nil, nil })
	if _, err := Create("ghost", "test", "60s,a,u,p", time.Hour); err != nil || !slices.Contains(Types(), "ghost") || Description("ghost") != "x" {
		t.Errorf("registered: Create %v, Types %v, description %q", err, Types(), Description("ghost"))
	}
}
