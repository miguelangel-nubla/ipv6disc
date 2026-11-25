package unifi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

// The clients of the fake, as the UniFi Network API lists them, with fields the plugin doesn't
// read: a laptop of both families, with the name you gave it; a device of UniFi's; a client with
// an IPv4 address alone, and no name; and what is no host's: a group MAC, an address that is
// none, and a MAC that is none.
const fakeClients = `[
	{"mac": "00:11:22:33:44:10", "ip": "192.168.1.10", "ipv6_address": ["2001:db8::10", "fe80::10"], "hostname": "Laptop", "name": "Living Room TV", "last_seen": 1795567706, "is_wired": false},
	{"mac": "00:11:22:33:44:20", "ip": "192.168.1.20", "hostname": "U6-Lite", "type": "UNIFI_DEVICE"},
	{"mac": "00:11:22:33:44:30", "ip": "192.168.1.30"},
	{"mac": "01:00:5e:00:00:01", "ip": "192.168.1.40"},
	{"mac": "00:11:22:33:44:50", "ip": "not-an-address", "ipv6_address": ["2001:db8::50"]},
	{"mac": "not-a-mac", "ip": "192.168.1.60"}
]`

// fakeUniFi is the UniFi Network API of the clients: UniFi OS, with an API key or a login whose
// session the test can end, under /proxy/network; or a self-hosted Network Application, with a
// login of its own, which answers UniFi OS's as its API does without a session, and no prefix.
type fakeUniFi struct {
	unifiOS bool

	mutex    sync.Mutex
	sessions map[string]bool
	logins   int
	asked    []string
}

func newFake(t *testing.T, unifiOS bool) (*fakeUniFi, *httptest.Server) {
	f := &fakeUniFi{unifiOS: unifiOS, sessions: map[string]bool{}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	return f, server
}

func (f *fakeUniFi) fail(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	fmt.Fprint(w, body)
}

func (f *fakeUniFi) serve(w http.ResponseWriter, r *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.asked = append(f.asked, r.Method+" "+r.URL.RequestURI())
	switch {
	case r.URL.Path == "/api/auth/login" && !f.unifiOS:
		f.fail(w, http.StatusUnauthorized, `{"meta":{"rc":"error","msg":"api.err.LoginRequired"},"data":[]}`)
		return
	case r.URL.Path == "/api/auth/login" && f.unifiOS, r.URL.Path == "/api/login" && !f.unifiOS:
		var body struct{ Username, Password string }
		json.NewDecoder(r.Body).Decode(&body)
		if body.Username != "admin" || body.Password != " secret " {
			if f.unifiOS {
				f.fail(w, http.StatusForbidden, `{"message":"Invalid username or password","code":"AUTHENTICATION_FAILED_INVALID_CREDENTIALS"}`)
			} else {
				f.fail(w, http.StatusBadRequest, `{"meta":{"rc":"error","msg":"api.err.Invalid"},"data":[]}`)
			}
			return
		}
		f.logins++
		cookie := fmt.Sprintf("session%d", f.logins)
		f.sessions[cookie] = true
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: cookie, Path: "/"})
		fmt.Fprint(w, `{"username":"admin"}`)
		return
	}
	prefix := ""
	if f.unifiOS {
		prefix = "/proxy/network"
	}
	if r.URL.Path != prefix+"/v2/api/site/default/clients/active" {
		f.fail(w, http.StatusNotFound, `<html>404</html>`)
		return
	}
	if key := r.Header.Get("X-API-KEY"); key != "" {
		if key != "the-key" {
			f.fail(w, http.StatusUnauthorized, `{"error":{"code":401,"message":"Unauthorized"}}`)
			return
		}
	} else if c, err := r.Cookie("TOKEN"); err != nil || !f.sessions[c.Value] {
		f.fail(w, http.StatusUnauthorized, `{"code":"api.err.UserNotAuthenticated","errorCode":401,"message":"User not authenticated"}`)
		return
	}
	fmt.Fprint(w, fakeClients)
}

func fingerprint(server *httptest.Server) string {
	sum := sha256.Sum256(server.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

// addresses are the addresses of the state, as "MAC address".
func addresses(state *ipv6disc.State) []string {
	var got []string
	for mac, collection := range state.GetAll() {
		for _, a := range collection.Strings() {
			got = append(got, mac+" "+a)
		}
	}
	slices.Sort(got)
	return got
}

// The clients' addresses of the families the state takes, of hosts alone; their names, the host's
// and yours, when it takes names; reported by the plugin, from the neighbors.
func TestDiscover(t *testing.T) {
	_, server := newFake(t, true)
	plugin := NewUniFiPlugin("gateway", Config{Interval: time.Minute, Address: server.URL, APIKey: "the-key", Site: "default", TLSFingerprint: fingerprint(server)}, time.Hour)
	state := ipv6disc.NewState()
	defer state.Close()
	state.SetFamilies(true, true)
	state.SetNames(true, 0)
	found, err := plugin.discover(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"00:11:22:33:44:10 192.168.1.10", "00:11:22:33:44:10 2001:db8::10", "00:11:22:33:44:10 fe80::10",
		"00:11:22:33:44:20 192.168.1.20", "00:11:22:33:44:30 192.168.1.30", "00:11:22:33:44:50 2001:db8::50",
	}
	if got := addresses(state); !slices.Equal(got, want) || found != len(want) {
		t.Errorf("found %d: %q\nwant %q", found, got, want)
	}
	for _, collection := range state.GetAll() {
		for _, addr := range collection.Get() {
			records := addr.Records()
			if len(records) != 1 || records[0].By != "gateway" || records[0].Type != "unifi" || records[0].From != ipv6disc.FromNeighbors {
				t.Errorf("%s: records %+v", addr.Addr, records)
			}
		}
	}
	var names []string
	for mac, hostNames := range state.AllNames() {
		for _, n := range hostNames {
			names = append(names, mac+" "+n.Name+" "+strings.Join(n.Sources, ","))
		}
	}
	slices.Sort(names)
	if want := []string{"00:11:22:33:44:10 laptop gateway", "00:11:22:33:44:10 living-room-tv gateway", "00:11:22:33:44:20 u6-lite gateway"}; !slices.Equal(names, want) {
		t.Errorf("names %q\nwant %q", names, want)
	}

	// Again: what it found is there already.
	if found, err := plugin.discover(context.Background(), state); err != nil || found != 0 {
		t.Errorf("again: found %d, %v", found, err)
	}
}

// The families the state takes, alone; no names when it takes none.
func TestDiscoverFamilies(t *testing.T) {
	_, server := newFake(t, true)
	for _, c := range []struct {
		ipv6, ipv4 bool
		want       []string
	}{
		{true, false, []string{"00:11:22:33:44:10 2001:db8::10", "00:11:22:33:44:10 fe80::10", "00:11:22:33:44:50 2001:db8::50"}},
		{false, true, []string{"00:11:22:33:44:10 192.168.1.10", "00:11:22:33:44:20 192.168.1.20", "00:11:22:33:44:30 192.168.1.30"}},
	} {
		plugin := NewUniFiPlugin("gateway", Config{Interval: time.Minute, Address: server.URL, APIKey: "the-key", Site: "default", TLSFingerprint: fingerprint(server)}, time.Hour)
		state := ipv6disc.NewState()
		state.SetFamilies(c.ipv6, c.ipv4)
		if _, err := plugin.discover(context.Background(), state); err != nil {
			t.Fatal(err)
		}
		if got := addresses(state); !slices.Equal(got, c.want) {
			t.Errorf("IPv6 %v, IPv4 %v: %q\nwant %q", c.ipv6, c.ipv4, got, c.want)
		}
		if len(state.AllNames()) != 0 {
			t.Errorf("names taken: %v", state.AllNames())
		}
		state.Close()
	}
}

// A user: of UniFi OS, or of a self-hosted Network Application, which answers UniFi OS's login as
// any call without a session; one login, kept between polls, and another when it ends. The
// password is taken with its spaces.
func TestDiscoverLogin(t *testing.T) {
	for _, unifiOS := range []bool{true, false} {
		f, server := newFake(t, unifiOS)
		plugin := NewUniFiPlugin("gateway", Config{Interval: time.Minute, Address: server.URL, Username: "admin", Password: " secret ", Site: "default", TLSFingerprint: fingerprint(server)}, time.Hour)
		state := ipv6disc.NewState()
		state.SetFamilies(true, true)
		for range 2 {
			if _, err := plugin.discover(context.Background(), state); err != nil {
				t.Fatalf("UniFi OS %v: %v", unifiOS, err)
			}
		}
		f.mutex.Lock()
		logins := f.logins
		f.sessions = map[string]bool{}
		f.mutex.Unlock()
		if _, err := plugin.discover(context.Background(), state); err != nil {
			t.Fatalf("UniFi OS %v, after the session ended: %v", unifiOS, err)
		}
		if logins != 1 || f.logins != 2 || len(addresses(state)) != 6 {
			t.Errorf("UniFi OS %v: %d logins, then %d; %d addresses", unifiOS, logins, f.logins, len(addresses(state)))
		}
		state.Close()
	}
}

// Each refusal says why, and what to do; and a certificate of another fingerprint is refused.
func TestDiscoverErrors(t *testing.T) {
	_, os := newFake(t, true)
	_, self := newFake(t, false)
	for _, c := range []struct {
		name   string
		server *httptest.Server
		config Config
		want   string
	}{
		{"a wrong key", os, Config{APIKey: "wrong"}, "HTTP 401: the API key is refused"},
		{"a wrong password", os, Config{Username: "admin", Password: "wrong"}, "logging in: HTTP 403: the username or the password is refused"},
		{"a wrong password, self-hosted", self, Config{Username: "admin", Password: "wrong"}, "logging in: HTTP 400: the username or the password is refused"},
		{"a key, self-hosted", self, Config{APIKey: "the-key"}, "a self-hosted Network Application needs username and password"},
		{"another site", os, Config{APIKey: "the-key", Site: "other"}, `HTTP 404: no site "other" here`},
		{"another certificate", os, Config{APIKey: "the-key", TLSFingerprint: strings.Repeat("0", 64)}, "tls fingerprint mismatch"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.config
			cfg.Interval, cfg.Address = time.Minute, c.server.URL
			if cfg.Site == "" {
				cfg.Site = "default"
			}
			if cfg.TLSFingerprint == "" {
				cfg.TLSFingerprint = fingerprint(c.server)
			}
			_, err := NewUniFiPlugin("gateway", cfg, time.Hour).discover(context.Background(), ipv6disc.NewState())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
		})
	}
}

func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig("60s, https://192.168.1.1 ,the-key,,")
	if err != nil || cfg.Interval != time.Minute || cfg.Address != "https://192.168.1.1" || cfg.APIKey != "the-key" || cfg.Site != "default" {
		t.Errorf("%+v, %v", cfg, err)
	}
	cfg, err = ParseConfig("5m,https://unifi:8443,,admin, p w ,lab,AA:" + strings.Repeat("bb", 31))
	if err != nil || cfg.Password != " p w " || cfg.Site != "lab" || cfg.TLSFingerprint != "aa"+strings.Repeat("bb", 31) {
		t.Errorf("%+v, %v", cfg, err)
	}
	for config, want := range map[string]string{
		"60s":                                   "invalid unifi config format",
		"60s,https://u":                         "needs api_key, or username and password",
		"often,https://u,k,,":                   "invalid interval format",
		"0s,https://u,k,,":                      "it must be positive",
		"60s,,k,,":                              "needs its address",
		"60s,192.168.1.1,k,,":                   "invalid address",
		"60s,https://u,k,admin,p":               "not both",
		"60s,https://u,,admin,":                 "needs api_key, or username and password",
		"60s,https://u,k,,,default,abc":         "invalid tls_fingerprint",
		"60s,https://u,k,,,default,abc,toomany": "invalid unifi config format",
	} {
		if _, err := ParseConfig(config); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %s", config, err, want)
		}
	}
}

// The params by name, as a configuration file gives them.
func TestCreateByName(t *testing.T) {
	plugin, err := plugins.Create("unifi", "gateway", "interval=60s,address=https://192.168.1.1,api_key=the-key", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if p := plugin.(*UniFiPlugin); p.config.APIKey != "the-key" || p.config.Site != "default" || p.Name() != "gateway" {
		t.Errorf("%+v", p.config)
	}
}

// A poll ends with its context.
func TestDiscoverStopsWithItsContext(t *testing.T) {
	silent := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer silent.Close()
	plugin := NewUniFiPlugin("gateway", Config{Interval: time.Minute, Address: silent.URL, APIKey: "k", Site: "default", TLSFingerprint: fingerprint(silent)}, time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := plugin.discover(ctx, ipv6disc.NewState()); err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("%v after %s", err, time.Since(start))
	}
}
