package mikrotik

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

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

// A certificate fingerprint, as RouterOS and openssl show it.
const testFingerprint = "AB:cd:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab"

func TestParseConfig(t *testing.T) {
	normalized := strings.ToLower(strings.ReplaceAll(testFingerprint, ":", ""))
	cfg, err := ParseConfig("60s,192.0.2.1,admin,secret,TRUE," + testFingerprint)
	if err != nil || !cfg.UseTLS || cfg.TLSFingerprint != normalized || len(normalized) != 64 || cfg.Address != "192.0.2.1" || cfg.Username != "admin" || cfg.Password != "secret" {
		t.Errorf("got %+v, %v", cfg, err)
	}
	// The spaces after the commas are not of the values, but of the password.
	cfg, err = ParseConfig("60s, 192.0.2.1, admin, secret, true , " + normalized + " ")
	if err != nil || !cfg.UseTLS || cfg.TLSFingerprint != normalized || cfg.Address != "192.0.2.1" || cfg.Username != "admin" || cfg.Password != " secret" {
		t.Errorf("with spaces: got %+v, %v", cfg, err)
	}
	for config, useTLS := range map[string]bool{
		"60s,192.0.2.1,admin,secret":        false,
		"60s,192.0.2.1,admin,secret,":       false,
		"60s,192.0.2.1,admin,secret,false":  false,
		"60s,192.0.2.1,admin,secret,false,": false,
		"60s,192.0.2.1,admin,secret,0":      false,
		"60s,192.0.2.1,admin,secret,true":   true,
		"60s,192.0.2.1,admin,secret,True,":  true,
		"60s,192.0.2.1,admin,secret,1":      true,
		"60s,192.0.2.1,admin,":              false, // no password
	} {
		if cfg, err := ParseConfig(config); err != nil || cfg.UseTLS != useTLS || cfg.TLSFingerprint != "" {
			t.Errorf("%q: got %+v, %v, want TLS %v", config, cfg, err, useTLS)
		}
	}
	for _, bad := range []string{
		"60s,192.0.2.1,admin", "never,192.0.2.1,admin,secret", "0s,192.0.2.1,admin,secret",
		// No address would be this machine.
		"60s,,admin,secret", "60s, ,admin,secret", "60s,192.0.2.1,,secret",
		// Not true: it must not pass for false, the password in the clear.
		"60s,192.0.2.1,admin,secret,yes", "60s,192.0.2.1,admin,secret,on", "60s,192.0.2.1,admin,secret,ture",
		// A fingerprint that no certificate can have.
		"60s,192.0.2.1,admin,secret,true,abcd01", "60s,192.0.2.1,admin,secret,true,SHA256:abc", "60s,192.0.2.1,admin,secret,true," + normalized + "00",
		// A fingerprint that would not be checked.
		"60s,192.0.2.1,admin,secret,," + normalized, "60s,192.0.2.1,admin,secret,false," + normalized,
		"60s,192.0.2.1,admin,secret,true," + normalized + ",extra",
	} {
		if _, err := ParseConfig(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

func TestCreateByName(t *testing.T) {
	normalized := strings.ToLower(strings.ReplaceAll(testFingerprint, ":", ""))
	if _, err := plugins.Create("mikrotik", "router", "interval=60s, address=192.0.2.1, username=admin, password=secret, use_tls=true, tls_fingerprint="+testFingerprint, time.Hour); err != nil {
		t.Error(err)
	}
	// As a program with the params as fields gives them: the fingerprint without use_tls.
	for _, bad := range []string{
		"interval=60s,address=192.0.2.1,username=admin,password=secret,tls_fingerprint=" + normalized,
		"interval=60s,address=192.0.2.1,username=admin,password=secret,use_tls=yes",
	} {
		if _, err := plugins.Create("mikrotik", "router", bad, time.Hour); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

var neighbors = []map[string]string{
	{"address": "2001:db8::1", "mac-address": "00:11:22:33:44:01", "status": "reachable"},
	{"address": "fe80::2%bridge", "mac-address": "00:11:22:33:44:02", "status": "delay"},
	{"address": "2001:db8::3", "mac-address": "00:11:22:33:44:03"}, // no status
	{"address": "2001:db8::4", "mac-address": "00:11:22:33:44:04", "status": "stale"},
	{"address": "2001:db8::5", "mac-address": "00:11:22:33:44:05", "status": "failed"},
	{"address": "2001:db8::6", "status": "incomplete"},
	{"address": "not an address", "mac-address": "00:11:22:33:44:07", "status": "reachable"},
	{"address": "2001:db8::8", "mac-address": "not a MAC", "status": "reachable"},
}

var arpTable = []map[string]string{
	{"address": "192.168.88.10", "mac-address": "00:11:22:33:44:10", "interface": "bridge", "status": "reachable"},
	{"address": "192.168.88.11", "mac-address": "00:11:22:33:44:11", "interface": "bridge", "status": "stale"},
	{"address": "192.168.88.12", "interface": "bridge", "status": "failed"},
}

func neighborTable(command string) []map[string]string {
	switch command {
	case "/ipv6/neighbor/print":
		return neighbors
	case "/ip/arp/print":
		return arpTable
	}
	return nil
}

func TestDiscover(t *testing.T) {
	address := serveRouterOS(t, nil, neighborTable)
	plugin := NewMikrotikPlugin("router", Config{Interval: time.Minute, Address: address, Username: "admin"}, time.Hour)
	state := ipv6disc.NewState()

	found, err := plugin.discover(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if found != 3 {
		t.Errorf("found %d, want the 3 neighbors in use", found)
	}
	var got []string
	for mac, collection := range state.GetAll() {
		for _, addr := range collection.Get() {
			got = append(got, mac+" "+addr.WithZone("").String())
			if sources := addr.Sources(); len(sources) != 1 || sources[0] != "router" {
				t.Errorf("%s: sources %v, want the plugin's name", addr, sources)
			}
			addr.Unwatch()
		}
	}
	slices.Sort(got)
	want := []string{"00:11:22:33:44:01 2001:db8::1", "00:11:22:33:44:02 fe80::2", "00:11:22:33:44:03 2001:db8::3"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	if found, err := plugin.discover(context.Background(), state); err != nil || found != 0 {
		t.Errorf("again: found %d, %v, want none new", found, err)
	}
}

func TestDiscoverTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()
	certificate := server.TLS.Certificates[0]
	hash := sha256.Sum256(certificate.Certificate[0])
	fingerprint := hex.EncodeToString(hash[:])
	address := serveRouterOS(t, &tls.Config{Certificates: []tls.Certificate{certificate}}, neighborTable)

	for _, tt := range []struct {
		fingerprint string
		ok          bool
	}{
		{fingerprint, true},
		{strings.Repeat("0", 64), false},
		{"", false}, // a self-signed certificate, untrusted
	} {
		plugin := NewMikrotikPlugin("router", Config{Interval: time.Minute, Address: address, Username: "admin", UseTLS: true, TLSFingerprint: tt.fingerprint}, time.Hour)
		_, err := plugin.discover(context.Background(), ipv6disc.NewState())
		if (err == nil) != tt.ok {
			t.Errorf("fingerprint %q: got %v, want success %v", tt.fingerprint, err, tt.ok)
		}
	}
}

// RouterOS lists the multicast groups the router joined among its neighbors: they are not hosts.
func TestDiscoverSkipsGroups(t *testing.T) {
	address := serveRouterOS(t, nil, func(command string) []map[string]string {
		if command == "/ip/arp/print" {
			return []map[string]string{
				{"address": "224.0.0.251", "mac-address": "01:00:5e:00:00:fb", "status": "noarp"},
				{"address": "192.168.88.255", "mac-address": "ff:ff:ff:ff:ff:ff", "status": "noarp"},
				{"address": "192.168.88.20", "mac-address": "00:11:22:33:44:20", "status": "noarp"},
			}
		}
		return []map[string]string{
			{"address": "ff02::1", "mac-address": "33:33:00:00:00:01", "status": "noarp"},
			{"address": "ff02::1:ff00:1", "mac-address": "33:33:ff:00:00:01", "status": "noarp"},
			{"address": "2001:db8::1", "mac-address": "00:11:22:33:44:01", "status": "reachable"},
			{"address": "2001:db8::2", "mac-address": "00:11:22:33:44:02", "status": "noarp"},
		}
	})
	state := ipv6disc.NewState()
	state.SetFamilies(true, true)
	found, err := NewMikrotikPlugin("router", Config{Interval: time.Minute, Address: address, Username: "admin"}, time.Hour).discover(context.Background(), state)
	if err != nil || found != 3 {
		t.Errorf("found %d, %v, want the 3 hosts", found, err)
	}
	var got []string
	for mac := range state.GetAll() {
		got = append(got, mac)
	}
	slices.Sort(got)
	if want := []string{"00:11:22:33:44:01", "00:11:22:33:44:02", "00:11:22:33:44:20"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A router that accepts the connection and says nothing, or stops answering once logged in, must
// not hold the poll past its context: neither the next polls nor the shutdown would come.
func TestDiscoverStopsWithItsContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	release := make(chan struct{})
	defer close(release)
	loggedIn := serveRouterOS(t, nil, func(string) []map[string]string {
		<-release // a table that never comes
		return nil
	})

	for name, address := range map[string]string{"silent": listener.Addr().String(), "silent once logged in": loggedIn} {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		plugin := NewMikrotikPlugin("router", Config{Interval: time.Minute, Address: address, Username: "admin"}, time.Hour)
		done := make(chan error, 1)
		go func() {
			_, err := plugin.discover(ctx, ipv6disc.NewState())
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("%s: got %v, want the deadline of the context", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s: the poll goes on after its context is done", name)
		}
		cancel()
	}
}

func TestStartNeedsAnInterval(t *testing.T) {
	plugin := NewMikrotikPlugin("router", Config{Address: "192.0.2.1", Username: "admin"}, time.Hour)
	if err := plugin.Start(context.Background(), ipv6disc.NewState(), nil); err == nil {
		t.Error("no interval: want an error")
	}
}

func TestDiscoverUnreachable(t *testing.T) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	address := listener.Addr().String()
	listener.Close()
	plugin := NewMikrotikPlugin("router", Config{Interval: time.Minute, Address: address, Username: "admin"}, time.Hour)
	if _, err := plugin.discover(context.Background(), ipv6disc.NewState()); err == nil {
		t.Error("nothing listening: want an error")
	}
}

func FuzzParseConfig(f *testing.F) {
	f.Add("60s,192.0.2.1,admin,secret,true," + testFingerprint)
	f.Add("60s, 192.0.2.1, admin, secret, yes")
	f.Add("-1s,,,")
	f.Fuzz(func(t *testing.T, config string) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return
		}
		if cfg.Interval <= 0 {
			t.Errorf("%q: interval %s accepted", config, cfg.Interval)
		}
		if cfg.Address == "" || cfg.Username == "" {
			t.Errorf("%q: address %q and username %q accepted", config, cfg.Address, cfg.Username)
		}
		if cfg.TLSFingerprint != "" && (!cfg.UseTLS || len(cfg.TLSFingerprint) != 64 || strings.Trim(cfg.TLSFingerprint, "0123456789abcdef") != "") {
			t.Errorf("%q: fingerprint %q accepted, TLS %v", config, cfg.TLSFingerprint, cfg.UseTLS)
		}
	})
}

func TestDiscoverIPv4(t *testing.T) {
	var asked []string
	address := serveRouterOS(t, nil, func(command string) []map[string]string {
		asked = append(asked, command)
		return neighborTable(command)
	})
	plugin := NewMikrotikPlugin("router", Config{Interval: time.Minute, Address: address, Username: "admin"}, time.Hour)

	state := ipv6disc.NewState()
	state.SetFamilies(true, true)
	found, err := plugin.discover(context.Background(), state)
	if err != nil || found != 4 {
		t.Errorf("found %d, %v, want the 3 IPv6 neighbors and the reachable IPv4 one", found, err)
	}
	if got := state.GetAll()["00:11:22:33:44:10"]; got == nil || got.Strings()[0] != "192.168.88.10" {
		t.Errorf("the IPv4 neighbor: %v", got)
	}
	if _, stale := state.GetAll()["00:11:22:33:44:11"]; stale {
		t.Error("the stale IPv4 neighbor is registered")
	}
	if !slices.Contains(asked, "/ip/arp/print") {
		t.Errorf("asked %v", asked)
	}
}

func TestDiscoverIPv4Only(t *testing.T) {
	var asked []string
	address := serveRouterOS(t, nil, func(command string) []map[string]string {
		asked = append(asked, command)
		return neighborTable(command)
	})
	state := ipv6disc.NewState()
	state.SetFamilies(false, true)
	found, err := NewMikrotikPlugin("router", Config{Interval: time.Minute, Address: address, Username: "admin"}, time.Hour).discover(context.Background(), state)
	if err != nil || found != 1 || !slices.Equal(asked, []string{"/ip/arp/print"}) {
		t.Errorf("found %d, %v, asked %v", found, err, asked)
	}
}
