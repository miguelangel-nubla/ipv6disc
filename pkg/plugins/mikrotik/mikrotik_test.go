package mikrotik

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
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
	f.Add("60s,192.0.2.1,admin,secret,true,AB:CD")
	f.Add("-1s,,,")
	f.Fuzz(func(t *testing.T, config string) {
		cfg, err := ParseConfig(config)
		if err != nil {
			return
		}
		if cfg.Interval <= 0 {
			t.Errorf("%q: interval %s accepted", config, cfg.Interval)
		}
		if strings.ContainsAny(cfg.TLSFingerprint, ":ABCDEF") {
			t.Errorf("%q: fingerprint %q not normalized", config, cfg.TLSFingerprint)
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
	state.EnableIPv4()
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
