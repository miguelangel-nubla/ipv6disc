package unifi

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

// A real UniFi Network: IPV6DISC_LIVE_UNIFI has the plugin's params by name, as
// interval=60s,address=https://...,api_key=...,tls_fingerprint=..., and more of them separated by
// a newline. Skipped without. A test server without a gateway knows no clients: the poll must
// log in, find the site's clients where the plugin asks, and read them, none.
//
// Of a console with a gateway, the clients it lists are logged, each with its fields of IPv6,
// whatever UniFi names them: what a real gateway gives of IPv6, which only a run against one tells.
func TestLiveUniFi(t *testing.T) {
	servers := os.Getenv("IPV6DISC_LIVE_UNIFI")
	if servers == "" {
		t.Skip("IPV6DISC_LIVE_UNIFI is not set")
	}
	for i, config := range strings.Split(strings.TrimSpace(servers), "\n") {
		plugin, err := plugins.Create("unifi", "gateway", strings.TrimSpace(config), time.Hour)
		if err != nil {
			t.Fatalf("server %d: %v", i+1, err)
		}
		state := ipv6disc.NewState()
		state.SetFamilies(true, true)
		state.SetNames(true, 0)
		for poll := range 2 {
			found, err := plugin.(*UniFiPlugin).discover(context.Background(), state)
			if err != nil {
				t.Fatalf("server %d, poll %d: %v", i+1, poll+1, err)
			}
			t.Logf("server %d, poll %d: %d addresses found, %d hosts", i+1, poll+1, found, len(state.GetAll()))
		}
		// What the gateway lists, as UniFi has it.
		var clients []map[string]any
		if err := plugin.(*UniFiPlugin).client.Call(context.Background(), http.MethodGet, "/clients/active?includeUnifiDevices=true", nil, &clients); err != nil {
			t.Fatalf("server %d: %v", i+1, err)
		}
		withIPv6 := 0
		for _, c := range clients {
			ipv6 := map[string]any{}
			for key, value := range c {
				if strings.Contains(strings.ToLower(key), "ipv6") {
					ipv6[key] = value
				}
			}
			if v, ok := c["ipv6_address"].([]any); ok && len(v) > 0 {
				withIPv6++
			}
			t.Logf("server %d: %v %v, hostname %q, name %q, IPv6 %v", i+1, c["mac"], c["ip"], c["hostname"], c["name"], ipv6)
		}
		t.Logf("server %d: %d clients, %d with IPv6 addresses in ipv6_address; the state has %d hosts, %d addresses", i+1, len(clients), withIPv6, len(state.GetAll()), countAddresses(state))
		state.Close()
	}
}

// countAddresses is how many addresses the state has.
func countAddresses(state *ipv6disc.State) int {
	n := 0
	for _, c := range state.GetAll() {
		n += len(c.Get())
	}
	return n
}
