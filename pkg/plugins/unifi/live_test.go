package unifi

import (
	"context"
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
		state.Close()
	}
}
