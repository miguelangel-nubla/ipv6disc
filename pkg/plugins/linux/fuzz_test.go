package linux

import (
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

func FuzzParseNDPOutput(f *testing.F) {
	f.Add("fe80::1 dev eth0 lladdr 00:1a:2b:3c:4d:08 STALE\n2001:db8::2 dev eth0  FAILED\n")
	f.Add("2001:db8::1 dev eth0 lladdr 00:1a:2b:3c:4d:09 router REACHABLE\nlladdr\n lladdr lladdr lladdr lladdr lladdr\n")
	f.Fuzz(func(t *testing.T, output string) {
		state := ipv6disc.NewState()
		plugin := &LinuxPlugin{name: "test", lifetime: time.Hour}
		count := plugin.parseNDPOutput(output, state)

		registered := 0
		for _, collection := range state.GetAll() {
			for _, addr := range collection.Get() {
				registered++
				addr.Unwatch()
			}
		}
		if count != registered {
			t.Errorf("counted %d new neighbors, the state has %d", count, registered)
		}
		if count > strings.Count(output, "lladdr") {
			t.Errorf("counted %d neighbors from %d lladdr", count, strings.Count(output, "lladdr"))
		}
	})
}
