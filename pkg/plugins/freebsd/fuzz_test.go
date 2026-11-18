package freebsd

import (
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

func FuzzParseNDPOutput(f *testing.F) {
	f.Add("Neighbor Linklayer Address Netif Expire S Flags\n2001:db8::1 00:11:22:33:44:55 em0 permanent R\n2001:db8::2 (incomplete) em0 expired N\n")
	f.Fuzz(func(t *testing.T, output string) {
		state := ipv6disc.NewState()
		plugin := &FreeBSDPlugin{name: "test", lifetime: time.Hour}
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
		if lines := strings.Count(output, "\n") + 1; count > lines {
			t.Errorf("counted %d neighbors from %d lines", count, lines)
		}
	})
}
