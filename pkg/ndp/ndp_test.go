package ndp

import (
	"sync/atomic"
	"testing"
)

func TestConnStatisticsAreAtomicallyAccessible(t *testing.T) {
	// Use adjacent connections as well as a single allocation: every element
	// must keep its counters aligned on 32-bit architectures.
	connections := make([]Conn, 2)
	for i := range connections {
		conn := &connections[i]
		conn.IncrementHostsFound()
		atomic.AddUint64(&conn.stats.DiscoveryRuns, 2)
		atomic.AddUint64(&conn.stats.PacketsSent, 3)
		atomic.AddUint64(&conn.stats.PacketsReceived, 4)
		stats := conn.Stats()
		for key, want := range map[string]uint64{"hosts": 1, "runs": 2, "sent": 3, "recv": 4} {
			if got := stats[key]; got != want {
				t.Errorf("connection %d %s = %v, want %d", i, key, got, want)
			}
		}
	}
}
