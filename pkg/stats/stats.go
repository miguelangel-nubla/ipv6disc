// Package stats holds the counters every discovery protocol keeps.
package stats

import "sync/atomic"

type Counters struct {
	DiscoveryRuns   atomic.Uint64
	HostsFound      atomic.Uint64
	PacketsSent     atomic.Uint64
	PacketsReceived atomic.Uint64
}

func (c *Counters) Stats() map[string]any {
	return map[string]any{
		"runs":  c.DiscoveryRuns.Load(),
		"hosts": c.HostsFound.Load(),
		"sent":  c.PacketsSent.Load(),
		"recv":  c.PacketsReceived.Load(),
	}
}
