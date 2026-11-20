//go:build linux

package arp

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSettle(t *testing.T) {
	neighSysctl = t.TempDir()
	defer func() { neighSysctl = "/proc/sys/net/ipv4/neigh" }()
	set := func(iface string, values map[string]string) {
		os.MkdirAll(filepath.Join(neighSysctl, iface), 0o755)
		for name, value := range values {
			os.WriteFile(filepath.Join(neighSysctl, iface, name), []byte(value+"\n"), 0o644)
		}
	}
	set("defaults", map[string]string{"delay_first_probe_time": "5", "retrans_time_ms": "1000", "ucast_solicit": "3", "app_solicit": "0"})
	set("quick", map[string]string{"delay_first_probe_time": "2", "retrans_time_ms": "500", "ucast_solicit": "4", "app_solicit": "1"})
	set("garbage", map[string]string{"delay_first_probe_time": "soon", "retrans_time_ms": "-1"})
	set("slow", map[string]string{"delay_first_probe_time": "60"})
	set("none", map[string]string{"delay_first_probe_time": "0", "retrans_time_ms": "0", "ucast_solicit": "0"})
	for iface, want := range map[string]time.Duration{
		"defaults": 9 * time.Second,
		"quick":    5500 * time.Millisecond,
		"missing":  9 * time.Second, // the kernel's defaults
		"garbage":  9 * time.Second,
		"slow":     maxSettle,
		"none":     minSettle,
	} {
		if got := Settle(iface); got != want {
			t.Errorf("%s: %s, want %s", iface, got, want)
		}
	}
}

// The machine's own: what the kernel has, within the bounds.
func TestSettleOfTheMachine(t *testing.T) {
	if got := Settle("lo"); got < minSettle || got > maxSettle {
		t.Errorf("lo: %s", got)
	}
}
