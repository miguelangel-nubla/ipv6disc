//go:build linux

package arp

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// neighSysctl is where the kernel's neighbor settings of each interface are: another for tests.
var neighSysctl = "/proc/sys/net/ipv4/neigh"

// Settle is how long after a sweep on iface the neighbor table has its answers: what the kernel
// takes to check an entry the sweep found stale, by its own settings for the interface, and a
// second more. It waits delay_first_probe_time before its first probe, then sends ucast_solicit
// probes and app_solicit asks retrans_time_ms apart: by then, a host that answers is confirmed
// again, and one that left has failed. With the defaults, 5s, 3 and 1s: 9s.
func Settle(iface string) time.Duration {
	read := func(name string, otherwise int) int {
		content, err := os.ReadFile(filepath.Join(neighSysctl, iface, name))
		if err != nil {
			return otherwise
		}
		v, err := strconv.Atoi(strings.TrimSpace(string(content)))
		if err != nil || v < 0 {
			return otherwise
		}
		return v
	}
	delay := time.Duration(read("delay_first_probe_time", 5)) * time.Second
	retrans := time.Duration(read("retrans_time_ms", 1000)) * time.Millisecond
	probes := read("ucast_solicit", 3) + read("app_solicit", 0)
	return min(max(delay+time.Duration(probes)*retrans+time.Second, minSettle), maxSettle)
}
