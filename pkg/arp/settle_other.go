//go:build !linux

package arp

import "time"

// Settle is how long after a sweep on iface the neighbor table has its answers.
func Settle(iface string) time.Duration { return minSettle }
