//go:build !linux

package ipv6disc

import "net/netip"

// temporaryAddrs is known on Linux only: elsewhere, no address is said temporary.
func temporaryAddrs() map[netip.Addr]bool { return nil }
