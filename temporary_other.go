//go:build !linux && !darwin

package ipv6disc

import "net/netip"

// temporaryAddrs is known on Linux and macOS only: elsewhere, no address is said temporary.
func temporaryAddrs() map[netip.Addr]bool { return nil }

// unlistenableAddrs is of macOS: elsewhere, no address the machine has is known not to be one
// that can be listened on.
func unlistenableAddrs() map[netip.Addr]bool { return nil }
