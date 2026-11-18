//go:build !linux

package arp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
)

// Probe needs Linux's packet sockets.
func Probe(ctx context.Context, iface *net.Interface, local netip.Addr, mac net.HardwareAddr, targets []netip.Addr) ([]netip.Addr, error) {
	return nil, fmt.Errorf("probing by ARP on %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
