//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package arp

import (
	"errors"
	"fmt"
	"runtime"
)

// Table isn't there on this system: the plugins read the IPv4 neighbors of routers.
func Table() ([]Neighbor, error) {
	return nil, fmt.Errorf("reading the neighbor table on %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
