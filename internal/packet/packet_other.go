//go:build !linux

package packet

import (
	"errors"
	"fmt"
	"net"
	"runtime"

	"golang.org/x/net/bpf"
)

// Conn is never there: Listen needs Linux's packet sockets.
type Conn struct{}

func Listen(iface *net.Interface, protocol uint16, filter []bpf.Instruction) (*Conn, error) {
	return nil, fmt.Errorf("listening for frames on %s: %w", runtime.GOOS, errors.ErrUnsupported)
}

func (c *Conn) Join(*net.Interface, net.HardwareAddr) error { return errors.ErrUnsupported }

func (c *Conn) Read([]byte) (int, net.HardwareAddr, bool, error) {
	return 0, nil, false, net.ErrClosed
}

func (c *Conn) Close() error { return nil }
