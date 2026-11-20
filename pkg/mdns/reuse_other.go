//go:build !unix && !windows

package mdns

import "syscall"

// reuse does nothing: no system the command is released for is left here.
func reuse(syscall.RawConn) error { return nil }
