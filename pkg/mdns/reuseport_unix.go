//go:build unix && !solaris && !illumos

package mdns

import "golang.org/x/sys/unix"

func reusePort(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
