//go:build solaris || illumos

package mdns

// reusePort does nothing: x/sys has no SO_REUSEPORT for Solaris, where SO_REUSEADDR is what
// shares a port among the sockets of a group.
func reusePort(int) error { return nil }
