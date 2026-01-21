package plugins

import "net"

// FormatAddress ensures the address has a port, adding defaultPort if missing.
// It handles IPv6 literals correctly.
func FormatAddress(addr, defaultPort string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Assume the whole string is the host if SplitHostPort fails
		// (e.g. missing port, or too many colons like in a bare IPv6 address)
		host = addr
		port = defaultPort

		// If the host is already enclosed in brackets (e.g. [::1]), strip them
		// because net.JoinHostPort will add them back if needed.
		if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
			host = host[1 : len(host)-1]
		}
	}
	return net.JoinHostPort(host, port)
}
