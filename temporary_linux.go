//go:build linux

package ipv6disc

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// ifaFlagTemporary is IFA_F_TEMPORARY: a privacy address (RFC 8981).
const ifaFlagTemporary = 0x01

// temporaryAddrs returns this machine's IPv6 addresses the kernel says are temporary, from
// /proc/net/if_inet6: one line per address, its 32 hex digits, the interface's index, the prefix
// length, the scope and the flags, in hex, and the interface's name.
func temporaryAddrs() map[netip.Addr]bool {
	f, err := os.Open("/proc/net/if_inet6")
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseIfInet6(bufio.NewScanner(f))
}

func parseIfInet6(lines *bufio.Scanner) map[netip.Addr]bool {
	temporary := make(map[netip.Addr]bool)
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) < 6 {
			continue
		}
		raw, err := hex.DecodeString(fields[0])
		flags, ferr := strconv.ParseUint(fields[4], 16, 32)
		if err != nil || ferr != nil || len(raw) != 16 {
			continue
		}
		if flags&ifaFlagTemporary != 0 {
			temporary[netip.AddrFrom16([16]byte(raw))] = true
		}
	}
	return temporary
}
