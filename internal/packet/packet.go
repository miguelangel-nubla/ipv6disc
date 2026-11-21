// Package packet hears the frames of one protocol on an interface, by a packet socket of Linux:
// what no bound port tells, as the DHCP of the clients beside a server of this machine's that has
// the port, ARP, or LLDP. It only hears: nothing is ever sent. Elsewhere Listen says it can't.
package packet

import (
	"errors"
	"net"
	"os"

	"github.com/miguelangel-nubla/ipv6disc/internal/backoff"
)

// Run reads the frames that come in until the Conn is closed, which ends it without a call of
// onError: handle gets the payload of each, after its link-layer header, and the MAC it came
// from. A socket of one protocol hears what comes in, not what this machine sends: one it
// would hear of those is left out all the same. Any other error of a read is reported, and the
// next read tried, after a wait that grows while they fail.
func (c *Conn) Run(handle func(payload []byte, from net.HardwareAddr), onError func(error)) {
	buf := make([]byte, 2048)
	var retry backoff.Delay
	for {
		n, from, outgoing, err := c.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			if onError != nil {
				onError(err)
			}
			retry.Wait()
			continue
		}
		retry.Reset()
		if !outgoing {
			handle(buf[:n], from)
		}
	}
}
