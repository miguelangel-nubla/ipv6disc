package ipv6disc

import (
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// A cause is what a protocol saw of an address whose MAC the discovery doesn't know yet: the
// record it is, once the MAC is known, as the solicitation it led to is answered. Of a message
// that tells whose it is, as a DHCP request's client MAC, it is that MAC's alone.
type cause struct {
	protocol string
	way      Way
	mac      net.HardwareAddr
	at       time.Time
}

type causeKey struct {
	iface string
	addr  netip.Addr
}

// causeWait is how long a cause waits for its address's MAC, causesMost how many addresses have
// causes waiting at once, and causesEach how many wait for one address: the solicitation of the
// discovery is answered in a second, and what never is goes. An address has a cause for each
// protocol and way, and for each MAC a message said it is at: messages made up, each with another
// MAC, fill no more than that.
const (
	causeWait  = 10 * time.Second
	causesMost = 1024
	causesEach = 32
)

// causes are the causes that wait, by interface and address.
type causes struct {
	mutex   sync.Mutex
	waiting map[causeKey][]cause
}

// add keeps a cause for addr on iface, as a record to be when its MAC is known. A cause there
// already is seen again.
func (c *causes) add(iface string, addr netip.Addr, protocol string, way Way, mac net.HardwareAddr, now time.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.waiting == nil {
		c.waiting = make(map[causeKey][]cause)
	}
	key := causeKey{iface, addr.WithZone("").Unmap()}
	// Those of the address that waited too long go first: of one whose MAC never comes, nothing
	// else takes them out.
	list := slices.DeleteFunc(c.waiting[key], func(k cause) bool { return now.Sub(k.at) > causeWait })
	if len(list) == 0 {
		delete(c.waiting, key)
	} else {
		c.waiting[key] = list
	}
	for i, old := range list {
		if old.protocol == protocol && old.way == way && macEqual(old.mac, mac) {
			list[i].at = now
			return
		}
	}
	if len(list) >= causesEach {
		return
	}
	if len(list) == 0 && len(c.waiting) >= causesMost {
		c.expire(now)
		if len(c.waiting) >= causesMost {
			return
		}
	}
	c.waiting[key] = append(list, cause{protocol: protocol, way: way, mac: mac, at: now})
}

// take returns the causes of addr on iface that hw has, and are still waiting: they are records of
// it now. Those of another MAC wait on.
func (c *causes) take(iface string, addr netip.Addr, hw net.HardwareAddr, now time.Time) []cause {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	key := causeKey{iface, addr.WithZone("").Unmap()}
	var taken, kept []cause
	for _, k := range c.waiting[key] {
		switch {
		case now.Sub(k.at) > causeWait:
		case k.mac == nil || macEqual(k.mac, hw):
			taken = append(taken, k)
		default:
			kept = append(kept, k)
		}
	}
	if len(kept) == 0 {
		delete(c.waiting, key)
	} else {
		c.waiting[key] = kept
	}
	return taken
}

// expire drops the causes that waited too long, with the mutex held.
func (c *causes) expire(now time.Time) {
	for key, list := range c.waiting {
		list = slices.DeleteFunc(list, func(k cause) bool { return now.Sub(k.at) > causeWait })
		if len(list) == 0 {
			delete(c.waiting, key)
		} else {
			c.waiting[key] = list
		}
	}
}

func macEqual(a, b net.HardwareAddr) bool {
	return a.String() == b.String()
}

// saw records what a protocol saw of addr on iface: at once, of an address the State has; or, of
// one whose MAC isn't known yet, when the discovery finds it. With mac, it is of that MAC alone: of
// an address the State has at another, nothing.
func (w *Worker) saw(iface string, addr netip.Addr, protocol string, way Way, mac net.HardwareAddr) {
	addr = addr.WithZone("").Unmap()
	if known, ok := w.State.macOf(addr, iface); ok {
		if mac == nil || macEqual(known, mac) {
			w.State.registerLocal(known, addr, Record{Protocol: protocol, Way: way, On: iface}, w.config.Lifetime, nil)
		}
		return
	}
	w.causes.add(iface, addr, protocol, way, mac, time.Now())
}

// registerFound is registerLocal for what the discovery found on iface, r, with the causes that
// waited for it: the records of what saw the address before its MAC was known.
func (w *Worker) registerFound(hw net.HardwareAddr, ip netip.Addr, r Record, onExpiration func(*Addr, AddrExpirationRemainingEvents)) (*Addr, bool) {
	addr, existing := w.State.registerLocal(hw, ip, r, w.config.Lifetime, onExpiration)
	if addr == nil {
		return addr, existing
	}
	for _, k := range w.causes.take(r.On, ip, hw, time.Now()) {
		w.State.registerLocal(hw, ip, Record{Protocol: k.protocol, Way: k.way, On: r.On}, w.config.Lifetime, onExpiration)
	}
	return addr, existing
}

// announcedBy records what a host at from said, on iface, is its address addr: of the address it
// sent from, as any; of another, only once the State has both at one MAC, as a record a host sends
// of another, a proxy's, is no announcement of its own.
func (w *Worker) announcedBy(iface string, from, addr netip.Addr, protocol string) {
	from, addr = from.WithZone("").Unmap(), addr.WithZone("").Unmap()
	if addr == from {
		w.saw(iface, addr, protocol, Announced, nil)
		return
	}
	sender, ok := w.State.macOf(from, iface)
	if !ok {
		return
	}
	w.saw(iface, addr, protocol, Announced, sender)
}
