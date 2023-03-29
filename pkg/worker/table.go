package worker

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

type IPAddressInfo struct {
	Address          netip.Addr
	Hw               net.HardwareAddr
	mutex            sync.RWMutex
	timer            *time.Timer
	timerExpiration  time.Time
	timerPreventive1 *time.Timer
	timerPreventive2 *time.Timer
	timerPreventive3 *time.Timer
	stopChannel      chan bool
	onExpiration     func(*IPAddressInfo, int)
}

type IPAddressSet struct {
	addresses         map[netip.Addr]*IPAddressInfo
	addressesMapMutex sync.RWMutex
}

type Table struct {
	macs         map[string]*IPAddressSet
	macsMapMutex sync.RWMutex
}

func (i *IPAddressInfo) IsStillValid() bool {
	return i.timerExpiration.After(time.Now())
}

func (i *IPAddressInfo) Extend(ttl time.Duration) {
	i.mutex.Lock()
	i.timerExpiration = time.Now().Add(ttl)
	i.timer.Reset(ttl)
	i.timerPreventive1.Reset(ttl / 3 * 2)
	i.timerPreventive2.Reset(ttl / 4 * 3)
	i.timerPreventive3.Reset(ttl / 5 * 4)
	i.mutex.Unlock()
}

func (i *IPAddressInfo) GetExpiration() time.Time {
	i.mutex.RLock()
	expiration := i.timerExpiration
	i.mutex.RUnlock()
	return expiration
}

func (i *IPAddressInfo) GetAddress() netip.Addr {
	return i.Address
}

func (i *IPAddressInfo) Clear() {
	i.mutex.Lock()
	i.timerExpiration = time.Now()
	i.timer.Stop()
	i.timerPreventive1.Stop()
	i.timerPreventive2.Stop()
	i.timerPreventive3.Stop()
	close(i.stopChannel)
	i.mutex.Unlock()
}

func NewIPAddressInfo(hw net.HardwareAddr, addr netip.Addr, ttl time.Duration, onExpiration func(*IPAddressInfo, int)) *IPAddressInfo {
	info := &IPAddressInfo{
		onExpiration:     onExpiration,
		Address:          addr,
		Hw:               hw,
		timer:            time.NewTimer(ttl),
		timerExpiration:  time.Now().Add(ttl),
		timerPreventive1: time.NewTimer(ttl / 3 * 2),
		timerPreventive2: time.NewTimer(ttl / 4 * 3),
		timerPreventive3: time.NewTimer(ttl / 5 * 4),
		stopChannel:      make(chan bool),
	}

	go func() {
		for {
			select {
			case <-info.timer.C:
				info.onExpiration(info, 0)
				return
			case <-info.timerPreventive1.C:
				info.onExpiration(info, 1)
			case <-info.timerPreventive2.C:
				info.onExpiration(info, 2)
			case <-info.timerPreventive3.C:
				info.onExpiration(info, 3)
			case <-info.stopChannel:
				return
			}
		}
	}()

	return info
}

// Add an IPv6 address to the set with a TTL (in seconds).
func (s *IPAddressSet) Add(hw net.HardwareAddr, addr netip.Addr, ttl time.Duration, onExpiration func(*IPAddressInfo, int)) bool {
	existing := false
	if !s.Contains(addr) {
		s.addressesMapMutex.Lock()
		s.addresses[addr] = NewIPAddressInfo(hw, addr, ttl, onExpiration)
		s.addressesMapMutex.Unlock()
	} else {
		if (s.addresses[addr]).IsStillValid() {
			existing = true
		}
		(s.addresses[addr]).Extend(ttl)
		(s.addresses[addr]).onExpiration = onExpiration
	}
	return existing
}

// Remove an IPv6 address from the set.
func (s *IPAddressSet) Remove(addr netip.Addr) {
	if s.Contains(addr) {
		(s.addresses[addr]).Clear()

		s.addressesMapMutex.Lock()
		delete(s.addresses, addr)
		s.addressesMapMutex.Unlock()
	}
}

// Check if an IPv6 address exists in the set and is not expired.
func (s *IPAddressSet) Contains(addr netip.Addr) bool {
	s.addressesMapMutex.RLock()
	info, ok := s.addresses[addr]
	s.addressesMapMutex.RUnlock()
	if !ok {
		return false
	}
	return time.Now().Before(info.GetExpiration())
}

func (s *IPAddressSet) PrettyPrint(tabSize int) string {
	indent := func(level int) string {
		return strings.Repeat(" ", level*tabSize)
	}

	var result strings.Builder
	s.addressesMapMutex.RLock()

	// Get the keys from the map
	keys := make([]netip.Addr, 0, len(s.addresses))
	for k := range s.addresses {
		keys = append(keys, k)
	}

	// Sort the keys
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Less(keys[j])
	})

	// Iterate ordered
	for _, key := range keys {
		ipAddressInfo := s.addresses[key]
		fmt.Fprintf(&result, indent(2)+"%s %.0f\n", ipAddressInfo.Address.String(), time.Until(ipAddressInfo.GetExpiration()).Seconds())
	}
	s.addressesMapMutex.RUnlock()

	return result.String()
}

func NewIPAddressSet() *IPAddressSet {
	return &IPAddressSet{addresses: make(map[netip.Addr]*IPAddressInfo)}
}

// Add  macs address to the set with a TTL (in seconds).
func (t *Table) Add(hw net.HardwareAddr, addr netip.Addr, ttl time.Duration, onExpiration func(*IPAddressInfo, int)) bool {
	mac := hw.String()
	if !t.Contains(hw) {
		t.macsMapMutex.Lock()
		t.macs[mac] = NewIPAddressSet()
		t.macsMapMutex.Unlock()
	}
	return (t.macs[mac]).Add(hw, addr, ttl, onExpiration)
}

// Remove an MACs address from the set.
func (t *Table) Remove(hw net.HardwareAddr) {
	mac := hw.String()
	t.macsMapMutex.Lock()
	delete(t.macs, mac)
	t.macsMapMutex.Unlock()
}

// Check if an MAC address exists in the set and is not expired.
func (t *Table) Contains(hw net.HardwareAddr) bool {
	mac := hw.String()
	t.macsMapMutex.RLock()
	_, ok := t.macs[mac]
	t.macsMapMutex.RUnlock()
	return ok
}

func (t *Table) Filter(hws []net.HardwareAddr, prefixes []netip.Prefix) []*IPAddressInfo {
	found := []*IPAddressInfo{}
	for _, prefix := range prefixes {
		for _, hw := range hws {
			mac := hw.String()
			t.macsMapMutex.RLock()
			if t.Contains(hw) {
				for _, ipAddressInfo := range t.macs[mac].addresses {
					// Remove zone identifier from netip.Addr, zones strip prefixes
					test := netip.AddrFrom16(ipAddressInfo.Address.As16())
					if prefix.Contains(test) {
						found = append(found, ipAddressInfo)
					}
				}
			}
			t.macsMapMutex.RUnlock()
		}
	}

	return found
}

func (t *Table) PrettyPrint(tabSize int) string {
	indent := func(level int) string {
		return strings.Repeat(" ", level*tabSize)
	}
	var result strings.Builder

	result.WriteString("Table:\n")

	t.macsMapMutex.RLock()

	// Get the keys from the map
	keys := make([]string, 0, len(t.macs))
	for k := range t.macs {
		keys = append(keys, k)
	}

	// Sort the keys
	sort.Strings(keys)

	// Iterate ordered
	for _, key := range keys {
		fmt.Fprintf(&result, indent(1)+"%s:\n", key)
		result.WriteString(t.macs[key].PrettyPrint(tabSize))
	}

	t.macsMapMutex.RUnlock()

	return result.String()
}

func NewTable() *Table {
	return &Table{macs: make(map[string]*IPAddressSet)}
}
