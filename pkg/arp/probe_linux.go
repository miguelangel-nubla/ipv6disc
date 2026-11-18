//go:build linux

package arp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// probeSettle is how long the answers to a probe's last request have to come.
const probeSettle = 500 * time.Millisecond

// Probe asks mac, by ARP requests sent to it alone, for each of the targets, from local on iface,
// and returns those it answered for. Nothing is broadcast: the rest of the link sees nothing. It
// needs CAP_NET_RAW.
func Probe(ctx context.Context, iface *net.Interface, local netip.Addr, mac net.HardwareAddr, targets []netip.Addr) ([]netip.Addr, error) {
	if len(mac) != 6 || len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("probing %s on %s: not Ethernet", mac, iface.Name)
	}
	protocol := htons(unix.ETH_P_ARP)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(protocol))
	if err != nil {
		return nil, fmt.Errorf("opening an ARP socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: protocol, Ifindex: iface.Index}); err != nil {
		return nil, fmt.Errorf("binding the ARP socket to %s: %w", iface.Name, err)
	}
	// Reads wake up to see whether to stop.
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100_000}); err != nil {
		return nil, err
	}

	var mutex sync.Mutex
	found := make(map[netip.Addr]bool)
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		buf := make([]byte, 128)
		for {
			select {
			case <-done:
				return
			default:
			}
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				continue // the timeout, to look at done
			}
			sender, ip, ok := parseReply(buf[:n])
			if ok && bytes.Equal(sender, mac) {
				mutex.Lock()
				found[ip] = true
				mutex.Unlock()
			}
		}
	}()

	destination := &unix.SockaddrLinklayer{Protocol: protocol, Ifindex: iface.Index, Halen: 6}
	copy(destination.Addr[:], mac)
	ticker := time.NewTicker(sweepPace)
	defer ticker.Stop()
	var sendErr error
	for _, target := range targets {
		if err := unix.Sendto(fd, request(iface.HardwareAddr, local, target), 0, destination); err != nil {
			sendErr = fmt.Errorf("sending ARP to %s on %s: %w", mac, iface.Name, err)
			break
		}
		select {
		case <-ctx.Done():
			sendErr = ctx.Err()
		case <-ticker.C:
		}
		if sendErr != nil {
			break
		}
	}
	if sendErr == nil {
		select {
		case <-ctx.Done():
			sendErr = ctx.Err()
		case <-time.After(probeSettle):
		}
	}
	close(done)
	<-stopped

	mutex.Lock()
	defer mutex.Unlock()
	var result []netip.Addr
	for ip := range found {
		result = append(result, ip)
	}
	return result, sendErr
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
