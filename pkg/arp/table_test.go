package arp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// neighMessage builds an RTM_NEWNEIGH message, as the kernel sends it.
func neighMessage(family byte, index int32, state uint16, ip []byte, mac []byte) []byte {
	attr := func(kind uint16, value []byte) []byte {
		b := make([]byte, align(4+len(value)))
		binary.NativeEndian.PutUint16(b[0:2], uint16(4+len(value)))
		binary.NativeEndian.PutUint16(b[2:4], kind)
		copy(b[4:], value)
		return b
	}
	data := make([]byte, ndmsgLen)
	data[0] = family
	binary.NativeEndian.PutUint32(data[4:8], uint32(index))
	binary.NativeEndian.PutUint16(data[8:10], state)
	if ip != nil {
		data = append(data, attr(ndaDst, ip)...)
	}
	if mac != nil {
		data = append(data, attr(ndaLladdr, mac)...)
	}
	header := make([]byte, nlmsgHeaderLen)
	binary.NativeEndian.PutUint32(header[0:4], uint32(nlmsgHeaderLen+len(data)))
	binary.NativeEndian.PutUint16(header[4:6], rtmNewNeigh)
	return append(header, data...)
}

func TestParseNetlinkNeighbors(t *testing.T) {
	mac := []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55}
	var dump []byte
	dump = append(dump, neighMessage(afInet, 2, nudReachable, []byte{192, 168, 1, 10}, mac)...)
	dump = append(dump, neighMessage(afInet, 2, 0x04, []byte{192, 168, 1, 11}, mac)...)                 // stale
	dump = append(dump, neighMessage(afInet, 2, 0x20, []byte{192, 168, 1, 12}, nil)...)                 // failed
	dump = append(dump, neighMessage(afInet, 3, nudPermanent, []byte{10, 0, 0, 1}, mac)...)             // permanent
	dump = append(dump, neighMessage(afInet, 2, nudDelay, []byte{192, 168, 1, 13}, make([]byte, 6))...) // no MAC
	dump = append(dump, neighMessage(10, 2, nudReachable, net.ParseIP("2001:db8::1").To16(), mac)...)   // IPv6
	done := make([]byte, nlmsgHeaderLen)
	binary.NativeEndian.PutUint32(done[0:4], nlmsgHeaderLen)
	binary.NativeEndian.PutUint16(done[4:6], nlmsgDone)
	dump = append(dump, done...)

	got := parseNetlinkNeighbors(dump, func(index int) string { return map[int]string{2: "eth0", 3: "eth1"}[index] })
	if len(got) != 2 || got[0].IP.String() != "192.168.1.10" || got[0].Interface != "eth0" || got[0].MAC.String() != "00:11:22:33:44:55" || got[1].IP.String() != "10.0.0.1" || got[1].Interface != "eth1" {
		t.Errorf("got %v", got)
	}

	// Truncated or garbage input stops the parse, without a panic.
	for i := range dump {
		parseNetlinkNeighbors(dump[:i], nil)
	}
}

func TestSweepTargets(t *testing.T) {
	for local, want := range map[string]struct {
		count       int
		first, last string
	}{
		"192.168.1.10/24": {253, "192.168.1.1", "192.168.1.254"},
		"10.0.0.5/22":     {1021, "10.0.0.1", "10.0.3.254"},
		"10.0.0.5/16":     {253, "10.0.0.1", "10.0.0.254"}, // larger than a /22: its /24
		"10.0.0.0/31":     {1, "10.0.0.1", "10.0.0.1"},
		"10.0.0.1/32":     {0, "", ""},
	} {
		got := SweepTargets(netip.MustParsePrefix(local))
		if len(got) != want.count || len(got) > 0 && (got[0].String() != want.first || got[len(got)-1].String() != want.last) {
			t.Errorf("SweepTargets(%s): %d from %v to %v, want %d from %s to %s", local, len(got), first(got), last(got), want.count, want.first, want.last)
		}
	}
	if got := SweepTargets(netip.MustParsePrefix("2001:db8::1/64")); got != nil {
		t.Errorf("IPv6: %v", got)
	}
}

func first(a []netip.Addr) any {
	if len(a) == 0 {
		return nil
	}
	return a[0]
}

func last(a []netip.Addr) any {
	if len(a) == 0 {
		return nil
	}
	return a[len(a)-1]
}

func TestSweep(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	saved := sweepPort
	sweepPort = uint16(listener.LocalAddr().(*net.UDPAddr).Port)
	defer func() { sweepPort = saved }()

	loopback := netip.MustParseAddr("127.0.0.1")
	if err := Sweep(context.Background(), loopback, []netip.Addr{loopback, loopback}); err != nil {
		t.Fatal(err)
	}
	listener.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := range 2 {
		if _, _, err := listener.ReadFromUDP(make([]byte, 8)); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Sweep(ctx, loopback, []netip.Addr{loopback, loopback}); !errors.Is(err, context.Canceled) {
		t.Errorf("a done context: got %v", err)
	}
}

// The table of this machine reads, on the systems it can.
func TestTable(t *testing.T) {
	neighbors, err := Table()
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range neighbors {
		if !n.IP.Is4() || len(n.MAC) != 6 {
			t.Errorf("neighbor %v", n)
		}
	}
}

func TestPacket(t *testing.T) {
	sender := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	b := request(sender, netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"))
	if len(b) != packetLen || b[7] != opRequest || b[27] != 2 || b[17] != 1 {
		t.Fatalf("request: % x", b)
	}
	if _, _, ok := parseReply(b); ok {
		t.Error("a request read as a reply")
	}
	// The same packet, as the reply of 10.0.0.2 at its MAC.
	reply := append([]byte(nil), b...)
	reply[7] = opReply
	copy(reply[8:14], []byte{0x02, 0, 0, 0, 0, 2})
	copy(reply[14:18], []byte{10, 0, 0, 2})
	// Addressed to the asker.
	copy(reply[18:24], sender)
	copy(reply[24:28], []byte{10, 0, 0, 1})
	mac, ip, ok := parseReply(reply)
	if !ok || mac.String() != "02:00:00:00:00:02" || ip.String() != "10.0.0.2" {
		t.Errorf("reply: %s %s %v", mac, ip, ok)
	}
	// To the sender of the request, not to another host.
	if !repliesTo(reply, sender, netip.MustParseAddr("10.0.0.1")) {
		t.Error("the reply to the request not seen as one")
	}
	copy(reply[24:28], []byte{10, 0, 0, 9})
	if repliesTo(reply, sender, netip.MustParseAddr("10.0.0.1")) {
		t.Error("a reply to another address seen as ours")
	}
	if _, _, ok := parseReply(reply[:20]); ok {
		t.Error("a truncated reply read")
	}
}
