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

// What isn't a host of the table: by its state, its addresses, or the kind of message.
func TestParseNetlinkNeighborsLeftOut(t *testing.T) {
	mac := []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55}
	ip := []byte{192, 168, 1, 10}
	message := func(kind uint16, data []byte) []byte {
		header := make([]byte, nlmsgHeaderLen)
		binary.NativeEndian.PutUint32(header[0:4], uint32(nlmsgHeaderLen+len(data)))
		binary.NativeEndian.PutUint16(header[4:6], kind)
		return append(header, data...)
	}
	for name, b := range map[string][]byte{
		"incomplete":             neighMessage(afInet, 2, 0x01, ip, nil),
		"incomplete with a MAC":  neighMessage(afInet, 2, 0x01, ip, mac),
		"stale":                  neighMessage(afInet, 2, 0x04, ip, mac),
		"failed":                 neighMessage(afInet, 2, 0x20, ip, mac),
		"noarp":                  neighMessage(afInet, 2, 0x40, ip, mac),
		"noarp multicast group":  neighMessage(afInet, 2, 0x40, []byte{224, 0, 0, 251}, []byte{0x01, 0, 0x5e, 0, 0, 0xfb}),
		"no state":               neighMessage(afInet, 2, 0, ip, mac),
		"permanent multicast":    neighMessage(afInet, 2, nudPermanent, []byte{224, 0, 0, 251}, []byte{0x01, 0, 0x5e, 0, 0, 0xfb}),
		"permanent broadcast":    neighMessage(afInet, 2, nudPermanent, []byte{192, 168, 1, 255}, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		"limited broadcast":      neighMessage(afInet, 2, nudReachable, []byte{255, 255, 255, 255}, mac),
		"unspecified":            neighMessage(afInet, 2, nudReachable, []byte{0, 0, 0, 0}, mac),
		"an Infiniband address":  neighMessage(afInet, 2, nudReachable, ip, make([]byte, 20)),
		"a tunnel's address":     neighMessage(afInet, 2, nudReachable, ip, []byte{10, 0, 0, 1}),
		"no address":             neighMessage(afInet, 2, nudReachable, nil, mac),
		"an IPv6 address in ARP": neighMessage(afInet, 2, nudReachable, net.ParseIP("2001:db8::1").To16(), mac),
		// NLMSG_ERROR, 2, with its errno: the dump ends without neighbors.
		"an error": message(2, make([]byte, 20)),
		// RTM_DELNEIGH, 29: of a table's changes, not of a dump.
		"a deletion": func() []byte {
			b := neighMessage(afInet, 2, nudReachable, ip, mac)
			binary.NativeEndian.PutUint16(b[4:6], 29)
			return b
		}(),
	} {
		if got := parseNetlinkNeighbors(b, nil); len(got) != 0 {
			t.Errorf("%s: got %v", name, got)
		}
	}

	// Every state that counts, alone and with others, as the kernel never gives them but could.
	for _, state := range []uint16{nudReachable, nudDelay, nudProbe, nudPermanent, nudReachable | 0x04} {
		if got := parseNetlinkNeighbors(neighMessage(afInet, 2, state, ip, mac), nil); len(got) != 1 || got[0].Interface != "" {
			t.Errorf("state %#x: got %v", state, got)
		}
	}

	// The messages after an error, or after one that isn't a neighbor, are read: a dump is whatever
	// the kernel wrote until its end.
	good := neighMessage(afInet, 2, nudReachable, ip, mac)
	if got := parseNetlinkNeighbors(append(message(2, make([]byte, 20)), good...), nil); len(got) != 1 {
		t.Errorf("after an error: got %v", got)
	}
	// Nothing is read after the end of the dump.
	if got := parseNetlinkNeighbors(append(message(nlmsgDone, nil), good...), nil); len(got) != 0 {
		t.Errorf("after the end: got %v", got)
	}
	// A last message whose length isn't of 4 bytes, without its padding: read, and the parse ends.
	odd := message(rtmNewNeigh, append(neighMessage(afInet, 2, nudReachable, ip, mac)[nlmsgHeaderLen:], 0, 0, 0)[:ndmsgLen+8+10+1])
	if got := parseNetlinkNeighbors(odd, nil); len(got) != 1 {
		t.Errorf("an unpadded last message: got %v", got)
	}
	if got := parseNetlinkNeighbors(append(odd, 0, 0, 0), nil); len(got) != 1 {
		t.Errorf("a padded last message: got %v", got)
	}
	// A negative interface index, as the s32 it is.
	var index int
	parseNetlinkNeighbors(neighMessage(afInet, -1, nudReachable, ip, mac), func(i int) string { index = i; return "" })
	if index != -1 {
		t.Errorf("index %d, want -1", index)
	}
}

func TestProbeAddrs(t *testing.T) {
	a := netip.MustParseAddr
	for _, local := range []netip.Addr{{}, a("2001:db8::1"), a("fe80::1%eth0")} {
		if _, _, err := probeAddrs(local, []netip.Addr{a("10.0.0.2")}); err == nil {
			t.Errorf("local %v: want an error", local)
		}
	}
	local, targets, err := probeAddrs(a("::ffff:10.0.0.1"), []netip.Addr{a("10.0.0.2"), a("2001:db8::2"), {}, a("::ffff:10.0.0.3")})
	if err != nil || local != a("10.0.0.1") || len(targets) != 2 || targets[0] != a("10.0.0.2") || targets[1] != a("10.0.0.3") {
		t.Errorf("got %v, %v, %v", local, targets, err)
	}
	// What it returns is what request takes, and what a reply's addresses equal.
	request(net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, local, targets[1])
	if _, targets, err := probeAddrs(a("10.0.0.1"), nil); err != nil || len(targets) != 0 {
		t.Errorf("no targets: %v, %v", targets, err)
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
		"10.0.0.1/31":     {1, "10.0.0.0", "10.0.0.0"},
		"10.0.0.5/0":      {253, "10.0.0.1", "10.0.0.254"},
		// The ends of the address space: the last address has no next one.
		"255.255.255.250/0":  {253, "255.255.255.1", "255.255.255.254"},
		"255.255.255.254/24": {253, "255.255.255.1", "255.255.255.253"},
		"255.255.255.255/32": {0, "", ""},
		"0.0.0.1/24":         {253, "0.0.0.2", "0.0.0.254"},
	} {
		got := SweepTargets(netip.MustParsePrefix(local))
		if len(got) != want.count || len(got) > 0 && (got[0].String() != want.first || got[len(got)-1].String() != want.last) {
			t.Errorf("SweepTargets(%s): %d from %v to %v, want %d from %s to %s", local, len(got), first(got), last(got), want.count, want.first, want.last)
		}
	}
	for _, local := range []string{"2001:db8::1/64", "::ffff:10.0.0.5/120"} {
		if got := SweepTargets(netip.MustParsePrefix(local)); got != nil {
			t.Errorf("%s, not IPv4: %v", local, got)
		}
	}
	if got := SweepTargets(netip.Prefix{}); got != nil {
		t.Errorf("no prefix: %v", got)
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
	// To another MAC, as the answer to another host's request the socket would hear.
	copy(reply[24:28], []byte{10, 0, 0, 1})
	if repliesTo(reply, net.HardwareAddr{0x02, 0, 0, 0, 0, 9}, netip.MustParseAddr("10.0.0.1")) {
		t.Error("a reply to another MAC seen as ours")
	}
	// A gratuitous reply: to everyone, of the sender's own address.
	gratuitous := append([]byte(nil), reply...)
	copy(gratuitous[18:24], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(gratuitous[24:28], []byte{10, 0, 0, 2})
	if repliesTo(gratuitous, sender, netip.MustParseAddr("10.0.0.1")) {
		t.Error("a gratuitous reply seen as ours")
	}
	if repliesTo(reply[:20], sender, netip.MustParseAddr("10.0.0.1")) {
		t.Error("a truncated reply seen as ours")
	}
	if _, _, ok := parseReply(reply[:20]); ok {
		t.Error("a truncated reply read")
	}
	// Not Ethernet, or not IPv4: not read.
	for _, at := range []int{1, 3, 4, 5} {
		other := append([]byte(nil), reply...)
		other[at]++
		if _, _, ok := parseReply(other); ok {
			t.Errorf("a reply with byte %d changed read", at)
		}
	}
}
