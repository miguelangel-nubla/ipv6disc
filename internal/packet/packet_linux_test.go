//go:build linux

package packet

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/net/bpf"
)

// A packet socket hears the frames of its protocol that come in on its interface and that its
// filter takes, whose offsets are from the start of the payload, and those alone: once each, as
// they come in, not as this machine sent them, over the loopback where it does both. And Close
// ends a read that waits. It needs root.
func TestListen(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root, for a packet socket")
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip(err)
	}
	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	port := uint32(receiver.LocalAddr().(*net.UDPAddr).Port)
	// UDP over IPv4, to that port: after a header of the length the packet says.
	conn, err := Listen(lo, 0x0800, []bpf.Instruction{
		bpf.LoadAbsolute{Off: 9, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 17, SkipTrue: 4},
		bpf.LoadMemShift{Off: 0},
		bpf.LoadIndirect{Off: 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: port, SkipTrue: 1},
		bpf.RetConstant{Val: 0xffff},
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Join(lo, net.HardwareAddr{0x01, 0x80, 0xc2, 0, 0, 0x0e}); err != nil {
		t.Errorf("joining a group: %v", err)
	}

	type frame struct {
		payload  string
		outgoing bool
	}
	frames := make(chan frame, 8)
	ended := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, outgoing, err := conn.Read(buf)
			if err != nil {
				ended <- err
				return
			}
			// After the IPv4 and the UDP headers.
			frames <- frame{string(buf[28:n]), outgoing}
		}
	}()
	sender, err := net.Dial("udp4", receiver.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	// One to another port first, which the filter leaves.
	other, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	stray, err := net.Dial("udp4", other.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	stray.Write([]byte("to another port"))
	stray.Close()
	if _, err := sender.Write([]byte("to the port")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-frames:
		if got.payload != "to the port" || got.outgoing {
			t.Errorf("heard %+v, want the packet to the port, as it came in", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the packet was not heard")
	}
	time.Sleep(200 * time.Millisecond)
	if len(frames) != 0 {
		t.Errorf("heard %d frames more: %+v", len(frames), <-frames)
	}

	if err := conn.Close(); err != nil {
		t.Error(err)
	}
	select {
	case err := <-ended:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("the read ended with %v, want that the socket closed", err)
		}
		if _, _, _, err := conn.Read(make([]byte, 64)); !errors.Is(err, net.ErrClosed) {
			t.Errorf("a read after Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end the read that waited")
	}
}

// Run tells the frames that came in, not those this machine sent, and ends when the socket is
// closed, without an error told.
func TestRun(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root, for a packet socket")
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip(err)
	}
	receiver, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip(err)
	}
	defer receiver.Close()
	conn, err := Listen(lo, 0x86dd, nil)
	if err != nil {
		t.Fatal(err)
	}
	heard := make(chan int, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.Run(func(payload []byte, _ net.HardwareAddr) {
			if len(payload) == 40+8+len("a packet") && string(payload[48:]) == "a packet" {
				heard <- len(payload)
			}
		}, func(err error) { t.Errorf("an error told: %v", err) })
	}()
	sender, err := net.Dial("udp6", receiver.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	sender.Write([]byte("a packet"))
	select {
	case <-heard:
	case <-time.After(5 * time.Second):
		t.Fatal("the packet was not heard")
	}
	time.Sleep(200 * time.Millisecond)
	if len(heard) != 0 {
		t.Errorf("the packet was heard %d times more: as it left too", len(heard))
	}
	conn.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not end with the socket")
	}
}
