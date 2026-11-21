//go:build linux

package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Conn is a packet socket on an interface, of one protocol.
type Conn struct {
	file   *os.File
	raw    syscall.RawConn
	closed atomic.Bool
}

// Listen opens a packet socket for the frames of protocol, an EtherType, on iface, without their
// link-layer header: of those, only the ones filter takes, when there is one, whose offsets are
// from the start of the payload. It needs CAP_NET_RAW.
func Listen(iface *net.Interface, protocol uint16, filter []bpf.Instruction) (*Conn, error) {
	// Of no protocol until it is bound: nothing comes in before the filter is there.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("opening a packet socket: %w", err)
	}
	if len(filter) > 0 {
		raw, err := bpf.Assemble(filter)
		if err != nil {
			unix.Close(fd)
			return nil, err
		}
		program := make([]unix.SockFilter, len(raw))
		for i, r := range raw {
			program[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
		}
		if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(program)), Filter: (*unix.SockFilter)(unsafe.Pointer(&program[0]))}); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("attaching the filter: %w", err)
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(protocol), Ifindex: iface.Index}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("binding the packet socket to %s: %w", iface.Name, err)
	}
	// As a file the runtime waits for: closing it ends a read that waits.
	file := os.NewFile(uintptr(fd), "packet")
	raw, err := file.SyscallConn()
	if err != nil {
		file.Close()
		return nil, err
	}
	return &Conn{file: file, raw: raw}, nil
}

// Join has the interface take the frames sent to a group's MAC, as LLDP's, for as long as the
// Conn is open.
func (c *Conn) Join(iface *net.Interface, group net.HardwareAddr) error {
	mreq := unix.PacketMreq{Ifindex: int32(iface.Index), Type: unix.PACKET_MR_MULTICAST, Alen: uint16(len(group))}
	copy(mreq.Address[:], group)
	var sockErr error
	if err := c.raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptPacketMreq(int(fd), unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
	}); err != nil {
		return err
	}
	return sockErr
}

// Read reads a frame's payload into b: its length, the MAC it came from, and whether this
// machine sent it, which a socket of one protocol doesn't hear: only what comes in.
func (c *Conn) Read(b []byte) (n int, from net.HardwareAddr, outgoing bool, err error) {
	var sockErr error
	var address unix.Sockaddr
	if err := c.raw.Read(func(fd uintptr) bool {
		n, address, sockErr = unix.Recvfrom(int(fd), b, 0)
		return sockErr != unix.EAGAIN
	}); err != nil {
		// Whatever a read says of a socket that was closed under it, it is that it closed.
		if c.closed.Load() {
			return 0, nil, false, net.ErrClosed
		}
		return 0, nil, false, err
	}
	if sockErr != nil {
		if c.closed.Load() {
			return 0, nil, false, net.ErrClosed
		}
		return 0, nil, false, sockErr
	}
	if ll, ok := address.(*unix.SockaddrLinklayer); ok {
		outgoing = ll.Pkttype == unix.PACKET_OUTGOING
		if int(ll.Halen) <= len(ll.Addr) {
			from = net.HardwareAddr(append([]byte(nil), ll.Addr[:ll.Halen]...))
		}
	}
	return n, from, outgoing, nil
}

// Close ends the listening: a Read that waits returns net.ErrClosed, and so does every one after.
func (c *Conn) Close() error {
	c.closed.Store(true)
	return c.file.Close()
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
