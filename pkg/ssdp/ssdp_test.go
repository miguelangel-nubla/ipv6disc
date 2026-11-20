package ssdp

import (
	"net/netip"
	"testing"
)

func TestSearchMessage(t *testing.T) {
	got := string(searchMessage(netip.MustParseAddr("ff02::c")))
	want := "M-SEARCH * HTTP/1.1\r\nHOST: [ff02::c]:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A zone names the link on this machine only: it isn't of the Host header.
func TestSearchMessageWithoutZone(t *testing.T) {
	got := string(searchMessage(netip.MustParseAddr("fe80::1%eth0")))
	want := "M-SEARCH * HTTP/1.1\r\nHOST: [fe80::1]:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMulticastAddress(t *testing.T) {
	if ssdpMulticastAddress != netip.MustParseAddr("ff02::c") || !ssdpMulticastAddress.IsLinkLocalMulticast() || ssdpPort != 1900 {
		t.Errorf("SSDP goes to %s port %d", ssdpMulticastAddress, ssdpPort)
	}
}
