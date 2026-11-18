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
