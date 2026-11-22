package ipv6disc

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/internal/reportpic"
	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// The picture of the page in the README has the roles reportpic.Roles reads from its text: they
// are the roles the program gives, of every kind of line of the discovery.
func TestPagePictureHasTheRolesOfTheProgram(t *testing.T) {
	state := NewState()
	t.Cleanup(state.Close)
	state.SetFamilies(true, true)
	state.SetNames(true, time.Hour)
	named, _ := net.ParseMAC("00:11:22:33:44:55")
	other, _ := net.ParseMAC("66:77:88:99:aa:bb")
	state.Register(named, netip.MustParseAddr("2001:db8::a"), "eth0", time.Hour, nil)
	state.Report(named, netip.MustParseAddr("192.0.2.10"), "router", "mikrotik", "leases", time.Hour, nil)
	state.RegisterName(named, "nas", "mdns on eth0", time.Hour)
	state.ReportName(named, "nas", "router", "leases", time.Hour)
	state.Register(other, netip.MustParseAddr("2001:db8::b"), "eth0", time.Hour, nil)

	page := state.Page("")
	text := page.String()
	for _, has := range []string{"Discovery: 2 hosts, 1 named, 3 addresses\n", "        names:\n", "            nas ", "        addresses:\n", "reported by router from leases"} {
		if !strings.Contains(text, has) {
			t.Fatalf("the page of the test has no %q:\n%s", has, text)
		}
	}
	got := reportpic.Roles(text)
	if len(got) != len(page) {
		t.Fatalf("%d lines, of %d", len(got), len(page))
	}
	roles := func(line pretty.Line) string {
		var b strings.Builder
		for _, span := range line {
			for _, r := range span.Text {
				if r == ' ' {
					b.WriteByte(' ')
				} else {
					b.WriteByte('0' + byte(span.Role))
				}
			}
		}
		return b.String()
	}
	for i := range page {
		if want, have := roles(page[i]), roles(got[i]); want != have {
			t.Errorf("the roles of %q:\n%s the program's\n%s the picture's", page[i].String(), want, have)
		}
	}
}
