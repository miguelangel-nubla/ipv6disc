package pretty

import (
	"strings"
	"testing"
	"time"
)

func TestUp(t *testing.T) {
	for d, want := range map[time.Duration]string{
		3*24*time.Hour + 4*time.Hour + 5*time.Minute: "  3d 4h      ",
		6*time.Hour + 20*time.Minute + 9*time.Second: "     6h20m   ",
		41*time.Minute + 30*time.Second:              "       41m30s",
		12 * 24 * time.Hour:                          " 12d         ",
		9*time.Hour + 1*time.Minute:                  "     9h 1m   ",
		58 * time.Second:                             "          58s",
		0:                                            "           0s",
		-time.Second:                                 "           0s",
	} {
		if got := Up(d); got != want {
			t.Errorf("Up(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestLeft(t *testing.T) {
	for _, c := range []struct {
		d           time.Duration
		days, hours bool
		want        string
	}{
		{2*time.Minute + 41*time.Second, false, true, "    2m41s"},
		{3*time.Hour + 59*time.Minute + 12*time.Second, false, true, " 3h59m12s"},
		{time.Minute + 3*time.Second, false, true, "    1m 3s"},
		{58 * time.Second, false, true, "      58s"},
		{58 * time.Second, false, false, "   58s"},
		{30 * time.Hour, false, true, "30h 0m 0s"},
		{30 * time.Hour, true, true, "  1d 6h 0m 0s"},
		{0, false, true, "  expired"},
		{time.Hour - time.Millisecond, false, true, " 1h 0m 0s"},
	} {
		if got := Left(c.d, c.days, c.hours); got != c.want {
			t.Errorf("Left(%s, %t, %t) = %q, want %q", c.d, c.days, c.hours, got, c.want)
		}
	}
}

// The rows line up: their labels padded to the widest, the units of their times under each other,
// a note in place of the time, a heading of no column between them.
func TestTable(t *testing.T) {
	var tb Table
	tb.Line("00:1b:21:bc:be:de")
	tb.Row("    10.2.3.12", 2*time.Minute+41*time.Second, 3*24*time.Hour+4*time.Hour, "")
	tb.Row("        arp:answered on lan-ipv4", 3*time.Hour+59*time.Minute+12*time.Second, 2*time.Hour+10*time.Minute, "")
	tb.RowNote("        reported by mikrotik-57 from leases", "(lease)", 3*24*time.Hour+4*time.Hour, "")
	tb.Row("    10.2.3.75", 9*time.Minute+59*time.Second, 9*time.Hour+time.Minute, "(this host)")
	got := tb.Render("  ")
	want := `  00:1b:21:bc:be:de
      10.2.3.12                                    2m41s  up   3d 4h
          arp:answered on lan-ipv4              3h59m12s  up      2h10m
          reported by mikrotik-57 from leases    (lease)  up   3d 4h
      10.2.3.75                                    9m59s  up      9h 1m     (this host)
`
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", strings.ReplaceAll(got, " ", "·"), strings.ReplaceAll(want, " ", "·"))
	}
}
