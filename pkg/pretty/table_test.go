package pretty

import (
	"slices"
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
      10.2.3.12                                    2m41s    3d 4h
          arp:answered on lan-ipv4              3h59m12s       2h10m
          reported by mikrotik-57 from leases    (lease)    3d 4h
      10.2.3.75                                    9m59s       9h 1m     (this host)
`
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", strings.ReplaceAll(got, " ", "·"), strings.ReplaceAll(want, " ", "·"))
	}
}

// The page is the same text, with the roles: of a line as given, of a row its label's, and Detail
// for its columns. What the text has is no markup: escaped as HTML, and of no role of its own.
func TestTablePage(t *testing.T) {
	var tb Table
	tb.Spans(As(Heading, "Hosts:"), Span{Text: " 1"})
	tb.Row("    <b>[[e|x]]", time.Minute, time.Hour, "").Label(Name)
	tb.Row("    10.2.3.75", 9*time.Minute, 9*time.Hour, "a&b")
	tb.RowText("    alone", "")
	page := tb.Page("  ")
	if got, want := page.String(), tb.Render("  "); got != want {
		t.Fatalf("the page as text:\n%s\nwant\n%s", got, want)
	}
	// Each line: its pieces' roles, and the text of the first, which of a row is its label.
	want := []struct {
		roles []Role
		first string
	}{
		{[]Role{Plain, Heading, Plain}, "  "},
		{[]Role{Name, Detail}, "      <b>[[e|x]]"},
		{[]Role{Plain, Detail}, "      10.2.3.75"},
		{[]Role{Plain}, "      alone"},
	}
	if len(page) != len(want) {
		t.Fatalf("got %d lines, want %d", len(page), len(want))
	}
	for i, w := range want {
		var roles []Role
		for _, s := range page[i] {
			roles = append(roles, s.Role)
		}
		if !slices.Equal(roles, w.roles) || page[i][0].Text != w.first {
			t.Errorf("line %d: %q with roles %v, want %q first and roles %v", i, page[i], roles, w.first, w.roles)
		}
	}
	html := page.HTML()
	for _, has := range []string{
		`  <span class="h">Hosts:</span> 1` + "\n",
		`<span class="n">      &lt;b&gt;[[e|x]]</span><span class="d">`,
		`a&amp;b</span>` + "\n",
		"      alone\n",
	} {
		if !strings.Contains(html, has) {
			t.Errorf("the HTML has no %q:\n%s", has, html)
		}
	}
	if strings.Contains(html, "<b>") {
		t.Errorf("a tag of the text is in the HTML:\n%s", html)
	}
}

func TestText(t *testing.T) {
	if got := Text("a\n\nb\n"); len(got) != 3 || got.String() != "a\n\nb\n" {
		t.Errorf("got %q", got)
	}
	if got := Text(""); len(got) != 0 {
		t.Errorf("no text: %q", got)
	}
}
