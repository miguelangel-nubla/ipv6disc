// Package reportpic draws the page of the discovery as a picture, for the pages that can't show
// its colors: the roles of a page given as text, and the SVG of a page.
package reportpic

import (
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"

	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// Roles gives the discovery of a page, as text, the roles the program gives it: a test holds it
// to what the program writes.
func Roles(text string) pretty.Page {
	var page pretty.Page
	group := ""
	for line := range strings.SplitSeq(strings.TrimSuffix(text, "\n"), "\n") {
		body := strings.TrimLeft(line, " ")
		indent := len(line) - len(body)
		switch {
		case strings.HasPrefix(line, "Discovery:"):
			page.Add(pretty.As(pretty.Heading, "Discovery:"), pretty.Span{Text: strings.TrimPrefix(line, "Discovery:")})
		case indent == 8 && strings.HasSuffix(body, ":"):
			group = body
			page.Add(pretty.As(pretty.Detail, line))
		case indent == 12 && group == "names:":
			page = append(page, row(line, pretty.Name))
		case indent == 12:
			page = append(page, row(line, pretty.Plain))
		case indent > 12:
			page.Add(pretty.As(pretty.Detail, line))
		default:
			page.Add(pretty.Span{Text: line})
		}
	}
	return page
}

// row is a row of a table: its label, up to the columns, with its role, and the rest a detail.
func row(line string, label pretty.Role) pretty.Line {
	body := strings.TrimLeft(line, " ")
	cut := len(line)
	if i := strings.Index(body, "  "); i >= 0 {
		cut = len(line) - len(body) + i
	}
	out := pretty.Line{{Text: line[:cut], Role: label}}
	if cut < len(line) {
		out = append(out, pretty.As(pretty.Detail, line[cut:]))
	}
	return out
}

// Theme is the colors of a picture: on a light or a dark ground.
type Theme struct {
	Ground, Border, Text string
	Roles                map[pretty.Role]string
}

var (
	Light = Theme{"#ffffff", "#d0d7de", "#1d2530", map[pretty.Role]string{
		pretty.Heading: "#1d2530", pretty.Name: "#0f3a8a", pretty.OK: "#1d7a3e", pretty.Warn: "#8a5200", pretty.Error: "#c0262d", pretty.Detail: "#5d6877"}}
	Dark = Theme{"#12161c", "#30363d", "#dde3ea", map[pretty.Role]string{
		pretty.Heading: "#f1f4f8", pretty.Name: "#9cc0ff", pretty.OK: "#5fcf83", pretty.Warn: "#e7b04f", pretty.Error: "#ff7b7b", pretty.Detail: "#8c97a6"}}
)

// The size of the letters, of a monospaced font: each piece of text is given its width, so the
// columns line up whatever font the reader has.
const (
	size    = 13.0
	advance = 7.8
	leading = 19.0
	padX    = 16.0
	padY    = 14.0
)

var gap = regexp.MustCompile(` {2,}`)

// SVG is the page as a picture, in the colors of theme. A piece of text is placed at its column:
// the spaces between the columns are left out, as SVG would join them.
func SVG(page pretty.Page, theme Theme) string {
	cols := 0
	for _, line := range page {
		cols = max(cols, len([]rune(line.String())))
	}
	width, height := float64(cols)*advance+2*padX, float64(len(page))*leading+2*padY
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %s %s" width="%s" height="%s" role="img" aria-label="The page of ipv6disc, with its colors">`+"\n", num(width), num(height), num(width), num(height))
	fmt.Fprintf(&b, `<rect x="0.5" y="0.5" width="%s" height="%s" rx="6" fill="%s" stroke="%s"/>`+"\n", num(width-1), num(height-1), theme.Ground, theme.Border)
	fmt.Fprintf(&b, `<g font-family="ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'DejaVu Sans Mono', monospace" font-size="%s" fill="%s">`+"\n", num(size), theme.Text)
	for i, line := range page {
		y := padY + float64(i)*leading + 14
		col := 0
		for _, span := range line {
			text := []rune(span.Text)
			at := 0
			for _, piece := range pieces(string(text)) {
				at = piece.at
				attrs := ""
				if fill, ok := theme.Roles[span.Role]; ok {
					attrs += ` fill="` + fill + `"`
				}
				if span.Role == pretty.Heading || span.Role == pretty.Error {
					attrs += ` font-weight="600"`
				}
				n := len([]rune(piece.text))
				fmt.Fprintf(&b, `<text x="%s" y="%s" textLength="%s" lengthAdjust="spacingAndGlyphs"%s>%s</text>`+"\n",
					num(padX+float64(col+at)*advance), num(y), num(float64(n)*advance), attrs, html.EscapeString(piece.text))
			}
			col += len(text)
		}
	}
	b.WriteString("</g>\n</svg>\n")
	return b.String()
}

type piece struct {
	at   int
	text string
}

// pieces are the runs of text of s that two spaces or more set apart, each with its column.
func pieces(s string) []piece {
	var out []piece
	at := 0
	for _, part := range gapSplit(s) {
		if strings.TrimSpace(part.text) != "" {
			lead := len(part.text) - len(strings.TrimLeft(part.text, " "))
			out = append(out, piece{at + part.at + lead, strings.TrimSpace(part.text)})
		}
	}
	return out
}

func gapSplit(s string) []piece {
	var out []piece
	last := 0
	for _, loc := range gap.FindAllStringIndex(s, -1) {
		out = append(out, piece{len([]rune(s[:last])), s[last:loc[0]]})
		last = loc[1]
	}
	return append(out, piece{len([]rune(s[:last])), s[last:]})
}

func num(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}
