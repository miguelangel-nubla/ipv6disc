package pretty

import (
	"html"
	"strings"
)

// Role is what a piece of the page is, for whatever shows it to tell it apart: by a color in a
// terminal or on a web page, by nothing as text. The words say it all the same: no role is the
// only thing that tells a state.
type Role uint8

const (
	// Plain is the text of no role: values, as addresses and keys.
	Plain Role = iota
	// Heading is the title of a section, or of a group in it.
	Heading
	// Name is what the page is about: a host name.
	Name
	// OK is a state that works.
	OK
	// Warn is a state that waits, or lacks something.
	Warn
	// Error is a state that needs a look.
	Error
	// Detail is what steps back: times, sources, counters.
	Detail
)

// Span is a piece of a line, all of one role. Its text is taken as it is, whatever it has:
// nothing in it is markup, so a name or an error from elsewhere can't give itself a role.
type Span struct {
	Text string
	Role Role
}

// Line is a line of the page, without its end.
type Line []Span

// Page is the lines of a page.
type Page []Line

// As is text with a role.
func As(role Role, text string) Span {
	return Span{Text: text, Role: role}
}

// Text is text as it is: lines of no role, one for each that text has.
func Text(text string) Page {
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return nil
	}
	var page Page
	for l := range strings.SplitSeq(text, "\n") {
		page = append(page, Line{{Text: l}})
	}
	return page
}

// Add adds a line of spans to the page.
func (p *Page) Add(spans ...Span) {
	*p = append(*p, Line(spans))
}

// String is the line as text.
func (l Line) String() string {
	var b strings.Builder
	for _, s := range l {
		b.WriteString(s.Text)
	}
	return b.String()
}

// String is the page as text, each line ended.
func (p Page) String() string {
	var b strings.Builder
	for _, l := range p {
		for _, s := range l {
			b.WriteString(s.Text)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// Class is the role's name as HTML shows it, in the class of a span: none for Plain.
func (r Role) Class() string {
	switch r {
	case Heading:
		return "h"
	case Name:
		return "n"
	case OK:
		return "ok"
	case Warn:
		return "w"
	case Error:
		return "e"
	case Detail:
		return "d"
	}
	return ""
}

// HTML is the page as the content of a pre element: the text escaped, and each piece with a role
// in a span of its class.
func (p Page) HTML() string {
	var b strings.Builder
	for _, l := range p {
		for _, s := range l {
			class := s.Role.Class()
			if class == "" || s.Text == "" {
				b.WriteString(html.EscapeString(s.Text))
				continue
			}
			b.WriteString(`<span class="` + class + `">` + html.EscapeString(s.Text) + `</span>`)
		}
		b.WriteByte('\n')
	}
	return b.String()
}
