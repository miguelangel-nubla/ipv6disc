// Package pretty lays out the page of a program on ipv6disc, as -live shows it: lines of a value,
// how long it has left, and how long it has been seen, each in its column, and the units of the
// durations under each other, days under days, hours under hours.
package pretty

import (
	"fmt"
	"strings"
	"time"
)

// Table is lines, some of them rows of columns: Render pads them to line up.
type Table struct {
	lines []line
}

type line struct {
	// A line as it is, of no column.
	text string
	row  bool

	label string
	// How long it has left, or in its place a note, as (lease); and since when it was seen.
	left    time.Duration
	hasLeft bool
	note    string
	up      time.Duration
	hasUp   bool
	rest    string
}

// Line adds a line as it is, as a heading: it has no column, and the rows around it line up all
// the same.
func (t *Table) Line(text string) {
	t.lines = append(t.lines, line{text: text})
}

// Row adds a row: label, with its indentation, how long it has left, how long it has been seen,
// and the rest, as what said it.
func (t *Table) Row(label string, left, up time.Duration, rest string) {
	t.lines = append(t.lines, line{row: true, label: label, left: left, hasLeft: true, up: up, hasUp: true, rest: rest})
}

// RowNote is Row with a note in place of how long it has left: what has no time of its own.
func (t *Table) RowNote(label, note string, up time.Duration, rest string) {
	t.lines = append(t.lines, line{row: true, label: label, note: note, up: up, hasUp: true, rest: rest})
}

// RowText is a row of label and the rest alone: no time, the columns left blank.
func (t *Table) RowText(label, rest string) {
	t.lines = append(t.lines, line{row: true, label: label, rest: rest})
}

// Render is the lines, the rows of each prefixed by prefix, padded to the widest label, and their
// times each in its column.
func (t *Table) Render(prefix string) string {
	width, days, hours := 0, false, false
	for _, l := range t.lines {
		if !l.row {
			continue
		}
		width = max(width, len(l.label))
		if l.hasLeft {
			left := l.left.Round(time.Second)
			days = days || left >= 24*time.Hour
			hours = hours || left >= time.Hour
		}
	}
	leftWidth := len(Left(0, days, hours))
	for _, l := range t.lines {
		if l.row && !l.hasLeft {
			leftWidth = max(leftWidth, len(l.note))
		}
	}
	var b strings.Builder
	for _, l := range t.lines {
		if !l.row {
			b.WriteString(prefix + l.text + "\n")
			continue
		}
		left := l.note
		if l.hasLeft {
			left = Left(l.left, days, hours)
		}
		up := strings.Repeat(" ", len("up ")+len(Up(0)))
		if l.hasUp {
			up = "up " + Up(l.up)
		}
		if !l.hasLeft && !l.hasUp && l.note == "" {
			left, up = "", strings.Repeat(" ", len(up))
		}
		row := fmt.Sprintf("%s%-*s  %*s  %s", prefix, width, l.label, leftWidth, left, up)
		if l.rest != "" {
			row += "  " + l.rest
		}
		b.WriteString(strings.TrimRight(row, " ") + "\n")
	}
	return b.String()
}

// Left is how long something has left, every unit from its largest down to the seconds, each in
// its column, those above blank: with days, of a table where one has them, and hours. The largest
// column takes what is beyond it, as 30h of a table of no days. Over, it is "expired".
func Left(d time.Duration, days, hours bool) string {
	units := allUnits
	if !days {
		units = units[1:]
		if !hours {
			units = units[1:]
		}
	}
	d = d.Round(time.Second)
	if d <= 0 {
		return fmt.Sprintf("%*s", cellsWidth(units), "expired")
	}
	first := len(units) - 1
	for i, u := range units {
		if d >= u.size {
			first = i
			break
		}
	}
	var b strings.Builder
	for i, u := range units {
		if i < first {
			b.WriteString(strings.Repeat(" ", u.width+len(u.name)))
			continue
		}
		n := d / u.size
		d -= n * u.size
		fmt.Fprintf(&b, "%*d%s", u.width, n, u.name)
	}
	return b.String()
}

// Up is how long something has been seen: its largest unit, and the next when it isn't zero, each
// in its column of days, hours, minutes and seconds, the others blank. The rest is cut.
func Up(d time.Duration) string {
	d = max(d, 0)
	first := len(allUnits) - 1
	for i, u := range allUnits {
		if d >= u.size {
			first = i
			break
		}
	}
	var b strings.Builder
	for i, u := range allUnits {
		n := d / u.size
		d -= n * u.size
		if i == first || i == first+1 && n > 0 {
			fmt.Fprintf(&b, "%*d%s", u.width, n, u.name)
		} else {
			b.WriteString(strings.Repeat(" ", u.width+len(u.name)))
		}
	}
	return b.String()
}

// allUnits are the columns of the durations: days, of three digits, and the others of two.
var allUnits = []unit{{24 * time.Hour, "d", 3}, {time.Hour, "h", 2}, {time.Minute, "m", 2}, {time.Second, "s", 2}}

type unit struct {
	size  time.Duration
	name  string
	width int
}

func cellsWidth(units []unit) int {
	w := 0
	for _, u := range units {
		w += u.width + len(u.name)
	}
	return w
}
