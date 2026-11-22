//go:build !plan9 && !js && !illumos && !aix && !solaris

package terminal

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nsf/termbox-go"

	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

// A rune is placed after the width of those before it, not their bytes: the arrows of the
// controls are 3 bytes each, and left gaps.
func TestLayoutLine(t *testing.T) {
	cells := layoutLine(text(controls), 200)
	if len(cells) != len([]rune(controls)) {
		t.Fatalf("controls: %d cells, want %d", len(cells), len([]rune(controls)))
	}
	for i, c := range cells {
		if c.col != i {
			t.Fatalf("controls: %q at column %d, want %d", c.ch, c.col, i)
		}
	}
	if !strings.Contains(controls, "q") {
		t.Error("the controls don't tell of q")
	}

	col := func(cells []cell, ch rune) int {
		for _, c := range cells {
			if c.ch == ch {
				return c.col
			}
		}
		return -1
	}
	if got := col(layoutLine(text("salón=x"), 80), '='); got != 5 {
		t.Errorf("salón=x: = at column %d, want 5", got)
	}
	// A wide rune takes two columns, a combining one none.
	if got := col(layoutLine(text("世="), 80), '='); got != 2 {
		t.Errorf("after a wide rune: column %d, want 2", got)
	}
	if got := col(layoutLine(text("é="), 80), '='); got != 1 {
		t.Errorf("after a combining rune: column %d, want 1", got)
	}

	// What doesn't fit is left out, a wide rune across the edge too.
	if got := layoutLine(text("abcdef"), 4); len(got) != 4 || got[3].ch != 'd' {
		t.Errorf("abcdef in 4 columns: %v", got)
	}
	if got := layoutLine(text("abc世"), 4); len(got) != 3 {
		t.Errorf("abc世 in 4 columns: %v, want the wide rune left out", got)
	}
	if got := layoutLine(text("abc"), 0); len(got) != 0 {
		t.Errorf("no columns: %v", got)
	}
}

func text(s string) pretty.Line {
	return pretty.Line{{Text: s}}
}

// The pieces of a line follow each other on the screen, each cell with the role of its piece.
func TestLayoutLineRoles(t *testing.T) {
	cells := layoutLine(pretty.Line{pretty.As(pretty.Name, "世a"), {Text: ": "}, pretty.As(pretty.Error, "bad")}, 6)
	want := []cell{{0, '世', pretty.Name}, {2, 'a', pretty.Name}, {3, ':', pretty.Plain}, {4, ' ', pretty.Plain}, {5, 'b', pretty.Error}}
	if !slices.Equal(cells, want) {
		t.Errorf("got %v, want %v", cells, want)
	}
}

// A state has its color, a heading and a detail the terminal's own; without colors the roles
// that are bold or dim stay so.
func TestAttribute(t *testing.T) {
	for _, c := range []struct {
		role          pretty.Role
		with, without termbox.Attribute
	}{
		{pretty.Plain, termbox.ColorDefault, termbox.ColorDefault},
		{pretty.Heading, termbox.ColorDefault | termbox.AttrBold, termbox.ColorDefault | termbox.AttrBold},
		{pretty.OK, termbox.ColorGreen, termbox.ColorDefault},
		{pretty.Warn, termbox.ColorYellow, termbox.ColorDefault},
		{pretty.Error, termbox.ColorRed | termbox.AttrBold, termbox.ColorDefault | termbox.AttrBold},
		{pretty.Detail, termbox.ColorDefault | termbox.AttrDim, termbox.ColorDefault | termbox.AttrDim},
	} {
		if got := attribute(c.role, true); got != c.with {
			t.Errorf("role %d: %v, want %v", c.role, got, c.with)
		}
		if got := attribute(c.role, false); got != c.without {
			t.Errorf("role %d without colors: %v, want %v", c.role, got, c.without)
		}
	}
	t.Setenv("NO_COLOR", "1")
	if !noColor() {
		t.Error("NO_COLOR=1 isn't taken")
	}
	t.Setenv("NO_COLOR", "")
	if noColor() {
		t.Error("NO_COLOR empty is taken")
	}
}

func TestClampOffset(t *testing.T) {
	for _, tt := range []struct {
		what                            string
		offset, lineCount, height, want int
	}{
		{"above the top", -3, 100, 10, 0},
		{"content shorter than the screen", 5, 4, 10, 0},
		{"in range", 7, 100, 10, 7},
		{"the last screen", 91, 100, 10, 91},
		{"past the end", 200, 100, 10, 91},
		{"after the content shrank", 91, 20, 10, 11},
		{"a taller screen", 91, 100, 40, 61},
		{"no content", 3, 0, 10, 0},
		{"no screen", 3, 5, 0, 3},
	} {
		if got := clampOffset(tt.offset, tt.lineCount, tt.height); got != tt.want {
			t.Errorf("%s: clampOffset(%d, %d, %d) = %d, want %d", tt.what, tt.offset, tt.lineCount, tt.height, got, tt.want)
		}
	}
}

// drawn is what loop displayed last.
type drawn struct {
	lines  int
	offset int
}

func runLoop(t *testing.T, ctx context.Context, height *int) (content chan pretty.Page, events chan termbox.Event, screen chan drawn, returned chan struct{}) {
	t.Helper()
	content, events = make(chan pretty.Page), make(chan termbox.Event)
	screen, returned = make(chan drawn, 100), make(chan struct{})
	go func() {
		loop(ctx, content, events, func() int { return *height }, func(lines pretty.Page, offset int) {
			screen <- drawn{len(lines), offset}
		})
		close(returned)
	}()
	return
}

func wantReturn(t *testing.T, returned chan struct{}, what string) {
	t.Helper()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: the loop didn't return", what)
	}
}

// The context ends it, as a key does: a SIGTERM is no key press.
func TestLoopEnds(t *testing.T) {
	height := 10
	ctx, cancel := context.WithCancel(context.Background())
	_, _, _, returned := runLoop(t, ctx, &height)
	cancel()
	wantReturn(t, returned, "context done")

	for _, ev := range []termbox.Event{
		{Type: termbox.EventKey, Ch: 'q'},
		{Type: termbox.EventKey, Key: termbox.KeyEsc},
		{Type: termbox.EventKey, Key: termbox.KeyEnter},
		{Type: termbox.EventKey, Key: termbox.KeyCtrlC},
	} {
		_, events, _, returned := runLoop(t, context.Background(), &height)
		events <- ev
		wantReturn(t, returned, "a quit key")
	}

	// The content's channel closed ends nothing, and doesn't spin: the keys still work.
	content, events, _, returned := runLoop(t, context.Background(), &height)
	content <- pretty.Text("a\nb\n")
	close(content)
	events <- termbox.Event{Type: termbox.EventKey, Key: termbox.KeyArrowDown}
	events <- termbox.Event{Type: termbox.EventKey, Ch: 'q'}
	wantReturn(t, returned, "q after the content closed")
}

// The offset is within the content at every draw, not only after a key: content with fewer
// lines, or a taller screen, left it past the end and the screen blank.
func TestLoopKeepsTheOffsetWithinTheContent(t *testing.T) {
	height := 10
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	content, events, screen, _ := runLoop(t, ctx, &height)

	content <- pretty.Text(strings.Repeat("line\n", 100))
	if got := <-screen; got != (drawn{100, 0}) {
		t.Fatalf("first draw: %+v", got)
	}
	var got drawn
	for range 20 {
		events <- termbox.Event{Type: termbox.EventKey, Key: termbox.KeyPgdn}
		got = <-screen
	}
	if got.offset != 91 {
		t.Fatalf("paged down to the end: offset %d, want 91", got.offset)
	}

	content <- pretty.Text(strings.Repeat("line\n", 20))
	if got := <-screen; got != (drawn{20, 11}) {
		t.Errorf("after the content shrank: %+v, want 20 lines at offset 11", got)
	}

	height = 40
	events <- termbox.Event{Type: termbox.EventResize}
	if got := <-screen; got.offset != 0 {
		t.Errorf("after the screen grew past the content: offset %d, want 0", got.offset)
	}

	events <- termbox.Event{Type: termbox.EventKey, Key: termbox.KeyArrowUp}
	if got := <-screen; got.offset != 0 {
		t.Errorf("up at the top: offset %d", got.offset)
	}
}
