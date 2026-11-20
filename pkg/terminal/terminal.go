//go:build !plan9 && !js && !illumos && !aix && !solaris

// Package terminal shows a text that changes in the terminal, full screen, scrolled with the keys.
package terminal

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-runewidth"
	"github.com/nsf/termbox-go"
)

const controls = "Controls: ↑ ↓ PgUp PgDn  q/ESC/Enter: quit"

// cell is a rune and the screen column it starts at.
type cell struct {
	col int
	ch  rune
}

// layoutLine places the runes of line in screen columns, each after the width of those before
// it, not their bytes, and leaves out what doesn't fit in width.
func layoutLine(line string, width int) []cell {
	cells := make([]cell, 0, len(line))
	col := 0
	for _, ch := range line {
		w := runewidth.RuneWidth(ch)
		if w == 0 { // combining or control: no cell of its own
			continue
		}
		if col+w > width {
			break
		}
		cells = append(cells, cell{col, ch})
		col += w
	}
	return cells
}

// clampOffset is the offset within what there is to scroll: lineCount lines, on a screen of
// height rows of which the last is the controls'.
func clampOffset(offset, lineCount, height int) int {
	return max(0, min(offset, lineCount+1-height))
}

func displayContent(lines []string, offset int) {
	termbox.Clear(termbox.ColorDefault, termbox.ColorDefault)
	width, height := termbox.Size()

	for y := 0; y < height-1 && y+offset < len(lines); y++ {
		for _, c := range layoutLine(lines[y+offset], width) {
			termbox.SetCell(c.col, y, c.ch, termbox.ColorDefault, termbox.ColorDefault)
		}
	}
	for _, c := range layoutLine(controls, width) {
		termbox.SetCell(c.col, height-1, c.ch, termbox.ColorDefault, termbox.ColorDefault)
	}

	termbox.Flush()
}

// pollEvents sends the terminal's events until it is interrupted, which Interrupt does after
// closing done: it doesn't leave before, so that Interrupt always finds it polling.
func pollEvents(eventChan chan<- termbox.Event, done <-chan struct{}) {
	for {
		ev := termbox.PollEvent()
		if ev.Type == termbox.EventInterrupt {
			return
		}
		select {
		case eventChan <- ev:
		case <-done:
		}
	}
}

// Init takes the terminal over. Without a terminal it returns an error: a caller checks it
// before starting what the output is of. Close gives the terminal back.
func Init() error {
	if err := termbox.Init(); err != nil {
		return err
	}
	termbox.SetInputMode(termbox.InputEsc | termbox.InputMouse)
	return nil
}

// Close gives back the terminal Init took.
func Close() {
	termbox.Close()
}

// Run shows each content received, on the terminal Init took, until a key quits, q, Esc, Enter
// or Ctrl-C, or ctx is done: the terminal is raw, so a signal is the caller's to turn into ctx.
func Run(ctx context.Context, contentChan <-chan string) {
	eventChan := make(chan termbox.Event)
	done := make(chan struct{})
	go pollEvents(eventChan, done)
	defer func() {
		close(done)
		termbox.Interrupt()
	}()

	loop(ctx, contentChan, eventChan, func() int {
		_, height := termbox.Size()
		return height
	}, displayContent)
}

// loop is Run, of the events and on the screen given.
func loop(ctx context.Context, contentChan <-chan string, eventChan <-chan termbox.Event, screenHeight func() int, display func(lines []string, offset int)) {
	offset := 0
	lines := []string{}

	for {
		select {
		case <-ctx.Done():
			return
		case content, ok := <-contentChan:
			if !ok {
				// No more content: what there is stays, until a key or ctx.
				contentChan = nil
				continue
			}
			lines = nil
			if content = strings.TrimSuffix(content, "\n"); content != "" {
				lines = strings.Split(content, "\n")
			}
		case ev := <-eventChan:
			if ev.Type == termbox.EventKey {
				page := screenHeight() - 1
				switch ev.Key {
				case termbox.KeyArrowUp:
					offset--
				case termbox.KeyArrowDown:
					offset++
				case termbox.KeyPgup:
					offset -= page
				case termbox.KeyPgdn:
					offset += page
				case termbox.KeyEsc, termbox.KeyCtrlC, termbox.KeyCtrlD, termbox.KeyCtrlZ, termbox.KeyEnter:
					return
				}
				if ev.Ch == 'q' || ev.Ch == 'Q' {
					return
				}
			}
		}
		// Whatever changed, the content, the offset or the size of the screen: fewer lines, or
		// a taller screen, would leave the offset past the end, and the screen blank.
		offset = clampOffset(offset, len(lines), screenHeight())
		display(lines, offset)
	}
}

// LiveOutput is Init, Run and Close, for a caller that has no context to stop it with. Without
// a terminal it exits.
func LiveOutput(contentChan chan string) {
	if err := Init(); err != nil {
		fmt.Fprintln(os.Stderr, "live output needs a terminal:", err)
		os.Exit(1)
	}
	defer Close()
	Run(context.Background(), contentChan)
}
