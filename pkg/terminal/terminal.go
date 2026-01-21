//go:build !plan9 && !js && !illumos && !aix && !solaris

package terminal

import (
	"bufio"
	"strings"

	"github.com/nsf/termbox-go"
)

func pollEvents(eventChan chan termbox.Event) {
	for {
		eventChan <- termbox.PollEvent()
	}
}

func displayContent(lines []string, offset int) {
	termbox.Clear(termbox.ColorDefault, termbox.ColorDefault)
	width, height := termbox.Size()

	for y := 0; y < height-1 && y+offset < len(lines); y++ {
		line := lines[y+offset]
		for x, ch := range line {
			if x < width {
				termbox.SetCell(x, y, ch, termbox.ColorDefault, termbox.ColorDefault)
			}
		}
	}

	controls := "Controls: ↑ ↓ PgUp PgDn ESC/Enter"
	for x, ch := range controls {
		termbox.SetCell(x, height-1, ch, termbox.ColorDefault, termbox.ColorDefault)
	}

	termbox.Flush()
}

func LiveOutput(contentChan chan string) {
	err := termbox.Init()
	if err != nil {
		panic(err)
	}
	defer termbox.Close()

	eventChan := make(chan termbox.Event)
	go pollEvents(eventChan)

	termbox.SetInputMode(termbox.InputEsc | termbox.InputMouse)
	offset := 0
	lines := []string{}

mainloop:
	for {
		select {
		case content := <-contentChan:
			lines = []string{}
			scanner := bufio.NewScanner(strings.NewReader(content))
			for scanner.Scan() {
				lines = append(lines, scanner.Text())
			}
			displayContent(lines, offset)
		case ev := <-eventChan:
			switch ev.Type {
			case termbox.EventKey:
				_, height := termbox.Size()
				switch ev.Key {
				case termbox.KeyArrowUp:
					offset--
				case termbox.KeyArrowDown:
					offset++
				case termbox.KeyPgup:
					offset -= (height - 1)
				case termbox.KeyPgdn:
					offset += (height - 1)
				case termbox.KeyEsc, termbox.KeyCtrlC, termbox.KeyCtrlD, termbox.KeyCtrlZ, termbox.KeyEnter:
					break mainloop
				}

				if ev.Ch == 'q' || ev.Ch == 'Q' {
					break mainloop
				}

				if offset < 0 {
					offset = 0
				}
				// +1 takes into account controls displayed at bottom of screen
				maxOffset := len(lines) + 1 - height
				if maxOffset < 0 {
					maxOffset = 0
				}
				if offset > maxOffset {
					offset = maxOffset
				}
			case termbox.EventResize:
				displayContent(lines, offset)
			}
			displayContent(lines, offset)
		}
	}
}
