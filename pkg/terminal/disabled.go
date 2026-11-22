//go:build plan9 || js || illumos || aix || solaris

// Package terminal shows a text that changes in the terminal, full screen, scrolled with the keys.
package terminal

import (
	"context"
	"errors"
	"log"

	"github.com/miguelangel-nubla/ipv6disc/pkg/pretty"
)

var errUnsupported = errors.New("live output is not supported on this platform")

// Init returns an error: there is no live output on this platform.
func Init() error { return errUnsupported }

func Close() {}

// Run returns at once: Init gave no terminal.
func Run(ctx context.Context, contentChan <-chan string) {}

// RunPages returns at once: Init gave no terminal.
func RunPages(ctx context.Context, contentChan <-chan pretty.Page) {}

func LiveOutput(contentChan chan string) {
	log.Fatal("Live output is not supported on this platform, please remove the -live flag.")
}
