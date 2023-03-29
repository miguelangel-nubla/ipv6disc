//go:build plan9 || js || illumos || aix || solaris

package terminal

import (
	"log"
)

func LiveOutput(contentChan chan string) {
	log.Fatal("Live output is not supported on this architecture, please remove the --live flag.")
}
