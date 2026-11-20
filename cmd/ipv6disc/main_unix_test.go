//go:build unix && !aix && !illumos && !solaris

package main

import (
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// -live without a terminal, as docker run without -t or a service: it says so and exits, before
// anything is started, where it panicked with the discovery running.
func TestLiveNeedsATerminal(t *testing.T) {
	// A session of its own has no controlling terminal, wherever the tests run.
	noTerminal := func(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
	code, stdout, stderr := command(t, noTerminal, "-live", "-ipv6=false", "-ipv4", "-ipv4_active=false")
	if code != 1 || !strings.Contains(stderr, "-live needs a terminal") || strings.Contains(stderr, "panic") || stdout != "" {
		t.Errorf("exit %d, want 1 and the reason alone:\n%s%s", code, stdout, stderr)
	}
}
