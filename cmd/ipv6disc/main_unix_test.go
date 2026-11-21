//go:build unix && !aix && !illumos && !solaris

package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// -live without a terminal, as docker run without -t or a service: it says so and exits, before
// anything is started, where it panicked with the discovery running.
func TestLiveNeedsATerminal(t *testing.T) {
	// A session of its own has no controlling terminal, wherever the tests run.
	noTerminal := func(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
	config := writeConfig(t, "ipv6:\n  enabled: false\nipv4:\n  enabled: true\n  active: false\n")
	code, stdout, stderr := command(t, noTerminal, "-live", "-config_file", config)
	if code != 1 || !strings.Contains(stderr, "-live needs a terminal") || strings.Contains(stderr, "panic") || stdout != "" {
		t.Errorf("exit %d, want 1 and the reason alone:\n%s%s", code, stdout, stderr)
	}
}

// output is what a command wrote so far, read while it runs.
type output struct {
	mutex   sync.Mutex
	written bytes.Buffer
}

func (o *output) Write(p []byte) (int, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.written.Write(p)
}

func (o *output) String() string {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.written.String()
}

// The log is at the level the file says, and at info without one: a command that starts warns
// of a family with no protocol, and says at info which protocols run. It sends nothing: IPv4
// alone, with none of its protocols.
func TestLogLevelOfTheFile(t *testing.T) {
	const quiet = "ipv6:\n  enabled: false\nipv4:\n  enabled: true\nprotocols:\n  arp:\n    enabled: false\n  arp-sweep:\n    enabled: false\n  arp-listen:\n    enabled: false\n"
	for _, tt := range []struct {
		level      string
		warn, info bool
	}{
		{"", true, true},
		{"log_level: info\n", true, true},
		{"log_level: debug\n", true, true},
		{"log_level: warn\n", true, false},
		{"log_level: error\n", false, false},
	} {
		cmd := exec.Command(os.Args[0], "-config_file", writeConfig(t, quiet+tt.level))
		cmd.Env = append(os.Environ(), asCommand+"=1")
		var out output
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		// Until it said what it says last as it starts, or, of one that says nothing, long
		// enough to have.
		last, wait := `"msg":"protocols of the local discovery: none"`, 10*time.Second
		if !tt.info {
			last = `"level":"warn"`
		}
		if !tt.warn {
			wait = 2 * time.Second
		}
		for deadline := time.Now().Add(wait); time.Now().Before(deadline) && !strings.Contains(out.String(), last); {
			time.Sleep(20 * time.Millisecond)
		}
		cmd.Process.Signal(syscall.SIGTERM)
		err := cmd.Wait()
		log := out.String()
		if err != nil {
			t.Errorf("%q: the command, told to stop: %v\n%s", tt.level, err, log)
		}
		if warned := strings.Contains(log, `"level":"warn","ts"`) && strings.Contains(log, "IPv4 listens, but no protocol that finds its hosts is enabled"); warned != tt.warn {
			t.Errorf("%q: warned %v, want %v:\n%s", tt.level, warned, tt.warn, log)
		}
		if info := strings.Contains(log, `"level":"info"`); info != tt.info {
			t.Errorf("%q: logged at info %v, want %v:\n%s", tt.level, info, tt.info, log)
		}
		if tt.info && !strings.Contains(log, `"msg":"stopping"`) {
			t.Errorf("%q: it didn't say it stops:\n%s", tt.level, log)
		}
	}
}
