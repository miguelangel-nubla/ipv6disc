package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// asCommand makes the test binary the command itself: the tests of what it does with its
// arguments, and how it exits, run it so.
const asCommand = "IPV6DISC_TEST_AS_COMMAND"

func TestMain(m *testing.M) {
	if os.Getenv(asCommand) != "" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// command runs the command with args, and returns its exit code and what it wrote.
func command(t *testing.T, prepare func(*exec.Cmd), args ...string) (code int, stdout, stderr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append(os.Environ(), asCommand+"=1")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if prepare != nil {
		prepare(cmd)
	}
	err := cmd.Run()
	var exit *exec.ExitError
	if ctx.Err() != nil {
		t.Fatalf("ipv6disc %s: still running after 30s", strings.Join(args, " "))
	} else if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode(), out.String(), errOut.String()
}

// What the command can't run with ends it at once, with the reason: nothing is left out, or
// taken as something else, without a word.
func TestCommandRejects(t *testing.T) {
	for _, tt := range []struct {
		args string
		code int
		want string
	}{
		// A word that is no flag: the flags after it would not be read.
		{"-ipv6 false -ipv4", 2, `unexpected argument "false"`},
		{"-ipv6=false -ipv4 -ipv4_active=false typo", 2, `unexpected argument "typo"`},
		{"-plugin nonsense", 2, "expected: name=type:params"},
		{"-plugin router=nosuch:60s", 1, "can't create plugin nosuch"},
		// The worker's own checks, of the config the flags make.
		{"-ipv6=false", 1, "nothing to do"},
		{"-lifetime 0", 1, "they must be positive"},
		{"-rediscover=-1s", 1, "they must be positive"},
		{"-ipv4_lifetime=-1s", 1, "invalid family lifetime"},
		// The names' flags reach the config: off unless given.
		{"-hostnames -hostnames_lifetime=-1s", 1, "invalid names' lifetime"},
		{"-hostnames=maybe", 2, "invalid boolean value"},
		{"-interfaces=[", 1, "invalid interface pattern"},
		{"-log_level=loud", 1, "invalid log level"},
	} {
		code, stdout, stderr := command(t, nil, strings.Fields(tt.args)...)
		if code != tt.code || !strings.Contains(stdout+stderr, tt.want) {
			t.Errorf("ipv6disc %s: exit %d, want %d with %q:\n%s%s", tt.args, code, tt.code, tt.want, stdout, stderr)
		}
		if tt.code == 2 && !strings.Contains(stderr, "Usage of") {
			t.Errorf("ipv6disc %s: no usage:\n%s", tt.args, stderr)
		}
	}
}
