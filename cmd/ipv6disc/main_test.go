package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

// writeConfig writes a configuration file of the test's, and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "discovery.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// What the command can't run with ends it at once, with the reason: nothing is left out, or
// taken as something else, without a word.
func TestCommandRejects(t *testing.T) {
	for _, tt := range []struct {
		args, config string
		code         int
		want         string
	}{
		// A word that is no flag: the flags after it would not be read.
		{args: "-live false -version", code: 2, want: `unexpected argument "false"`},
		{args: "-live=false typo", code: 2, want: `unexpected argument "typo"`},
		// What was a flag, and any other there is none of.
		{args: "-ipv4", code: 2, want: "flag provided but not defined: -ipv4"},
		{args: "-hostnames -live", code: 2, want: "flag provided but not defined: -hostnames"},
		{args: "-plugin router=linux:60s", code: 2, want: "flag provided but not defined: -plugin"},
		{args: "-log_level=debug", code: 2, want: "flag provided but not defined: -log_level"},
		{args: "-lifetime 1h", code: 2, want: "flag provided but not defined: -lifetime"},
		{args: "-live=maybe", code: 2, want: "invalid boolean value"},
		// A file that isn't there, and one that says what can't be: each error of it.
		{args: "-config_file /no/such/file.yaml", code: 1, want: "/no/such/file.yaml: no such file or directory"},
		{config: "ipv4: true", code: 1, want: "ipv4: true is not its settings: it is written as ipv4, with enabled: true under it"},
		{config: "protocols:\n  bonjour:\n    enabled: true", code: 1, want: "protocols.bonjour: no such protocol: they are ndp, ping,"},
		{config: "protocols:\n  mdns:\n    asks: true", code: 1, want: "protocols.mdns.asks: no such option of mdns: it has enabled, ask"},
		{config: "protocols:\n  mdns:\n    ask: 3", code: 1, want: "protocols.mdns.ask: 3 is not true or false"},
		{config: "hostnames:\n  enabled: true", code: 1, want: "hostnames.enabled: the names are no longer switched"},
		{config: "protocols:\n  arp-sweep:\n    max_prefix: 8", code: 1, want: "invalid max_prefix of the arp-sweep protocol, 8: it is from 16 to 30"},
		{config: "plugins:\n  router:\n    type: nosuch", code: 1, want: `plugins.router.type: no such type of plugin, "nosuch"`},
		{config: "lifetime: 0", code: 1, want: "they must be positive"},
		{config: "rediscover: -1s", code: 1, want: "they must be positive"},
		{config: "ipv4:\n  lifetime: -1s", code: 1, want: "invalid family lifetime"},
		{config: "hostnames:\n  lifetime: -1s", code: 1, want: "invalid names' lifetime"},
		{config: "interfaces: \"[\"", code: 1, want: "invalid interface pattern"},
		{config: "log_level: loud", code: 1, want: `log_level: "loud" is no level of the log`},
		// The worker's own check, of a valid configuration that does nothing.
		{config: "ipv6:\n  enabled: false", code: 1, want: "nothing to do"},
	} {
		args := strings.Fields(tt.args)
		if tt.config != "" {
			args = append(args, "-config_file", writeConfig(t, tt.config))
		}
		code, stdout, stderr := command(t, nil, args...)
		if code != tt.code || !strings.Contains(stdout+stderr, tt.want) {
			t.Errorf("ipv6disc %s (%s): exit %d, want %d with %q:\n%s%s", tt.args, tt.config, code, tt.code, tt.want, stdout, stderr)
		}
		if tt.code == 2 && !strings.Contains(stderr, "Usage of") {
			t.Errorf("ipv6disc %s: no usage:\n%s", tt.args, stderr)
		}
		// The errors of the file come before anything is logged, in plain words.
		if tt.config != "" && tt.want != "nothing to do" && (stdout != "" || !strings.HasPrefix(stderr, "ipv6disc: the configuration can't be used:\n")) {
			t.Errorf("ipv6disc (%s): the error of the file:\n%s%s", tt.config, stdout, stderr)
		}
	}
}

// -version says the version and exits, whatever else is given, and -h the flags and where the
// configuration file's keys are.
func TestCommandVersionAndHelp(t *testing.T) {
	code, stdout, stderr := command(t, nil, "-version", "-config_file", "/no/such/file.yaml")
	if code != 0 || !strings.HasPrefix(stdout, "ipv6disc ") || strings.TrimSpace(strings.TrimPrefix(stdout, "ipv6disc ")) == "" || stderr != "" {
		t.Errorf("-version: exit %d:\n%s%s", code, stdout, stderr)
	}
	for _, help := range []string{"-h", "-help"} {
		code, stdout, stderr = command(t, nil, help)
		if code != 0 || stdout != "" || !strings.Contains(stderr, "-config_file string") || !strings.Contains(stderr, reference) {
			t.Errorf("%s: exit %d:\n%s%s", help, code, stdout, stderr)
		}
	}
}
