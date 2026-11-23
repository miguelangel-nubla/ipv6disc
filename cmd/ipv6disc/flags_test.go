package main

import (
	"flag"
	"os"
	"slices"
	"strings"
	"testing"
)

// resetFlags gives the test the flags as a new process has them, none given, and leaves them so:
// the flags are the process's, and what a test gives them would otherwise stay for the next, and
// for its own next run under -count. A flag set can't forget what it was given, so the test has
// one of its own, and the process's, which has those of the tests too, comes back after it.
func resetFlags(t *testing.T) {
	t.Helper()
	original := flag.CommandLine
	define := func() {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
		flag.CommandLine.Usage = func() { flag.Usage() }
		defineFlags()
	}
	define()
	t.Cleanup(func() {
		// The values the flags were given are of the variables, which both sets have.
		configFile, live, showVersion = "", false, false
		define()
		flag.CommandLine = original
	})
}

// The command has three flags, and no other: the rest is the configuration file's.
func TestFlags(t *testing.T) {
	resetFlags(t)
	var names []string
	flag.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	if !slices.Equal(names, []string{"config", "live", "version"}) {
		t.Errorf("the flags are %v", names)
	}
	if err := flag.CommandLine.Parse(nil); err != nil || configFile != "" || live || showVersion {
		t.Errorf("without flags: config %q, live %v, version %v, %v", configFile, live, showVersion, err)
	}
	if err := flag.CommandLine.Parse([]string{"--config", "discovery.yaml", "--live"}); err != nil || configFile != "discovery.yaml" || !live {
		t.Errorf("with them: config %q, live %v, %v", configFile, live, err)
	}
}

// What was a flag is one no more, as any the command never had: its setting is a key of the
// configuration file.
func TestOldFlagsAreUnknown(t *testing.T) {
	for _, old := range []string{
		// The name --config had.
		"-config_file=discovery.yaml",
		"-ipv4", "-ipv6=false", "-ipv6_listen=false", "-ipv6_active=false", "-ipv4_listen", "-ipv4_active=false",
		"-lifetime=1h", "-ipv6_lifetime=1h", "-ipv4_lifetime=1h", "-rediscover=10m",
		"-hostnames", "-hostnames_lifetime=1h", "-hostnames_protocols=mdns", "-hostnames_dns=192.168.1.1",
		"-interfaces=eth0", "-exclude_interfaces=docker*", "-plugin=router=linux:60s", "-log_level=debug",
		// And the names they had before.
		"-discovery-listen", "-discovery-active", "-ipv6-listen", "-ipv4-active", "-ipv6-lifetime=1h", "-exclude-interfaces=docker*",
	} {
		resetFlags(t)
		var out strings.Builder
		flag.CommandLine.SetOutput(&out)
		name, _, _ := strings.Cut(old, "=")
		if err := flag.CommandLine.Parse([]string{old}); err == nil || err.Error() != "flag provided but not defined: "+name {
			t.Errorf("%s: %v, want it not defined", old, err)
		}
		if !strings.Contains(out.String(), "Usage of") || !strings.Contains(out.String(), reference) {
			t.Errorf("%s: no usage with where the configuration is told:\n%s", old, out.String())
		}
	}
}

// The usage lists the flags there are, and tells where the keys of the configuration file are.
func TestUsage(t *testing.T) {
	resetFlags(t)
	if err := flag.CommandLine.Parse([]string{"--live", "--config=other.yaml"}); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	previous := flag.CommandLine.Output()
	flag.CommandLine.SetOutput(&out)
	defer flag.CommandLine.SetOutput(previous)
	usage()

	for _, want := range []string{
		"  --config string\n",
		"Without it no file is read, and the defaults discover IPv6",
		"  --live\n",
		"  --version\n",
		"\nEverything else is in the configuration file, whose keys are at:\n  https://github.com/miguelangel-nubla/ipv6disc/blob/main/docs/reference/configuration.md\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the usage lacks %q:\n%s", want, out.String())
		}
	}
	// The page it points to is there.
	if _, err := os.Stat("../../docs/reference/configuration.md"); err != nil {
		t.Error(err)
	}
}

// flag stops at the first word that is no flag, and a boolean flag takes none: what follows
// "--live false" was left out without a word.
func TestUnexpectedArgs(t *testing.T) {
	parse := func(args ...string) (*flag.FlagSet, *bool, *string) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		live, file := fs.Bool("live", true, ""), fs.String("config", "", "")
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return fs, live, file
	}

	fs, live, file := parse("--live", "false", "--config", "discovery.yaml")
	if !*live || *file != "" || fs.NArg() != 3 {
		t.Fatalf("--live false --config discovery.yaml: live %v, config %q, left %v: flag changed, and so must this test", *live, *file, fs.Args())
	}
	if err := unexpectedArgs(fs.Args()); err == nil || !strings.Contains(err.Error(), `"false"`) || !strings.Contains(err.Error(), "--name=false") {
		t.Errorf("--live false: error %v, want one naming \"false\" and the way to write it", err)
	}

	fs, live, file = parse("--live=false", "--config", "discovery.yaml")
	if *live || *file != "discovery.yaml" {
		t.Errorf("--live=false --config discovery.yaml: live %v, config %q", *live, *file)
	}
	if err := unexpectedArgs(fs.Args()); err != nil {
		t.Errorf("--live=false --config discovery.yaml: %v", err)
	}
}

// The version is the release's, when its build set it, and never nothing.
func TestVersion(t *testing.T) {
	if got := versionString(); got == "" {
		t.Error("no version")
	}
	version = "1.2.3"
	defer func() { version = "" }()
	if got := versionString(); got != "1.2.3" {
		t.Errorf("the version of a release: %q", got)
	}
}
