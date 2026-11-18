package main

import (
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

var update = flag.Bool("update", false, "write the reference pages")

const generated = "<!-- Generated from the code by `go test ./cmd/ipv6disc -update`: edit it, not this page. -->\n\n"

// pluginTypes says what each plugin type reads, and how.
var pluginTypes = map[string]string{
	"freebsd":  "A FreeBSD host, as pfSense or OPNsense, over SSH: `ndp -an` for IPv6, `arp -an` for IPv4.",
	"linux":    "A Linux host, as OpenWrt, over SSH: `ip neigh`.",
	"mikrotik": "A Mikrotik router, over its API: `/ipv6/neighbor` for IPv6, `/ip/arp` for IPv4.",
}

func cell(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// cliPage is the reference of the flags, as -h lists them, without the deprecated names.
func cliPage() string {
	var b strings.Builder
	b.WriteString("# Flags\n\n" + generated)
	b.WriteString("| Flag | Default | |\n|---|---|---|\n")
	flag.VisitAll(func(f *flag.Flag) {
		if _, deprecated := deprecatedFlags[f.Name]; deprecated || f.Name == "update" || strings.HasPrefix(f.Name, "test.") {
			return
		}
		def := f.DefValue
		if def == "" || def == "0s" || def == "[]" {
			def = "-"
		} else {
			def = "`" + def + "`"
		}
		fmt.Fprintf(&b, "| `-%s` | %s | %s |\n", f.Name, def, cell(f.Usage))
	})
	b.WriteString("\nThe names from before still work, with a warning:")
	for _, old := range sortedKeys(deprecatedFlags) {
		fmt.Fprintf(&b, " `-%s`,", old)
	}
	s := strings.TrimSuffix(b.String(), ",")
	return s + ".\n"
}

// pluginsPage is the reference of the plugins' params, as they registered them.
func pluginsPage() (string, error) {
	var b strings.Builder
	b.WriteString("# Plugins\n\n" + generated)
	b.WriteString("`-plugin name=type:params`, the params in this order, separated by commas, or by name in any order: `interval=60s,address=192.168.1.1,...`. The optional ones at the end can be left out. A comma in a value is written `\\,`, and a backslash before a comma or another backslash `\\\\`. See [plugins](../plugins.md).\n")
	for _, name := range plugins.Types() {
		fields, err := plugins.Fields(name)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "\n## %s\n\n%s\n\n| Param | |\n|---|---|\n", name, pluginTypes[name])
		for _, f := range fields {
			desc := f.Description
			if f.Required {
				desc = "**Required.** " + desc
			}
			fmt.Fprintf(&b, "| `%s` | %s |\n", f.Name, cell(desc))
		}
	}
	return b.String(), nil
}

func sortedKeys(m map[string]string) []string {
	return slices.Sorted(maps.Keys(m))
}

// The reference pages are those the code makes: after changing a flag or a plugin's params,
// go test ./cmd/ipv6disc -update.
func TestReferenceUpToDate(t *testing.T) {
	pluginsRef, err := pluginsPage()
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"cli.md": cliPage(), "plugins.md": pluginsRef} {
		path = filepath.Join("..", "..", "docs", "reference", path)
		if *update {
			if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != want {
			t.Errorf("%s is behind the code: go test ./cmd/ipv6disc -update", path)
		}
	}
	for _, name := range plugins.Types() {
		if pluginTypes[name] == "" {
			t.Errorf("plugin %s: no description in pluginTypes", name)
		}
		fields, _ := plugins.Fields(name)
		for _, f := range fields {
			if f.Description == "" {
				t.Errorf("plugin %s, %s: no description", name, f.Name)
			}
		}
	}
}
