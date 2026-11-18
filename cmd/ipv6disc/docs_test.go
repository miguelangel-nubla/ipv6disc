package main

import (
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

var update = flag.Bool("update", false, "write the reference pages")

const generated = "<!-- Generated from the code by `go test ./cmd/ipv6disc -update`: edit it, not this page. -->\n\n"

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
		fmt.Fprintf(&b, "\n## %s\n\n%s\n\n| Param | |\n|---|---|\n", name, plugins.Description(name))
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
		if plugins.Description(name) == "" {
			t.Errorf("plugin %s: no description: plugins.Describe", name)
		}
		fields, _ := plugins.Fields(name)
		for _, f := range fields {
			if f.Description == "" {
				t.Errorf("plugin %s, %s: no description", name, f.Name)
			}
		}
	}
}

// Every -plugin of the documentation is one the plugins take.
func TestDocPluginExamples(t *testing.T) {
	root := filepath.Join("..", "..")
	files, _ := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	files = append(files, filepath.Join(root, "README.md"))
	example := regexp.MustCompile(`-plugin "([^"=]+)=([a-z]+):([^"]*)"`)
	checked := 0
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range example.FindAllStringSubmatch(string(content), -1) {
			if _, err := plugins.Create(m[2], m[1], m[3], time.Hour); err != nil {
				t.Errorf("%s: -plugin %q: %v", f, m[0], err)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Error("no example found")
	}
}
