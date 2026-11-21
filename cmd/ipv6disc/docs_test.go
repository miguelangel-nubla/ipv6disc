package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/config"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

var update = flag.Bool("update", false, "write the reference pages")

const generated = "<!-- Generated from the code by `go test ./cmd/ipv6disc -update`: edit it, not this page. -->\n\n"

func cell(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// cliPage is the reference of the flags, as -h lists them.
func cliPage() string {
	var b strings.Builder
	b.WriteString("# Flags\n\n" + generated)
	b.WriteString("| Flag | Default | |\n|---|---|---|\n")
	flag.VisitAll(func(f *flag.Flag) {
		if f.Name == "update" || strings.HasPrefix(f.Name, "test.") {
			return
		}
		def := f.DefValue
		if def == "" {
			def = "-"
		} else {
			def = "`" + def + "`"
		}
		fmt.Fprintf(&b, "| `-%s` | %s | %s |\n", f.Name, def, cell(f.Usage))
	})
	b.WriteString("\nEverything else is in the configuration file: the families, the protocols, the names, the interfaces, the lifetimes, the plugins and the level of the log. Its keys are in the [configuration reference](configuration.md). A flag there is none of is an error, as each of those the command had before the file.\n")
	b.WriteString("\nA boolean flag is turned off as `-live=false`, not `-live false`: a word that is no flag, nor a flag's value, is an error.\n")
	return b.String()
}

// pluginsPage is the reference of the plugins' fields, as they registered them.
func pluginsPage() (string, error) {
	var b strings.Builder
	b.WriteString("# Plugins\n\n" + generated)
	b.WriteString("Each plugin is a key of `plugins` in the [configuration file](configuration.md#plugins), its name, with its `type` and the fields of that type. See [plugins](../plugins.md).\n")
	b.WriteString("\n```yaml\nplugins:\n  router:\n    type: linux\n    interval: 60s\n    address: 192.168.1.1\n    username: root\n    identity_file: /key\n```\n")
	b.WriteString("\nA field is a string, in quotes when YAML would read it as something else, as a password of digits, but those that say otherwise. From Go, `plugins.Create` takes them as its params: in this order, separated by commas, or by name in any order, `interval=60s,address=192.168.1.1,...`, where a comma in a value is written `\\,`, and a backslash before a comma or another backslash `\\\\`.\n")
	for _, name := range plugins.Types() {
		fields, err := plugins.Fields(name)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "\n## %s\n\n%s\n\n| Field | Takes | |\n|---|---|---|\n", name, plugins.Description(name))
		for _, f := range fields {
			desc := f.Description
			if f.Required {
				desc = "**Required.** " + desc
			}
			takes := f.Type
			if takes == "" {
				takes = "string"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", f.Name, takes, cell(desc))
		}
	}
	return b.String(), nil
}

// object is a JSON object with its keys in the order they are written, which a map forgets.
type object struct {
	keys   []string
	values map[string]json.RawMessage
}

func (o *object) UnmarshalJSON(b []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(b))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return fmt.Errorf("not an object: %s", b)
	}
	o.values = make(map[string]json.RawMessage)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		o.keys = append(o.keys, key.(string))
		o.values[key.(string)] = value
	}
	return nil
}

// property is what the reference tells of a key of the schema.
type property struct {
	Type        string           `json:"type"`
	Ref         string           `json:"$ref"`
	Description string           `json:"description"`
	Default     *json.RawMessage `json:"default"`
	Enum        []string         `json:"enum"`
	Minimum     *int             `json:"minimum"`
	Maximum     *int             `json:"maximum"`
	Properties  *object          `json:"properties"`
}

func (p property) takes() string {
	switch {
	case p.Ref == "#/$defs/duration":
		return "duration"
	case p.Ref == "#/$defs/stringList":
		return "list, or comma separated"
	case len(p.Enum) > 0:
		return "`" + strings.Join(p.Enum, "`, `") + "`"
	case p.Minimum != nil && p.Maximum != nil:
		return fmt.Sprintf("%s, %d to %d", p.Type, *p.Minimum, *p.Maximum)
	case p.Type == "object":
		return "mapping"
	}
	return p.Type
}

func (p property) def() string {
	if p.Default == nil {
		return "-"
	}
	return "`" + strings.Trim(string(*p.Default), `"`) + "`"
}

// table writes the keys of a mapping of the schema, each with what it takes, its default and
// what it is: prefix before each, as "ndp." before the keys of a protocol.
func table(b *strings.Builder, prefix string, properties *object) error {
	for _, key := range properties.keys {
		var p property
		if err := json.Unmarshal(properties.values[key], &p); err != nil {
			return fmt.Errorf("%s%s: %w", prefix, key, err)
		}
		fmt.Fprintf(b, "| `%s%s` | %s | %s | %s |\n", prefix, key, p.takes(), p.def(), cell(p.Description))
	}
	return nil
}

const tableHead = "| Key | Takes | Default | |\n|---|---|---|---|\n"

// configPage is the reference of the configuration file, as its schema has it.
func configPage() (string, error) {
	var root property
	if err := json.Unmarshal(config.Schema(), &root); err != nil {
		return "", err
	}
	sub := func(key string) (property, error) {
		var p property
		err := json.Unmarshal(root.Properties.values[key], &p)
		if err == nil && p.Properties == nil {
			err = fmt.Errorf("the schema has no keys of %s", key)
		}
		return p, err
	}

	var b strings.Builder
	b.WriteString("# Configuration reference\n\n" + generated)
	b.WriteString("The configuration file is YAML, or JSON, given as `ipv6disc -config_file discovery.yaml`. Without the flag no file is read, and every key has its default: IPv6 is discovered, by the protocols that find hosts. Every key is optional. A duration is `90s`, `1m30s`, `4h`, or a number of seconds. A key there is none of, a key written twice, and a value of another type than its key takes, are errors at start, each with where it is and what there is; so is a second document after a `---`. The schema is [`pkg/config/schema.json`](../../pkg/config/schema.json), and the [discovery](../discovery.md) page says what each key does.\n")

	b.WriteString("\n## Top level\n\n" + root.Description + "\n\n" + tableHead)
	if err := table(&b, "", root.Properties); err != nil {
		return "", err
	}

	for _, section := range []struct{ title, key string }{{"IPv6", "ipv6"}, {"IPv4", "ipv4"}, {"Hostnames", "hostnames"}} {
		p, err := sub(section.key)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "\n## %s\n\n`%s`\n\n%s\n\n%s", section.title, section.key, p.Description, tableHead)
		if err := table(&b, "", p.Properties); err != nil {
			return "", err
		}
	}

	protocols, err := sub("protocols")
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "\n## Protocols\n\n`protocols`\n\n%s\n\n```yaml\nprotocols:\n  mdns:\n    enabled: true\n    ask: false\n  arp-sweep:\n    enabled: false\n```\n", protocols.Description)
	for _, name := range protocols.Properties.keys {
		var p property
		if err := json.Unmarshal(protocols.Properties.values[name], &p); err != nil || p.Properties == nil {
			return "", fmt.Errorf("the protocol %s: %v", name, err)
		}
		fmt.Fprintf(&b, "\n### %s\n\n`protocols.%s`\n\n%s\n\n%s", name, name, p.Description, tableHead)
		if err := table(&b, "", p.Properties); err != nil {
			return "", err
		}
	}

	var pluginsProperty property
	if err := json.Unmarshal(root.Properties.values["plugins"], &pluginsProperty); err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "\n## Plugins\n\n`plugins.<name>`\n\n%s\n\nEach has its `type`, one of `%s`, and the fields of that type, which the [plugins reference](plugins.md) lists.\n", pluginsProperty.Description, strings.Join(plugins.Types(), "`, `"))
	return b.String(), nil
}

// The reference pages are those the code makes: after changing a flag, the schema of the
// configuration or a plugin's fields, go test ./cmd/ipv6disc -update.
func TestReferenceUpToDate(t *testing.T) {
	pluginsRef, err := pluginsPage()
	if err != nil {
		t.Fatal(err)
	}
	configRef, err := configPage()
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"cli.md": cliPage(), "plugins.md": pluginsRef, "configuration.md": configRef} {
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
	// Every protocol the library has is in the page, with its switch.
	for _, protocol := range ipv6disc.ProtocolNames() {
		if !strings.Contains(configRef, "\n### "+protocol+"\n\n`protocols."+protocol+"`\n") {
			t.Errorf("the configuration reference has no protocol %s", protocol)
		}
	}
}

// parses tells whether a configuration of the documentation is one the command takes: on a
// system that can't run what hears frames, one that enables it is refused for that alone.
func parses(content []byte) error {
	_, err := config.Parse(content)
	if err == nil || runtime.GOOS == "linux" {
		return err
	}
	for _, line := range strings.Split(err.Error(), "\n") {
		if !strings.HasSuffix(line, "this system can't run it: it needs Linux") {
			return err
		}
	}
	return nil
}

// Every configuration the documentation shows is one the command takes, whole: each block of
// YAML of the pages, and of the README.
func TestDocConfigExamples(t *testing.T) {
	root := filepath.Join("..", "..")
	files, _ := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	reference, _ := filepath.Glob(filepath.Join(root, "docs", "reference", "*.md"))
	files = append(append(files, reference...), filepath.Join(root, "README.md"))
	example := regexp.MustCompile("(?s)```yaml\n(.*?)```")
	checked := 0
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range example.FindAllSubmatch(content, -1) {
			if err := parses(m[1]); err != nil {
				t.Errorf("%s:\n%s\n%v", f, m[1], err)
			}
			checked++
		}
		// No flag the command no longer has is left in the pages.
		for _, old := range regexp.MustCompile("`-(ipv[46]|hostnames|plugin|lifetime|rediscover|interfaces|exclude_interfaces|log_level)[a-z_]*[ =`]").FindAll(content, -1) {
			t.Errorf("%s still has the flag %s", f, old)
		}
	}
	if checked < 10 {
		t.Errorf("%d examples found: the pages show more", checked)
	}
}

// The example of the release is a configuration the command takes, and shows every key there
// is: each of the top level, and each protocol.
func TestExampleConfig(t *testing.T) {
	content, err := os.ReadFile("example.config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := parses(content); err != nil {
		t.Fatal(err)
	}
	var root property
	if err := json.Unmarshal(config.Schema(), &root); err != nil {
		t.Fatal(err)
	}
	for _, key := range root.Properties.keys {
		if !regexp.MustCompile(`(?m)^#? ?` + key + `:`).Match(content) {
			t.Errorf("the example has no %s", key)
		}
	}
	for _, protocol := range ipv6disc.ProtocolNames() {
		if !regexp.MustCompile(`(?m)^#?  ` + protocol + `:`).Match(content) {
			t.Errorf("the example has no protocol %s", protocol)
		}
	}
	// What it turns on is on: it is no copy of the defaults.
	file, _ := config.Parse(content)
	if !file.IPv4.Enabled || !file.Hostnames.Enabled || !file.Protocols.MDNS.Enabled || len(file.Plugins) != 0 {
		t.Errorf("the example: IPv4 %v, names %v, mDNS %v, %d plugins", file.IPv4.Enabled, file.Hostnames.Enabled, file.Protocols.MDNS.Enabled, len(file.Plugins))
	}
}

// The archives of a release have the example, and every page of the documentation, which the
// example and the README send their reader to: each is matched by one of the files of
// .goreleaser.yaml, where a pattern that matches less than it reads is only a line of a log.
func TestReleaseHasTheDocumentation(t *testing.T) {
	root := filepath.Join("..", "..")
	content, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The files of the archives, each a pattern on a line of its own.
	block := regexp.MustCompile(`(?m)^archives:\n(?:.*\n)*?    files:\n((?:      .*\n)+)`).FindSubmatch(content)
	if block == nil {
		t.Fatal(".goreleaser.yaml has no files of the archives")
	}
	var patterns []string
	for _, m := range regexp.MustCompile(`(?m)^      - (\S+)$`).FindAllSubmatch(block[1], -1) {
		patterns = append(patterns, string(m[1]))
	}
	pages, _ := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	reference, _ := filepath.Glob(filepath.Join(root, "docs", "reference", "*.md"))
	files := append(append(pages, reference...), filepath.Join(root, "README.md"), filepath.Join(root, "cmd", "ipv6disc", "example.config.yaml"))
	if len(pages) < 3 || len(reference) < 3 {
		t.Fatalf("%d pages and %d of the reference found: there are more", len(pages), len(reference))
	}
	for _, f := range files {
		name, err := filepath.Rel(root, f)
		if err != nil {
			t.Fatal(err)
		}
		name = filepath.ToSlash(name)
		// A * of these patterns stays within a directory, as path.Match has it.
		if !slices.ContainsFunc(patterns, func(pattern string) bool {
			ok, _ := path.Match(pattern, name)
			return ok
		}) {
			t.Errorf("%s is in no archive: the files of .goreleaser.yaml are %v", name, patterns)
		}
	}
}
