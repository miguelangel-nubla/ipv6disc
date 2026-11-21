// Package config is the configuration of the discovery as a file has it: its YAML form, read
// strictly, with its JSON schema, and what turns it into an ipv6disc.Config and its plugins. The
// ipv6disc command reads a File; a program that has the discovery among its own settings, as
// ipv6ddns does, has a Discovery among them, the same keys.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	goyaml "go.yaml.in/yaml/v2"
	"sigs.k8s.io/yaml"

	"github.com/miguelangel-nubla/ipv6disc"
	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
	// The plugin types, which say their fields.
	_ "github.com/miguelangel-nubla/ipv6disc/pkg/plugins/all"
	"github.com/miguelangel-nubla/ipv6disc/pkg/rdns"
)

// File is the configuration file of the ipv6disc command: the discovery, and what is the
// command's alone.
type File struct {
	Discovery
	// The level of the log: debug, info, warn or error.
	LogLevel string `json:"log_level"`
}

// Discovery is how hosts are discovered, as a configuration writes it: an ipv6disc.Config, and
// the plugins. What a document leaves out stays as it was before it was read: read it into
// DefaultDiscovery.
type Discovery struct {
	// How long an address stays after it was last seen, unless its family says.
	Lifetime Duration `json:"lifetime"`
	// How often the active discovery probes every host. Zero: a third of the shortest lifetime
	// of the families that probe.
	Rediscover Duration `json:"rediscover"`
	// The interfaces the local discovery runs on, and those it doesn't: names, or patterns.
	Interfaces        StringList `json:"interfaces"`
	ExcludeInterfaces StringList `json:"exclude_interfaces"`
	// The families: the switches of all their protocols at once.
	IPv6 Family `json:"ipv6"`
	IPv4 Family `json:"ipv4"`
	// The names of the hosts: how long they stay.
	Hostnames Hostnames `json:"hostnames"`
	// The protocols of the local discovery, each with its switch and its options.
	Protocols Protocols `json:"protocols"`
	// The plugins, which read the tables of routers and other hosts, by name.
	Plugins map[string]Plugin `json:"plugins"`
}

// Family is ipv6disc.Family.
type Family struct {
	Enabled  bool     `json:"enabled"`
	Listen   bool     `json:"listen"`
	Active   bool     `json:"active"`
	Lifetime Duration `json:"lifetime"`
}

// Hostnames is ipv6disc.Hostnames.
type Hostnames struct {
	Lifetime Duration `json:"lifetime"`
}

// Protocols is ipv6disc.Protocols: each protocol by its name, always with its settings, never a
// switch alone.
type Protocols struct {
	NDP       Protocol `json:"ndp"`
	Ping      Protocol `json:"ping"`
	SSDP      Fetching `json:"ssdp"`
	WSD       Fetching `json:"wsd"`
	MDNS      MDNS     `json:"mdns"`
	ARP       Protocol `json:"arp"`
	ARPSweep  ARPSweep `json:"arp-sweep"`
	ARPListen Protocol `json:"arp-listen"`
	DHCP      Protocol `json:"dhcp"`
	LLDP      Protocol `json:"lldp"`
	NetBIOS   Protocol `json:"netbios"`
	LLMNR     Protocol `json:"llmnr"`
	DNS       DNS      `json:"dns"`
}

// Protocol is a protocol with no options.
type Protocol struct {
	Enabled bool `json:"enabled"`
}

// Fetching is SSDP, or WS-Discovery: a protocol that can ask what answers it its name.
type Fetching struct {
	Enabled bool `json:"enabled"`
	Names   bool `json:"names"`
}

// MDNS is ipv6disc.MDNSProtocol.
type MDNS struct {
	Enabled bool `json:"enabled"`
	Ask     bool `json:"ask"`
}

// ARPSweep is ipv6disc.ARPSweepProtocol.
type ARPSweep struct {
	Enabled   bool `json:"enabled"`
	MaxPrefix int  `json:"max_prefix"`
}

// DNS is ipv6disc.DNSProtocol.
type DNS struct {
	Enabled bool    `json:"enabled"`
	Servers Servers `json:"servers"`
}

// Duration is a duration as a configuration writes it: as Go does, 90s or 4h, or a number of
// seconds.
type Duration time.Duration

func (d *Duration) set(path string, raw json.RawMessage) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	wrong := fmt.Errorf("%s: %s is not a duration, as 90s or 4h, nor a number of seconds", path, raw)
	switch value := value.(type) {
	case string:
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return wrong
		}
		*d = Duration(parsed)
	case float64:
		// Beyond what a time.Duration holds, about 292 years, the conversion depends on the
		// machine.
		nanoseconds := value * float64(time.Second)
		if nanoseconds >= math.MaxInt64 || nanoseconds <= math.MinInt64 {
			return wrong
		}
		*d = Duration(nanoseconds)
	default:
		return wrong
	}
	return nil
}

func (d *Duration) UnmarshalJSON(b []byte) error { return decode("", b, reflect.ValueOf(d).Elem()) }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d Duration) String() string { return time.Duration(d).String() }

// StringList is a list of strings: written as a list, or as one string of comma separated values.
type StringList []string

func (l *StringList) set(path string, raw json.RawMessage) error {
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		values = []json.RawMessage{raw}
	}
	*l = nil
	for _, raw := range values {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("%s: %s is not a string, nor a list of them", path, raw)
		}
		for _, v := range strings.Split(value, ",") {
			if v = strings.TrimSpace(v); v != "" {
				*l = append(*l, v)
			}
		}
	}
	return nil
}

func (l *StringList) UnmarshalJSON(b []byte) error {
	return decode("", b, reflect.ValueOf(l).Elem())
}

// Servers are the servers of a protocol, each an address, alone or with its port, the one of an
// IPv6 address in brackets: written as a StringList.
type Servers []netip.AddrPort

func (s *Servers) set(path string, raw json.RawMessage) error {
	var list StringList
	if err := list.set(path, raw); err != nil {
		return err
	}
	*s = nil
	var errs []error
	for _, written := range list {
		server, err := rdns.ParseServer(written)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			continue
		}
		*s = append(*s, server)
	}
	return errors.Join(errs...)
}

func (s Servers) MarshalJSON() ([]byte, error) {
	written := make([]string, len(s))
	for i, server := range s {
		written[i] = server.String()
	}
	return json.Marshal(written)
}

// Plugin is a plugin: its type, and the fields the type has, as plugins.Fields tells them, each
// as it is written in the params of plugins.Create.
type Plugin struct {
	Type   string
	Fields map[string]string
}

func (p *Plugin) set(path string, raw json.RawMessage) error {
	object, err := mapping(path, raw, reflect.TypeFor[Plugin]())
	if err != nil {
		return err
	}
	types := strings.Join(plugins.Types(), ", ")
	rawType, ok := object["type"]
	if !ok {
		return fmt.Errorf("%s: a plugin has a type: one of %s", path, types)
	}
	plugin := Plugin{Fields: make(map[string]string)}
	if json.Unmarshal(rawType, &plugin.Type) != nil {
		return fmt.Errorf("%s: %s is not a string", join(path, "type"), rawType)
	}
	known, err := plugins.Fields(plugin.Type)
	if err != nil {
		return fmt.Errorf("%s: no such type of plugin, %q: they are %s", join(path, "type"), plugin.Type, types)
	}
	names := make([]string, len(known))
	for i, field := range known {
		names[i] = field.Name
	}
	var errs []error
	for _, key := range slices.Sorted(maps.Keys(object)) {
		if key == "type" {
			continue
		}
		i := slices.Index(names, key)
		if i < 0 {
			errs = append(errs, fmt.Errorf("%s: no such field of a %s plugin: it has %s", join(path, key), plugin.Type, strings.Join(names, ", ")))
			continue
		}
		value, err := fieldValue(join(path, key), known[i].Type, object[key])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		plugin.Fields[key] = value
	}
	for _, field := range known {
		if field.Required && plugin.Fields[field.Name] == "" && !slices.ContainsFunc(errs, func(err error) bool {
			return strings.HasPrefix(err.Error(), join(path, field.Name)+":")
		}) {
			errs = append(errs, fmt.Errorf("%s: a %s plugin needs its %s", path, plugin.Type, field.Name))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	*p = plugin
	return nil
}

// fieldValue reads the value of a plugin's field of that type, as its params have it: text.
func fieldValue(path, typ string, raw json.RawMessage) (string, error) {
	switch typ {
	case plugins.FieldBoolean:
		var value bool
		if json.Unmarshal(raw, &value) != nil {
			return "", fmt.Errorf("%s: %s is not true or false", path, raw)
		}
		return strconv.FormatBool(value), nil
	case plugins.FieldDuration:
		var value Duration
		if err := value.set(path, raw); err != nil {
			return "", err
		}
		return value.String(), nil
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		// Not as a number: a password of digits would lose its leading zeros.
		return "", fmt.Errorf("%s: %s is not a string: write it in quotes", path, raw)
	}
	return value, nil
}

func (p Plugin) MarshalJSON() ([]byte, error) {
	object := map[string]any{"type": p.Type}
	known, _ := plugins.Fields(p.Type)
	for name, value := range p.Fields {
		object[name] = value
		if i := slices.IndexFunc(known, func(f plugins.Field) bool { return f.Name == name }); i >= 0 && known[i].Type == plugins.FieldBoolean {
			object[name] = value == "true"
		}
	}
	return json.Marshal(object)
}

// Params returns the fields of the plugin as the params of plugins.Create.
func (p Plugin) Params() (string, error) {
	return plugins.FieldParams(p.Type, p.Fields)
}

// UnmarshalJSON reads the discovery of a document strictly, over what d has: a key it doesn't
// have, and a value of the wrong type, are errors, each with its path and what there is.
func (d *Discovery) UnmarshalJSON(b []byte) error { return decode("", b, reflect.ValueOf(d).Elem()) }

// UnmarshalJSON reads the protocols of a document, as Discovery.UnmarshalJSON does.
func (p *Protocols) UnmarshalJSON(b []byte) error {
	return decode("protocols", b, reflect.ValueOf(p).Elem())
}

// UnmarshalJSON reads the file of the command, as Discovery.UnmarshalJSON does.
func (f *File) UnmarshalJSON(b []byte) error { return decode("", b, reflect.ValueOf(f).Elem()) }

// Default is the configuration of a command run without a file: DefaultDiscovery, logged at
// info.
func Default() File {
	return File{Discovery: DefaultDiscovery(), LogLevel: "info"}
}

// DefaultDiscovery is the discovery of a configuration that says nothing: ipv6disc.DefaultConfig,
// and no plugin.
func DefaultDiscovery() Discovery {
	return fromConfig(ipv6disc.DefaultConfig())
}

func fromConfig(c ipv6disc.Config) Discovery {
	family := func(f ipv6disc.Family) Family {
		return Family{Enabled: f.Enabled, Listen: f.Listen, Active: f.Active, Lifetime: Duration(f.Lifetime)}
	}
	p := c.Protocols
	return Discovery{
		Lifetime: Duration(c.Lifetime), Rediscover: Duration(c.Rediscover),
		Interfaces: c.Interfaces, ExcludeInterfaces: c.ExcludeInterfaces,
		IPv6: family(c.IPv6), IPv4: family(c.IPv4),
		Hostnames: Hostnames{Lifetime: Duration(c.Hostnames.Lifetime)},
		Protocols: Protocols{
			NDP: Protocol(p.NDP), Ping: Protocol(p.Ping),
			SSDP: Fetching{Enabled: p.SSDP.Enabled, Names: p.SSDP.Names},
			WSD:  Fetching{Enabled: p.WSD.Enabled, Names: p.WSD.Names},
			MDNS: MDNS{Enabled: p.MDNS.Enabled, Ask: p.MDNS.Ask},
			ARP:  Protocol(p.ARP), ARPSweep: ARPSweep{Enabled: p.ARPSweep.Enabled, MaxPrefix: p.ARPSweep.MaxPrefix},
			ARPListen: Protocol(p.ARPListen), DHCP: Protocol(p.DHCP), LLDP: Protocol(p.LLDP),
			NetBIOS: Protocol(p.NetBIOS), LLMNR: Protocol(p.LLMNR),
			DNS: DNS{Enabled: p.DNS.Enabled, Servers: p.DNS.Servers},
		},
	}
}

// Config is the discovery as a Worker takes it: all of it but the plugins, which NewPlugins makes.
func (d Discovery) Config() ipv6disc.Config {
	family := func(f Family) ipv6disc.Family {
		return ipv6disc.Family{Enabled: f.Enabled, Listen: f.Listen, Active: f.Active, Lifetime: time.Duration(f.Lifetime)}
	}
	p := d.Protocols
	return ipv6disc.Config{
		Lifetime: time.Duration(d.Lifetime), Rediscover: time.Duration(d.Rediscover),
		Interfaces: d.Interfaces, ExcludeInterfaces: d.ExcludeInterfaces,
		IPv6: family(d.IPv6), IPv4: family(d.IPv4),
		Hostnames: ipv6disc.Hostnames{Lifetime: time.Duration(d.Hostnames.Lifetime)},
		Protocols: ipv6disc.Protocols{
			NDP: ipv6disc.Protocol(p.NDP), Ping: ipv6disc.Protocol(p.Ping),
			SSDP: ipv6disc.SSDPProtocol{Enabled: p.SSDP.Enabled, Names: p.SSDP.Names},
			WSD:  ipv6disc.WSDProtocol{Enabled: p.WSD.Enabled, Names: p.WSD.Names},
			MDNS: ipv6disc.MDNSProtocol{Enabled: p.MDNS.Enabled, Ask: p.MDNS.Ask},
			ARP:  ipv6disc.Protocol(p.ARP), ARPSweep: ipv6disc.ARPSweepProtocol{Enabled: p.ARPSweep.Enabled, MaxPrefix: p.ARPSweep.MaxPrefix},
			ARPListen: ipv6disc.Protocol(p.ARPListen), DHCP: ipv6disc.Protocol(p.DHCP), LLDP: ipv6disc.Protocol(p.LLDP),
			NetBIOS: ipv6disc.Protocol(p.NetBIOS), LLMNR: ipv6disc.Protocol(p.LLMNR),
			DNS: ipv6disc.DNSProtocol{Enabled: p.DNS.Enabled, Servers: p.DNS.Servers},
		},
	}
}

// NewPlugins makes the plugins, in the order of their names, each with the lifetime of the
// discovery: a family's own, when given, is the state's to put in its place.
func (d Discovery) NewPlugins() ([]ipv6disc.Plugin, error) {
	var made []ipv6disc.Plugin
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(d.Plugins)) {
		plugin := d.Plugins[name]
		params, err := plugin.Params()
		if err == nil {
			var p ipv6disc.Plugin
			if p, err = plugins.Create(plugin.Type, name, params, time.Duration(d.Lifetime)); err == nil {
				made = append(made, p)
				continue
			}
		}
		errs = append(errs, fmt.Errorf("plugins.%s: %w", name, err))
	}
	return made, errors.Join(errs...)
}

// Validate tells what of the discovery can't run, every error of it: those of
// ipv6disc.Config.Validate, and those of the plugins, which are made, and dropped, to know. It is
// of a discovery read over DefaultDiscovery, where an option that is zero was written so.
func (d Discovery) Validate() error {
	var errs []error
	// A zero is the default to a Config made by hand: here it was written, as nothing left out
	// is zero in a document read over DefaultDiscovery.
	if sweep := d.Protocols.ARPSweep; sweep.Enabled && sweep.MaxPrefix == 0 {
		errs = append(errs, fmt.Errorf("invalid max_prefix of the %s protocol, 0: it is from %d to %d", ipv6disc.ProtocolARPSweep, ipv6disc.MinSweepPrefix, ipv6disc.MaxSweepPrefix))
	}
	_, err := d.NewPlugins()
	return errors.Join(append(errs, d.Config().Validate(), err)...)
}

// LogLevels are the levels a File's log_level takes.
func LogLevels() []string { return []string{"debug", "info", "warn", "error"} }

// Validate tells what of the file can't run: Discovery.Validate, and a level of the log there is
// none of.
func (f File) Validate() error {
	var err error
	if !slices.Contains(LogLevels(), f.LogLevel) {
		err = fmt.Errorf("log_level: %q is no level of the log: they are %s", f.LogLevel, strings.Join(LogLevels(), ", "))
	}
	return errors.Join(f.Discovery.Validate(), err)
}

// Parse reads a configuration file, YAML, or JSON, which is YAML too: over Default, strictly, and
// validated. An empty one is Default. It is one document: a second is an error.
func Parse(data []byte) (File, error) {
	file := Default()
	document, err := yaml.YAMLToJSONStrict(data)
	if err != nil {
		return file, fmt.Errorf("not YAML: %w", err)
	}
	// Only the first document of several is read: the others would be left out without a word.
	documents := goyaml.NewDecoder(bytes.NewReader(data))
	var first, second any
	if documents.Decode(&first) == nil && documents.Decode(&second) != io.EOF {
		return file, errors.New("the configuration is more than one YAML document: it is one, without a --- after it")
	}
	if err := file.UnmarshalJSON(document); err != nil {
		return file, err
	}
	return file, file.Validate()
}

// Load reads the configuration file at path, as Parse does.
func Load(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Default(), err
	}
	file, err := Parse(data)
	if err != nil {
		return file, fmt.Errorf("%s: %w", path, err)
	}
	return file, nil
}
