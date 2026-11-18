package plugins

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

type Factory func(name string, config string, lifetime time.Duration) (ipv6disc.Plugin, error)

// Field is a param of a plugin type, by name.
type Field struct {
	Name     string
	Required bool
	// What it is, for the documentation.
	Description string
}

type registered struct {
	factory     Factory
	fields      []Field
	description string
}

var (
	registry = make(map[string]registered)
	mu       sync.RWMutex
)

// Register makes a plugin type available to Create. fields are its params, in their order, so
// that they can also be given by name: "interval=60s,address=192.0.2.1,...".
func Register(name string, factory Factory, fields ...Field) {
	mu.Lock()
	defer mu.Unlock()
	registry[name] = registered{factory: factory, fields: fields, description: registry[name].description}
}

// Describe says what a plugin type reads, and how, for the documentation.
func Describe(typeName, description string) {
	mu.Lock()
	defer mu.Unlock()
	r := registry[typeName]
	r.description = description
	registry[typeName] = r
}

// Description returns what Describe said of a plugin type.
func Description(typeName string) string {
	mu.RLock()
	defer mu.RUnlock()
	return registry[typeName].description
}

// Types returns the plugin types registered.
func Types() []string {
	mu.RLock()
	defer mu.RUnlock()
	return slices.Sorted(maps.Keys(registry))
}

// Fields returns the params of a plugin type, in their order.
func Fields(typeName string) ([]Field, error) {
	mu.RLock()
	defer mu.RUnlock()
	r, ok := registry[typeName]
	if !ok {
		return nil, fmt.Errorf("plugin %s not found", typeName)
	}
	return slices.Clone(r.fields), nil
}

// FieldParams turns a plugin's params given by name into its params in order, as its factory
// takes them. A name the type doesn't have is an error; the optional params left out are left
// out, the first four always given.
func FieldParams(typeName string, values map[string]string) (string, error) {
	fields, err := Fields(typeName)
	if err != nil {
		return "", err
	}
	names := make([]string, len(fields))
	var missing []string
	for i, f := range fields {
		names[i] = f.Name
		if f.Required && values[f.Name] == "" {
			missing = append(missing, f.Name)
		}
	}
	var unknown []string
	for name := range values {
		if !slices.Contains(names, name) {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return "", fmt.Errorf("a %s plugin has no %s: its params are %s", typeName, strings.Join(unknown, ", "), strings.Join(names, ", "))
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("a %s plugin needs %s", typeName, strings.Join(missing, ", "))
	}
	ordered := make([]string, len(fields))
	for i, name := range names {
		ordered[i] = values[name]
	}
	for len(ordered) > 4 && ordered[len(ordered)-1] == "" {
		ordered = ordered[:len(ordered)-1]
	}
	return JoinParams(ordered...), nil
}

// byName tells whether params are given by name: their first is a name, as "interval", and "=".
// A positional first param, an interval, never has one. A name the type doesn't have is then told,
// rather than taken for an interval.
func byName(params string) bool {
	first, _, found := strings.Cut(SplitParams(params)[0], "=")
	return found && first != "" && strings.Trim(first, "abcdefghijklmnopqrstuvwxyz_") == ""
}

// Create makes a plugin of the type, with its params in order, or by name.
func Create(typeName string, name string, config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
	mu.RLock()
	r, ok := registry[typeName]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("plugin %s not found", typeName)
	}
	if byName(config) {
		values := make(map[string]string)
		for i, part := range SplitParams(config) {
			key, value, found := strings.Cut(part, "=")
			if !found {
				// Not the part itself: it can be a piece of a password.
				return nil, fmt.Errorf("plugin %s: param %d isn't name=value, as the first is (a comma in a value is \\,)", name, i+1)
			}
			if _, twice := values[key]; twice {
				return nil, fmt.Errorf("plugin %s: %s given twice", name, key)
			}
			values[key] = value
		}
		var err error
		if config, err = FieldParams(typeName, values); err != nil {
			return nil, err
		}
	}
	return r.factory(name, config, lifetime)
}
