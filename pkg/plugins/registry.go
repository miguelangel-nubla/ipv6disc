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

type registered struct {
	factory Factory
	fields  []string
}

var (
	registry = make(map[string]registered)
	mu       sync.RWMutex
)

// Register makes a plugin type available to Create. fields names its params, in their order, so
// that they can also be given by name: "interval=60s,address=192.0.2.1,...".
func Register(name string, factory Factory, fields ...string) {
	mu.Lock()
	defer mu.Unlock()
	registry[name] = registered{factory, fields}
}

// Types returns the plugin types registered.
func Types() []string {
	mu.RLock()
	defer mu.RUnlock()
	return slices.Sorted(maps.Keys(registry))
}

// Fields returns the names of a plugin type's params, in their order.
func Fields(typeName string) ([]string, error) {
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
	var unknown []string
	for name := range values {
		if !slices.Contains(fields, name) {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return "", fmt.Errorf("a %s plugin has no %s: its params are %s", typeName, strings.Join(unknown, ", "), strings.Join(fields, ", "))
	}
	ordered := make([]string, len(fields))
	for i, name := range fields {
		ordered[i] = values[name]
	}
	for len(ordered) > 4 && ordered[len(ordered)-1] == "" {
		ordered = ordered[:len(ordered)-1]
	}
	return JoinParams(ordered...), nil
}

// byName tells whether params are given by name: their first is one of the type's fields
// followed by "=". A positional first param, an interval, never has one.
func byName(params string, fields []string) bool {
	first, _, found := strings.Cut(SplitParams(params)[0], "=")
	return found && slices.Contains(fields, first)
}

// Create makes a plugin of the type, with its params in order, or by name.
func Create(typeName string, name string, config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
	mu.RLock()
	r, ok := registry[typeName]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("plugin %s not found", typeName)
	}
	if byName(config, r.fields) {
		values := make(map[string]string)
		for _, part := range SplitParams(config) {
			key, value, found := strings.Cut(part, "=")
			if !found {
				return nil, fmt.Errorf("plugin %s: %q isn't name=value, as the params before it", name, part)
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
