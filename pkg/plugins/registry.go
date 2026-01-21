package plugins

import (
	"fmt"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

type Factory func(config string, lifetime time.Duration) (ipv6disc.Plugin, error)

var (
	registry = make(map[string]Factory)
	mu       sync.RWMutex
)

func Register(name string, factory Factory) {
	mu.Lock()
	defer mu.Unlock()
	registry[name] = factory
}

func Create(name string, config string, lifetime time.Duration) (ipv6disc.Plugin, error) {
	mu.RLock()
	defer mu.RUnlock()
	factory, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("plugin %s not found", name)
	}
	return factory(config, lifetime)
}
