package ipv6disc

import (
	"context"
)

// Plugin is the interface that must be implemented by discovery plugins.
type Plugin interface {
	// Name returns the name of the plugin.
	Name() string
	// Start starts the plugin. It should block until the context is cancelled.
	Start(ctx context.Context, state *State) error
	// Stats returns the current statistics for the plugin.
	Stats() map[string]any
}
