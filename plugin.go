package ipv6disc

// Plugin is the interface that must be implemented by discovery plugins.
type Plugin interface {
	// Name returns the name of the plugin.
	Name() string
	// Discover is called periodically to perform host discovery.
	// It should update the provided state with any discovered hosts.
	Discover(state *State) error
	// Stats returns the current statistics for the plugin.
	Stats() map[string]any
}
