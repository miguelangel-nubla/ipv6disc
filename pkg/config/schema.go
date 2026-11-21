package config

import (
	_ "embed"
	"encoding/json"
	"slices"
)

//go:embed schema.json
var schema []byte

// Schema returns the JSON schema of a File: the configuration file of the ipv6disc command.
func Schema() []byte { return slices.Clone(schema) }

// DiscoverySchema returns the JSON schema of a Discovery: that of a File, without what is the
// command's alone. A program that has the discovery among its settings has it for that key.
func DiscoverySchema() []byte {
	var document map[string]any
	if err := json.Unmarshal(schema, &document); err != nil {
		panic(err)
	}
	delete(document["properties"].(map[string]any), "log_level")
	document["title"] = "The discovery"
	discovery, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(discovery, '\n')
}
