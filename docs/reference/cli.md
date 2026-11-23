# Flags

<!-- Generated from the code by `go test ./cmd/ipv6disc -update`: edit it, not this page. -->

| Flag | Default | |
|---|---|---|
| `--config` | - | The configuration file, YAML: the families, the protocols, the names and the plugins. Without it no file is read, and the defaults discover IPv6 |
| `--live` | `false` | Show the state in the terminal, updating, instead of the log |
| `--version` | `false` | Show the version, and exit |

Everything else is in the configuration file: the families, the protocols, the names, the interfaces, the lifetimes, the plugins and the level of the log. Its keys are in the [configuration reference](configuration.md). A flag there is none of is an error, as each of those the command had before the file.

A boolean flag is turned off as `--live=false`, not `--live false`: a word that is no flag, nor a flag's value, is an error.
