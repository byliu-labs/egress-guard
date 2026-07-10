package config

import _ "embed"

//go:embed defaults_embedded.toml
var defaultsTOML string

// LoadDefaults returns the bundled default allowlist embedded into the binary.
func LoadDefaults() (Resolved, error) {
	return LoadFromString(defaultsTOML)
}
