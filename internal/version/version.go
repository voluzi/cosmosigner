// Package version exposes build metadata, populated via -ldflags at build time.
package version

// Build information. Populated at build time via -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
