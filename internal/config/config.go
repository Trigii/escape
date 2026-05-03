// Package config holds the immutable run-configuration assembled from CLI
// flags (and, in the future, optional config files). Keeping it in its
// own package prevents the CLI layer from leaking flag.FlagSet types
// into modules.
package config

import (
	"time"

	"github.com/tristanvaquero/escape/pkg/check"
)

// OutputFormat is the rendering mode for the final report.
type OutputFormat string

const (
	OutputTable    OutputFormat = "table"
	OutputJSON     OutputFormat = "json"
	OutputMarkdown OutputFormat = "markdown"
)

// Config is the flat, validated configuration consumed by `scan`.
type Config struct {
	Output          OutputFormat
	OutputPath      string // "" means stdout
	NoColor         bool
	MinSeverity     check.Severity
	Modules         []string
	IDs             []string
	Parallelism     int
	PerCheckTimeout time.Duration
	GlobalTimeout   time.Duration
	Verbose         bool
	Quiet           bool
	// FailOn is the threshold above which the process exits non-zero.
	// SeverityInfo means "never fail".
	FailOn check.Severity
}

// Default returns sensible defaults that are safe for shared environments.
func Default() Config {
	return Config{
		Output:          OutputTable,
		MinSeverity:     check.SeverityInfo,
		Parallelism:     8,
		PerCheckTimeout: 5 * time.Second,
		GlobalTimeout:   60 * time.Second,
		FailOn:          check.SeverityInfo, // never fail by default
	}
}
