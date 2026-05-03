// Package check defines the public contract every ESCAPE check implements.
//
// A check is a self-contained, READ-ONLY observation about the runtime
// environment. Checks must not mutate state, exploit findings, or perform
// active probes against third-party systems.
package check

import "strings"

// Severity is the standardized weight assigned to a finding.
type Severity int

const (
	// SeverityInfo is informational — neither good nor bad on its own,
	// but useful context (e.g. "running on EKS").
	SeverityInfo Severity = iota
	// SeverityLow indicates a hardening opportunity with low blast radius.
	SeverityLow
	// SeverityMedium indicates a misconfiguration that meaningfully widens
	// the attack surface but is not directly exploitable on its own.
	SeverityMedium
	// SeverityHigh indicates a misconfiguration that is commonly chained
	// into container/cluster compromise.
	SeverityHigh
	// SeverityCritical indicates a configuration that, on its own, is
	// equivalent to giving the workload host-level capabilities.
	SeverityCritical
)

// String returns the canonical lowercase label.
func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	case SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

// ParseSeverity parses a case-insensitive label.
// Empty string returns SeverityInfo, false.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit", "c":
		return SeverityCritical, true
	case "high", "h":
		return SeverityHigh, true
	case "medium", "med", "m":
		return SeverityMedium, true
	case "low", "l":
		return SeverityLow, true
	case "info", "i":
		return SeverityInfo, true
	}
	return SeverityInfo, false
}

// AtLeast reports whether s is >= min on the severity ladder.
func (s Severity) AtLeast(min Severity) bool { return s >= min }
