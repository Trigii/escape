package check

import "context"

// Check is the contract every audit check implements.
//
// Implementations MUST be:
//   - read-only (no writes, no exec, no network mutations)
//   - safe to call concurrently with other checks
//   - context-aware (return promptly when ctx is cancelled)
//
// A Check is identified by a stable, dotted ID such as
// "container.privileged" or "k8s.sa.token". The ID is the
// public handle used in CLI filters, JSON output, and CI gates.
type Check interface {
	// ID returns the stable identifier of this check.
	ID() string
	// Name returns a short human-readable title.
	Name() string
	// Module returns the high-level group ("container", "kubernetes", ...).
	Module() string
	// Description returns a longer explanation suitable for a report.
	Description() string
	// Severity returns the inherent weight of a positive finding.
	Severity() Severity
	// References returns optional URLs (CIS, MITRE ATT&CK, vendor docs).
	References() []string
	// Run executes the check and returns a populated Result.
	// Implementations should handle their own errors and return them
	// via Result.Err with Status=StatusError rather than panicking.
	Run(ctx context.Context) Result
}

// Base is an embeddable struct that satisfies most of the Check
// interface, leaving only Run() to the concrete implementation.
//
//	type myCheck struct{ check.Base }
//	func (c *myCheck) Run(ctx context.Context) check.Result { ... }
type Base struct {
	IDValue          string
	NameValue        string
	ModuleValue      string
	DescriptionValue string
	SeverityValue    Severity
	ReferencesValue  []string
}

func (b Base) ID() string          { return b.IDValue }
func (b Base) Name() string        { return b.NameValue }
func (b Base) Module() string      { return b.ModuleValue }
func (b Base) Description() string { return b.DescriptionValue }
func (b Base) Severity() Severity  { return b.SeverityValue }
func (b Base) References() []string {
	if b.ReferencesValue == nil {
		return nil
	}
	out := make([]string, len(b.ReferencesValue))
	copy(out, b.ReferencesValue)
	return out
}
