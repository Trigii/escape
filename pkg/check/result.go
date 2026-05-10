package check

import "time"

// Status describes the outcome of a check execution.
type Status string

const (
	// StatusPass means the check ran and the condition is not present.
	StatusPass Status = "pass"
	// StatusFail means the check ran and a finding was identified.
	StatusFail Status = "fail"
	// StatusSkip means the check was not applicable to this environment
	// (e.g. a Kubernetes check on a bare-metal host).
	StatusSkip Status = "skip"
	// StatusError means the check could not be evaluated.
	StatusError Status = "error"
)

// Result is the structured output of a single check execution.
//
// Fields are kept stable so that JSON consumers (CI pipelines, SIEMs)
// can rely on them across versions.
type Result struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	Module         string        `json:"module"`
	Severity       Severity      `json:"severity"`
	SeverityLabel  string        `json:"severity_label"`
	Status         Status        `json:"status"`
	Description    string        `json:"description"`
	Evidence       []string      `json:"evidence,omitempty"`
	Recommendation string        `json:"recommendation,omitempty"`
	References     []string      `json:"references,omitempty"`
	Attack         []string      `json:"attack,omitempty"`
	CVE            []string      `json:"cve,omitempty"`
	Err            string        `json:"error,omitempty"`
	StartedAt      time.Time     `json:"started_at"`
	Duration       time.Duration `json:"duration_ns"`
}

// NewPass returns a Result with Status=pass, no evidence, and the
// given metadata. It is a convenience helper for checks that simply
// observe the absence of a condition.
func NewPass(c Check) Result {
	return Result{
		ID:            c.ID(),
		Name:          c.Name(),
		Module:        c.Module(),
		Severity:      c.Severity(),
		SeverityLabel: c.Severity().String(),
		Status:        StatusPass,
		Description:   c.Description(),
		References:    c.References(),
		Attack:        c.Attack(),
		CVE:           c.CVE(),
	}
}

// NewSkip returns a Result with Status=skip and a human-readable reason.
func NewSkip(c Check, reason string) Result {
	r := NewPass(c)
	r.Status = StatusSkip
	r.Evidence = []string{reason}
	return r
}

// NewFail returns a Result with Status=fail.
func NewFail(c Check, evidence []string, recommendation string) Result {
	r := NewPass(c)
	r.Status = StatusFail
	r.Evidence = evidence
	r.Recommendation = recommendation
	return r
}

// NewError returns a Result with Status=error.
func NewError(c Check, err error) Result {
	r := NewPass(c)
	r.Status = StatusError
	if err != nil {
		r.Err = err.Error()
	}
	return r
}
