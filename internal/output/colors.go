// Package output renders [check.Result] sets as table/JSON/Markdown.
//
// All renderers are stdlib-only — no termtables, no glamour. This keeps
// the binary small and auditable, which matters for a security tool.
package output

import "github.com/tristanvaquero/escape/pkg/check"

// ANSI escape sequences. We keep the palette tight and high-contrast.
const (
	ansiReset     = "\x1b[0m"
	ansiBold      = "\x1b[1m"
	ansiUnderline = "\x1b[4m"
	ansiDim       = "\x1b[2m"

	ansiRed     = "\x1b[31m"
	ansiYellow  = "\x1b[33m"
	ansiGreen   = "\x1b[32m"
	ansiCyan    = "\x1b[36m"
	ansiMagenta = "\x1b[35m"
)

// SeverityColor returns the ANSI prefix that wraps a severity label.
func SeverityColor(s check.Severity) string {
	switch s {
	case check.SeverityCritical:
		return ansiBold + ansiRed
	case check.SeverityHigh:
		return ansiRed
	case check.SeverityMedium:
		return ansiYellow
	case check.SeverityLow:
		return ansiCyan
	case check.SeverityInfo:
		return ansiDim
	}
	return ""
}

// StatusColor highlights pass/fail/skip/error.
func StatusColor(s check.Status) string {
	switch s {
	case check.StatusPass:
		return ansiGreen
	case check.StatusFail:
		return ansiRed
	case check.StatusSkip:
		return ansiDim
	case check.StatusError:
		return ansiMagenta
	}
	return ""
}
