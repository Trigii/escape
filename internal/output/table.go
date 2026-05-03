package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/tristanvaquero/escape/pkg/check"
)

// TableOptions tweaks rendering. NoColor is honoured here so the
// renderer stays decoupled from terminal-detection logic.
type TableOptions struct {
	NoColor bool
	Verbose bool
}

// WriteTable renders a list of results as a fixed-width table followed
// by a per-severity summary.
func WriteTable(w io.Writer, results []check.Result, opts TableOptions) error {
	if len(results) == 0 {
		fmt.Fprintln(w, "no checks executed")
		return nil
	}

	color := func(prefix, text string) string {
		if opts.NoColor || prefix == "" {
			return text
		}
		return prefix + text + ansiReset
	}

	// Compute column widths.
	idW, sevW := len("ID"), len("SEVERITY")
	stW, nameW := len("STATUS"), len("CHECK")
	for _, r := range results {
		idW = max(idW, len(r.ID))
		sevW = max(sevW, len(r.SeverityLabel))
		stW = max(stW, len(string(r.Status)))
		nameW = max(nameW, len(r.Name))
	}

	header := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s",
		idW, "ID", sevW, "SEVERITY", stW, "STATUS", nameW, "CHECK")
	if !opts.NoColor {
		header = ansiBold + ansiUnderline + header + ansiReset
	}
	fmt.Fprintln(w, header)

	for _, r := range results {
		sev := color(SeverityColor(r.Severity), padRight(r.SeverityLabel, sevW))
		st := color(StatusColor(r.Status), padRight(string(r.Status), stW))
		fmt.Fprintf(w, "  %-*s  %s  %s  %-*s\n",
			idW, r.ID, sev, st, nameW, r.Name)
		if opts.Verbose || r.Status == check.StatusFail || r.Status == check.StatusError {
			for _, e := range r.Evidence {
				fmt.Fprintf(w, "      %s %s\n", color(ansiDim, "·"), e)
			}
			if r.Recommendation != "" {
				fmt.Fprintf(w, "      %s %s\n", color(ansiCyan, "→"), r.Recommendation)
			}
			if r.Err != "" {
				fmt.Fprintf(w, "      %s %s\n", color(ansiMagenta, "!"), r.Err)
			}
		}
	}

	// Summary footer.
	summary := summarize(results)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s  total=%d pass=%d fail=%d skip=%d error=%d\n",
		color(ansiBold, "Summary:"),
		summary.Total, summary.Pass, summary.Fail, summary.Skip, summary.Error)
	if summary.Fail > 0 {
		bySev := summary.FailBySeverity
		fmt.Fprintf(w, "  %s   critical=%d  high=%d  medium=%d  low=%d  info=%d\n",
			color(ansiBold, "Failed: "),
			bySev[check.SeverityCritical], bySev[check.SeverityHigh],
			bySev[check.SeverityMedium], bySev[check.SeverityLow],
			bySev[check.SeverityInfo])
	}
	return nil
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Summary aggregates Result counts.
type Summary struct {
	Total          int
	Pass           int
	Fail           int
	Skip           int
	Error          int
	FailBySeverity map[check.Severity]int
}

func summarize(results []check.Result) Summary {
	s := Summary{FailBySeverity: map[check.Severity]int{}}
	for _, r := range results {
		s.Total++
		switch r.Status {
		case check.StatusPass:
			s.Pass++
		case check.StatusFail:
			s.Fail++
			s.FailBySeverity[r.Severity]++
		case check.StatusSkip:
			s.Skip++
		case check.StatusError:
			s.Error++
		}
	}
	return s
}
