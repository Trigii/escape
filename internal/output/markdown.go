package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/tristanvaquero/escape/pkg/check"
)

// WriteMarkdown renders an audit-style Markdown report.
//
// Layout:
//
//	# ESCAPE Audit Report
//	## Summary
//	## Findings (grouped by severity, descending)
//	## Skipped / Errored
func WriteMarkdown(w io.Writer, results []check.Result, version string) error {
	fmt.Fprintf(w, "# ESCAPE Audit Report\n\n")
	fmt.Fprintf(w, "_Tool version: `%s` — generated: %s_\n\n", version, time.Now().UTC().Format(time.RFC3339))

	s := summarize(results)
	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Metric | Count |\n|---|---|\n")
	fmt.Fprintf(w, "| Total checks | %d |\n", s.Total)
	fmt.Fprintf(w, "| Passed | %d |\n", s.Pass)
	fmt.Fprintf(w, "| Failed | %d |\n", s.Fail)
	fmt.Fprintf(w, "| Skipped | %d |\n", s.Skip)
	fmt.Fprintf(w, "| Errored | %d |\n\n", s.Error)

	if s.Fail > 0 {
		fmt.Fprintf(w, "### Failures by severity\n\n")
		fmt.Fprintf(w, "| Severity | Count |\n|---|---|\n")
		for _, sev := range []check.Severity{
			check.SeverityCritical, check.SeverityHigh,
			check.SeverityMedium, check.SeverityLow, check.SeverityInfo,
		} {
			fmt.Fprintf(w, "| %s | %d |\n", sev, s.FailBySeverity[sev])
		}
		fmt.Fprintln(w)
	}

	// Group findings by severity desc, then ID asc.
	failed := filter(results, func(r check.Result) bool { return r.Status == check.StatusFail })
	sort.SliceStable(failed, func(i, j int) bool {
		if failed[i].Severity != failed[j].Severity {
			return failed[i].Severity > failed[j].Severity
		}
		return failed[i].ID < failed[j].ID
	})
	if len(failed) > 0 {
		fmt.Fprintf(w, "## Findings\n\n")
		for _, r := range failed {
			fmt.Fprintf(w, "### %s — %s `%s`\n\n", strings.ToUpper(r.SeverityLabel), r.Name, r.ID)
			fmt.Fprintf(w, "- **Module:** %s\n", r.Module)
			fmt.Fprintf(w, "- **Description:** %s\n", r.Description)
			if len(r.Evidence) > 0 {
				fmt.Fprintf(w, "- **Evidence:**\n")
				for _, e := range r.Evidence {
					fmt.Fprintf(w, "    - %s\n", e)
				}
			}
			if r.Recommendation != "" {
				fmt.Fprintf(w, "- **Recommendation:** %s\n", r.Recommendation)
			}
			if len(r.References) > 0 {
				fmt.Fprintf(w, "- **References:**\n")
				for _, ref := range r.References {
					fmt.Fprintf(w, "    - <%s>\n", ref)
				}
			}
			fmt.Fprintln(w)
		}
	} else {
		fmt.Fprintf(w, "## Findings\n\n_No failures._\n\n")
	}

	// Skipped + errored go in their own section to keep the main one focused.
	other := filter(results, func(r check.Result) bool {
		return r.Status == check.StatusSkip || r.Status == check.StatusError
	})
	if len(other) > 0 {
		fmt.Fprintf(w, "## Skipped / Errored\n\n")
		fmt.Fprintf(w, "| ID | Status | Reason |\n|---|---|---|\n")
		for _, r := range other {
			reason := r.Err
			if r.Status == check.StatusSkip && len(r.Evidence) > 0 {
				reason = r.Evidence[0]
			}
			fmt.Fprintf(w, "| `%s` | %s | %s |\n", r.ID, r.Status, reason)
		}
	}
	return nil
}

func filter(in []check.Result, keep func(check.Result) bool) []check.Result {
	out := make([]check.Result, 0, len(in))
	for _, r := range in {
		if keep(r) {
			out = append(out, r)
		}
	}
	return out
}
