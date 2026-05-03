package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/tristanvaquero/escape/internal/engine"
)

// runListChecks prints every registered check, optionally filtered by module.
func runListChecks(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list-checks", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outputFmt := fs.String("output", "table", "output format: table|json")
	module := fs.String("module", "", "filter by module (comma-separated)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	checks := engine.All()
	if *module != "" {
		filt := engine.Filter{Modules: splitCSV(*module)}
		checks = filt.Apply(checks)
	}

	switch strings.ToLower(*outputFmt) {
	case "table":
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tMODULE\tSEVERITY\tNAME")
		for _, c := range checks {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
				c.ID(), c.Module(), c.Severity(), c.Name())
		}
		_ = tw.Flush()
		fmt.Fprintf(stdout, "\n%d checks\n", len(checks))
		return 0
	case "json":
		type entry struct {
			ID          string   `json:"id"`
			Module      string   `json:"module"`
			Severity    string   `json:"severity"`
			Name        string   `json:"name"`
			Description string   `json:"description"`
			References  []string `json:"references,omitempty"`
		}
		out := make([]entry, 0, len(checks))
		for _, c := range checks {
			out = append(out, entry{
				ID: c.ID(), Module: c.Module(),
				Severity: c.Severity().String(), Name: c.Name(),
				Description: c.Description(), References: c.References(),
			})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return ifErr(enc.Encode(out), stderr, 1)
	default:
		return fail(stderr, "invalid --output: %q", *outputFmt)
	}
}

func ifErr(err error, stderr io.Writer, code int) int {
	if err == nil {
		return 0
	}
	fmt.Fprintf(stderr, "escape: %v\n", err)
	return code
}

