package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/internal/output"
)

// runExplain prints detailed information about one or more registered
// checks WITHOUT running them. Useful when triaging a finding off a
// captured report, or browsing the catalogue for relevant checks.
func runExplain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	noColor := fs.Bool("no-color", false, "disable ANSI colors")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "usage: escape explain <check-id> [check-id ...]")
		fmt.Fprintln(stderr, "       escape explain container.privileged k8s.sa.token")
		return 2
	}

	all := engine.All()
	color := func(prefix, text string) string {
		if *noColor || prefix == "" {
			return text
		}
		return prefix + text + "\x1b[0m"
	}

	exitCode := 0
	for _, want := range rest {
		var matches []int
		for i, c := range all {
			if c.ID() == want ||
				(strings.HasSuffix(want, "*") && strings.HasPrefix(c.ID(), strings.TrimSuffix(want, "*"))) {
				matches = append(matches, i)
			}
		}
		if len(matches) == 0 {
			fmt.Fprintf(stderr, "no check matches %q\n", want)
			exitCode = 1
			continue
		}
		for _, idx := range matches {
			c := all[idx]
			fmt.Fprintln(stdout, color("\x1b[1m\x1b[4m", c.ID()))
			fmt.Fprintf(stdout, "  Name:        %s\n", c.Name())
			fmt.Fprintf(stdout, "  Module:      %s\n", c.Module())
			fmt.Fprintf(stdout, "  Severity:    %s\n",
				color(output.SeverityColor(c.Severity()), c.Severity().String()))
			fmt.Fprintf(stdout, "  Description: %s\n", c.Description())
			if refs := c.References(); len(refs) > 0 {
				fmt.Fprintln(stdout, "  References:")
				for _, r := range refs {
					fmt.Fprintf(stdout, "    - %s\n", r)
				}
			}
			fmt.Fprintln(stdout)
		}
	}
	return exitCode
}
