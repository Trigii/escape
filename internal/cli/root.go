// Package cli wires the stdlib flag package into a small subcommand
// router. We deliberately avoid Cobra/urfave-cli to keep the binary
// dependency-free — a security tool should be auditable end to end.
package cli

import (
	"fmt"
	"io"
	"os"
)

// Run is the entry point invoked from cmd/escape/main.go. It returns
// the desired process exit code so main can stay tiny and testable.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "scan":
		return runScan(rest, stdout, stderr)
	case "list-checks":
		return runListChecks(rest, stdout, stderr)
	case "explain":
		return runExplain(rest, stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, Banner)
		fmt.Fprintf(stdout, "  version: %s\n", Version)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", cmd)
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	const usage = `escape — read-only container & Kubernetes audit tool

USAGE
    escape <command> [flags]

COMMANDS
    scan          Run audit checks against the current environment
    list-checks   Print every registered check
    explain       Print metadata for one or more check IDs (no execution)
    version       Print version info
    help          Show this help

GLOBAL EXAMPLES
    escape scan
    escape scan --output html --output-file report.html
    escape scan --output sarif --output-file findings.sarif --fail-on high
    escape scan --module container,kubernetes --min-severity high
    escape scan --only-failures
    escape scan --id "host.*"
    escape list-checks --output json
    escape explain container.privileged host.proc_kcore

Run "escape <command> --help" for command-specific options.
`
	fmt.Fprint(w, usage)
}

// fail is a small helper used by the subcommands.
func fail(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "escape: "+format+"\n", args...)
	return 1
}

// openOutput returns w (or a created file if path is non-empty) and a
// closer suitable for `defer`. It is shared between subcommands.
func openOutput(path string, fallback io.Writer) (io.Writer, func() error, error) {
	if path == "" {
		return fallback, func() error { return nil }, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}
