package cli

import (
	"context"
	"flag"
	"io"
	"strings"
	"time"

	"github.com/tristanvaquero/escape/internal/config"
	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/internal/logging"
	"github.com/tristanvaquero/escape/internal/output"
	"github.com/tristanvaquero/escape/pkg/check"
)

func runScan(args []string, stdout, stderr io.Writer) int {
	cfg := config.Default()

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		outputFmt   = fs.String("output", "table", "output format: table|json|markdown")
		outputFile  = fs.String("output-file", "", "write output to file instead of stdout")
		noColor     = fs.Bool("no-color", false, "disable ANSI colors in table output")
		minSev      = fs.String("min-severity", "info", "drop findings below this severity")
		modulesFlag = fs.String("module", "", "comma-separated modules to run (container,kubernetes,host,cloud)")
		idsFlag     = fs.String("id", "", "comma-separated check IDs (supports trailing *)")
		parallel    = fs.Int("parallelism", 8, "max in-flight checks")
		perTimeout  = fs.Duration("timeout", 5*time.Second, "per-check timeout")
		globTimeout = fs.Duration("global-timeout", 60*time.Second, "global run timeout (0 = none)")
		verbose     = fs.Bool("verbose", false, "show evidence for passed checks too")
		quiet       = fs.Bool("quiet", false, "suppress logging on stderr")
		failOn      = fs.String("fail-on", "info", "exit non-zero if any failure >= this severity (info=never)")
	)

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Validate + populate cfg.
	switch strings.ToLower(*outputFmt) {
	case "table":
		cfg.Output = config.OutputTable
	case "json":
		cfg.Output = config.OutputJSON
	case "markdown", "md":
		cfg.Output = config.OutputMarkdown
	default:
		return fail(stderr, "invalid --output value: %q", *outputFmt)
	}
	cfg.OutputPath = *outputFile
	cfg.NoColor = *noColor
	if sev, ok := check.ParseSeverity(*minSev); ok {
		cfg.MinSeverity = sev
	} else {
		return fail(stderr, "invalid --min-severity: %q", *minSev)
	}
	if sev, ok := check.ParseSeverity(*failOn); ok {
		cfg.FailOn = sev
	} else {
		return fail(stderr, "invalid --fail-on: %q", *failOn)
	}
	cfg.Modules = splitCSV(*modulesFlag)
	cfg.IDs = splitCSV(*idsFlag)
	cfg.Parallelism = *parallel
	cfg.PerCheckTimeout = *perTimeout
	cfg.GlobalTimeout = *globTimeout
	cfg.Verbose = *verbose
	cfg.Quiet = *quiet

	// Build logger.
	level := logging.LevelInfo
	if *verbose {
		level = logging.LevelDebug
	}
	if *quiet {
		level = logging.LevelError
	}
	log := logging.NewWithWriter(level, stderr)

	// Filter + run.
	filter := engine.Filter{
		Modules:     cfg.Modules,
		IDs:         cfg.IDs,
		MinSeverity: cfg.MinSeverity,
	}
	checks := filter.Apply(engine.All())
	if len(checks) == 0 {
		return fail(stderr, "no checks match the supplied filters")
	}
	log.Infof("running %d checks (parallelism=%d, per-check=%s, global=%s)",
		len(checks), cfg.Parallelism, cfg.PerCheckTimeout, cfg.GlobalTimeout)

	ctx := context.Background()
	if cfg.GlobalTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.GlobalTimeout)
		defer cancel()
	}
	results := engine.Run(ctx, checks, engine.RunnerOptions{
		Parallelism:     cfg.Parallelism,
		PerCheckTimeout: cfg.PerCheckTimeout,
		Logger:          log,
	})

	// Write output.
	w, closer, err := openOutput(cfg.OutputPath, stdout)
	if err != nil {
		return fail(stderr, "open --output-file: %v", err)
	}
	defer func() { _ = closer() }()

	switch cfg.Output {
	case config.OutputTable:
		_ = output.WriteTable(w, results, output.TableOptions{NoColor: cfg.NoColor, Verbose: cfg.Verbose})
	case config.OutputJSON:
		if err := output.WriteJSON(w, results, Version); err != nil {
			return fail(stderr, "write json: %v", err)
		}
	case config.OutputMarkdown:
		if err := output.WriteMarkdown(w, results, Version); err != nil {
			return fail(stderr, "write markdown: %v", err)
		}
	}

	// Compute exit code based on --fail-on.
	if cfg.FailOn == check.SeverityInfo {
		return 0
	}
	for _, r := range results {
		if r.Status == check.StatusFail && r.Severity.AtLeast(cfg.FailOn) {
			return 1
		}
	}
	return 0
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

