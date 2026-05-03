package engine

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/tristanvaquero/escape/internal/logging"
	"github.com/tristanvaquero/escape/pkg/check"
)

// RunnerOptions controls execution semantics.
type RunnerOptions struct {
	// Parallelism caps simultaneous in-flight checks. <=0 means unlimited.
	Parallelism int
	// PerCheckTimeout aborts a single check that exceeds this budget.
	// Zero disables the per-check timeout.
	PerCheckTimeout time.Duration
	// Logger receives per-check progress events; nil is a no-op.
	Logger *logging.Logger
}

// Run executes the supplied checks concurrently and returns the results
// sorted by ID. The parent context cancels the entire run; PerCheckTimeout
// cancels an individual check without aborting siblings.
func Run(ctx context.Context, checks []check.Check, opts RunnerOptions) []check.Result {
	if opts.Logger == nil {
		opts.Logger = logging.Discard()
	}
	results := make([]check.Result, len(checks))

	var sem chan struct{}
	if opts.Parallelism > 0 {
		sem = make(chan struct{}, opts.Parallelism)
	}

	var wg sync.WaitGroup
	for i, c := range checks {
		i, c := i, c
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sem != nil {
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					results[i] = check.NewError(c, ctx.Err())
					return
				}
			}
			results[i] = runOne(ctx, c, opts)
		}()
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results
}

func runOne(parent context.Context, c check.Check, opts RunnerOptions) check.Result {
	ctx := parent
	cancel := func() {}
	if opts.PerCheckTimeout > 0 {
		ctx, cancel = context.WithTimeout(parent, opts.PerCheckTimeout)
	}
	defer cancel()

	start := time.Now()
	opts.Logger.Debugf("running check %s", c.ID())

	// Recover from panics inside checks so a single bad implementation
	// does not abort the whole audit.
	var (
		res check.Result
		rec interface{}
	)
	func() {
		defer func() { rec = recover() }()
		res = c.Run(ctx)
	}()
	if rec != nil {
		res = check.NewError(c, fmt.Errorf("panic: %v", rec))
	}

	res.StartedAt = start
	res.Duration = time.Since(start)
	if res.SeverityLabel == "" {
		res.SeverityLabel = res.Severity.String()
	}
	if res.ID == "" {
		// Defensive: a check returned a zero-value Result.
		res.ID = c.ID()
		res.Name = c.Name()
		res.Module = c.Module()
		res.Description = c.Description()
		res.Severity = c.Severity()
		res.SeverityLabel = c.Severity().String()
		if res.Status == "" {
			res.Status = check.StatusError
			res.Err = "check returned empty result"
		}
	}
	opts.Logger.Debugf("check %s -> %s (%s)", c.ID(), res.Status, res.Duration)
	return res
}
