// Package engine wires together the check registry and the concurrent runner.
//
// Modules register their checks via Register() in their init() function.
// The runner pulls from the global registry, applies user filters,
// and executes the surviving checks concurrently with per-check timeouts.
package engine

import (
	"sort"
	"strings"
	"sync"

	"github.com/tristanvaquero/escape/pkg/check"
)

var (
	mu       sync.RWMutex
	registry = make(map[string]check.Check)
)

// Register adds a check to the global registry. It panics if two
// checks share the same ID — this is a programmer error and is
// caught at process start (init time).
func Register(c check.Check) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[c.ID()]; dup {
		panic("escape: duplicate check ID: " + c.ID())
	}
	registry[c.ID()] = c
}

// All returns every registered check, sorted by ID for deterministic output.
func All() []check.Check {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]check.Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Filter is the set of selectors applied before execution. A zero-value
// Filter selects every registered check.
type Filter struct {
	// Modules, if non-empty, restricts execution to checks whose Module()
	// matches one of the values (case-insensitive).
	Modules []string
	// IDs, if non-empty, restricts execution to checks with matching IDs.
	// Glob-style "*" suffix is supported (e.g. "container.*").
	IDs []string
	// MinSeverity, if non-zero, drops checks whose inherent severity is
	// below this threshold.
	MinSeverity check.Severity
}

// Apply returns the subset of `in` that passes the filter.
func (f Filter) Apply(in []check.Check) []check.Check {
	out := make([]check.Check, 0, len(in))
	mods := lowerAll(f.Modules)
	for _, c := range in {
		if len(mods) > 0 && !contains(mods, strings.ToLower(c.Module())) {
			continue
		}
		if len(f.IDs) > 0 && !matchAny(f.IDs, c.ID()) {
			continue
		}
		if c.Severity() < f.MinSeverity {
			continue
		}
		out = append(out, c)
	}
	return out
}

func lowerAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func matchAny(patterns []string, id string) bool {
	for _, p := range patterns {
		if p == id {
			return true
		}
		if strings.HasSuffix(p, "*") && strings.HasPrefix(id, strings.TrimSuffix(p, "*")) {
			return true
		}
	}
	return false
}
