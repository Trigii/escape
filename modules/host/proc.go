// Package host inspects host-namespace artefacts that are visible from
// inside the workload. Findings here are signals of weak isolation:
// they don't prove a kernel-level escape exists, but they map directly
// to the prerequisites of well-known escape techniques.
package host

import (
	"context"
	"fmt"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

type pidNamespaceCheck struct{ check.Base }

func (c *pidNamespaceCheck) Run(ctx context.Context) check.Result {
	// PID 1 inside a container should be the workload's entrypoint,
	// not systemd / init. If we see init/systemd it suggests pid=host.
	data, err := DefaultFS.ReadFile("/proc/1/comm")
	if err != nil {
		return check.NewError(c, fmt.Errorf("read /proc/1/comm: %w", err))
	}
	comm := strings.TrimSpace(string(data))
	if comm == "systemd" || comm == "init" || comm == "launchd" {
		return check.NewFail(c,
			[]string{"/proc/1/comm = " + comm + " (looks like host PID namespace)"},
			"Do not run with hostPID: true / --pid=host. The workload should have its own PID namespace.")
	}
	res := check.NewPass(c)
	res.Evidence = []string{"/proc/1/comm = " + comm}
	return res
}

type procVisibilityCheck struct{ check.Base }

// procVisibilityCheck samples /proc to see how many host-only processes
// are visible. In an isolated PID namespace we expect only the workload
// tree (typically <20 entries).
func (c *procVisibilityCheck) Run(ctx context.Context) check.Result {
	entries, err := DefaultFS.ReadDir("/proc")
	if err != nil {
		return check.NewError(c, fmt.Errorf("read /proc: %w", err))
	}
	pids := 0
	for _, e := range entries {
		// numeric directory names are PIDs
		if e.IsDir() && isAllDigits(e.Name()) {
			pids++
		}
	}
	if pids > 200 {
		return check.NewFail(c,
			[]string{fmt.Sprintf("%d PIDs visible in /proc — likely shares the host PID namespace", pids)},
			"Drop hostPID and confirm the runtime is not configured with --pid=host.")
	}
	res := check.NewPass(c)
	res.Evidence = []string{fmt.Sprintf("%d PIDs visible in /proc", pids)}
	return res
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func init() {
	engine.Register(&pidNamespaceCheck{Base: check.Base{
		IDValue:          "host.pid_namespace",
		NameValue:        "Host PID namespace shared",
		ModuleValue:      "host",
		SeverityValue:    check.SeverityHigh,
		DescriptionValue: "Heuristic detection of hostPID: true based on /proc/1/comm.",
	}})
	engine.Register(&procVisibilityCheck{Base: check.Base{
		IDValue:          "host.proc_visibility",
		NameValue:        "Excessive /proc visibility",
		ModuleValue:      "host",
		SeverityValue:    check.SeverityMedium,
		DescriptionValue: "Counts PIDs visible in /proc; large counts suggest a shared PID namespace.",
	}})
}
