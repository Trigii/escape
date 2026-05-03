package host

import (
	"context"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

type cgroupReleaseCheck struct{ check.Base }

// On cgroups v1 with write access, an attacker could once trigger
// CVE-2022-0492-style escapes by abusing release_agent. This check
// reports whether release_agent is writable from inside the container,
// without performing the abuse.
func (c *cgroupReleaseCheck) Run(ctx context.Context) check.Result {
	data, err := DefaultFS.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return check.NewError(c, err)
	}
	var ev []string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		// We're looking for lines whose fs type is cgroup (v1) and that
		// are mounted rw. Mountinfo splits options around " - ".
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left := strings.Fields(parts[0])
		right := strings.Fields(parts[1])
		if len(left) < 6 || len(right) < 1 {
			continue
		}
		if right[0] == "cgroup" && strings.Contains(left[5], "rw") {
			ev = append(ev, "writable cgroup v1 mount: "+left[4])
		}
	}
	if len(ev) == 0 {
		return check.NewPass(c)
	}
	return check.NewFail(c, ev,
		"Mount cgroup hierarchies read-only inside the workload, or rely on cgroup v2 (which lacks the release_agent escape primitive).")
}

func init() {
	engine.Register(&cgroupReleaseCheck{Base: check.Base{
		IDValue:          "host.cgroup.writable_v1",
		NameValue:        "Writable cgroup v1 hierarchy",
		ModuleValue:      "host",
		SeverityValue:    check.SeverityHigh,
		DescriptionValue: "Reports writable cgroup v1 mounts, the prerequisite for the classic release_agent escape pattern. The check is read-only and never writes to release_agent.",
		ReferencesValue: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2022-0492",
		},
	}})
}
