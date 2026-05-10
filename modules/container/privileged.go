package container

import (
	"context"
	"fmt"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

type privilegedCheck struct{ check.Base }

// A "privileged" container is recognised heuristically by:
//   - CapEff containing the full bitmap (all 1s within the kernel's
//     supported range), AND
//   - the inability to find /sys mounted read-only.
//
// We deliberately avoid making any syscall that could be misread as
// active — we only read /proc and /proc/self/mountinfo.
func (c *privilegedCheck) Run(ctx context.Context) check.Result {
	status, err := DefaultFS.ReadFile("/proc/self/status")
	if err != nil {
		return check.NewError(c, fmt.Errorf("read /proc/self/status: %w", err))
	}
	mask, ok := parseCapEff(string(status))
	if !ok {
		return check.NewError(c, fmt.Errorf("CapEff missing"))
	}
	// 0x000001ffffffffff covers caps 0..40, the modern kernel range.
	const fullCapMask uint64 = 0x000001ffffffffff
	fullCaps := mask&fullCapMask == fullCapMask

	mountinfo, err := DefaultFS.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return check.NewError(c, fmt.Errorf("read mountinfo: %w", err))
	}
	sysWritable := isSysWritable(string(mountinfo))

	var ev []string
	ev = append(ev, fmt.Sprintf("CapEff=0x%016x (full=%v)", mask, fullCaps))
	ev = append(ev, fmt.Sprintf("/sys writable: %v", sysWritable))

	if fullCaps && sysWritable {
		return check.NewFail(c, ev,
			"Remove --privileged from `docker run` or set securityContext.privileged: false. "+
				"Grant only the specific capabilities you need.")
	}
	res := check.NewPass(c)
	res.Evidence = ev
	return res
}

func init() {
	engine.Register(&privilegedCheck{Base: check.Base{
		IDValue:          "container.privileged",
		NameValue:        "Privileged container",
		ModuleValue:      "container",
		SeverityValue:    check.SeverityCritical,
		DescriptionValue: "A privileged container holds the full Linux capability set and a writable /sys, which is functionally equivalent to host root.",
		ReferencesValue: []string{
			"https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
			"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
		},
		AttackValue: []string{"T1611"},
	}})
}
