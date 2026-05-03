package container

import (
	"context"
	"fmt"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

type seccompCheck struct{ check.Base }

func (c *seccompCheck) Run(ctx context.Context) check.Result {
	data, err := DefaultFS.ReadFile("/proc/self/status")
	if err != nil {
		return check.NewError(c, fmt.Errorf("read /proc/self/status: %w", err))
	}
	mode, ok := parseStatusInt(string(data), "Seccomp:")
	if !ok {
		return check.NewError(c, fmt.Errorf("Seccomp not reported"))
	}
	switch mode {
	case 0:
		return check.NewFail(c,
			[]string{"Seccomp: 0 (disabled)"},
			"Set securityContext.seccompProfile.type: RuntimeDefault, or use --security-opt seccomp=default.json.")
	case 1:
		return check.NewFail(c,
			[]string{"Seccomp: 1 (strict mode — usually a misconfiguration)"},
			"Strict mode is rarely intentional inside a container. Switch to a filter profile.")
	case 2:
		res := check.NewPass(c)
		res.Evidence = []string{"Seccomp: 2 (filter mode active)"}
		return res
	}
	return check.NewError(c, fmt.Errorf("unknown Seccomp mode: %d", mode))
}

// noNewPrivsCheck reports whether the no_new_privs bit is set.
// PR_SET_NO_NEW_PRIVS is a fundamental defence against suid/file-cap escalation.
type noNewPrivsCheck struct{ check.Base }

func (c *noNewPrivsCheck) Run(ctx context.Context) check.Result {
	data, err := DefaultFS.ReadFile("/proc/self/status")
	if err != nil {
		return check.NewError(c, fmt.Errorf("read /proc/self/status: %w", err))
	}
	v, ok := parseStatusInt(string(data), "NoNewPrivs:")
	if !ok {
		return check.NewError(c, fmt.Errorf("NoNewPrivs missing"))
	}
	if v == 1 {
		res := check.NewPass(c)
		res.Evidence = []string{"NoNewPrivs: 1"}
		return res
	}
	return check.NewFail(c,
		[]string{"NoNewPrivs: 0"},
		"Add allowPrivilegeEscalation: false to the securityContext, or pass "+
			"--security-opt=no-new-privileges to docker.")
}

func parseStatusInt(status, key string) (int, bool) {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, key) {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, false
			}
			var v int
			if _, err := fmt.Sscanf(fields[1], "%d", &v); err != nil {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}

func init() {
	engine.Register(&seccompCheck{Base: check.Base{
		IDValue:          "container.seccomp",
		NameValue:        "Seccomp profile applied",
		ModuleValue:      "container",
		SeverityValue:    check.SeverityMedium,
		DescriptionValue: "Reports whether a seccomp filter is active on the workload. Without seccomp, every kernel syscall is reachable.",
		ReferencesValue: []string{
			"https://kubernetes.io/docs/tutorials/security/seccomp/",
		},
	}})
	engine.Register(&noNewPrivsCheck{Base: check.Base{
		IDValue:          "container.no_new_privs",
		NameValue:        "no_new_privs flag",
		ModuleValue:      "container",
		SeverityValue:    check.SeverityMedium,
		DescriptionValue: "Reports the kernel's no_new_privs bit, the foundation for blocking suid-based privilege escalation inside the container.",
		ReferencesValue: []string{
			"https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html",
		},
	}})
}
