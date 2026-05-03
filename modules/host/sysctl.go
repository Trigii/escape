package host

import (
	"context"
	"fmt"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

// sysctlCheck inspects a curated list of /proc/sys entries that reveal
// hardening choices on the host. The values are visible from inside any
// container that hasn't masked /proc/sys (the default mask covers writes
// but reads frequently leak through).
type sysctlCheck struct{ check.Base }

// sysctlEntry: path, expected-safe-value, why it matters.
var sysctls = []struct {
	Path     string
	SafeVal  string // values matching this string are considered hardened
	Reason   string
}{
	{"/proc/sys/kernel/yama/ptrace_scope", "1", "ptrace_scope=0 lets any same-uid process attach via ptrace"},
	{"/proc/sys/kernel/dmesg_restrict", "1", "dmesg_restrict=0 leaks kernel messages to unprivileged users"},
	{"/proc/sys/kernel/kptr_restrict", "1", "kptr_restrict=0 leaks kernel pointers (KASLR bypass aid)"},
	{"/proc/sys/kernel/unprivileged_bpf_disabled", "1", "unprivileged_bpf enabled has historically been a CVE factory"},
	{"/proc/sys/net/core/bpf_jit_harden", "1", "bpf_jit_harden=0 leaves the JIT exposed to spray attacks"},
}

func (c *sysctlCheck) Run(ctx context.Context) check.Result {
	var bad []string
	var checked int
	for _, s := range sysctls {
		data, err := DefaultFS.ReadFile(s.Path)
		if err != nil {
			continue // not exposed → skip silently, don't penalize
		}
		checked++
		val := strings.TrimSpace(string(data))
		if val != s.SafeVal {
			bad = append(bad, fmt.Sprintf("%s = %s (%s)", s.Path, val, s.Reason))
		}
	}
	if checked == 0 {
		return check.NewSkip(c, "no /proc/sys entries readable")
	}
	if len(bad) == 0 {
		res := check.NewPass(c)
		res.Evidence = []string{fmt.Sprintf("%d sysctls checked, all safe", checked)}
		return res
	}
	return check.NewFail(c, bad,
		"Apply these sysctl values on the host (or via a hardened kernel command line).")
}

func init() {
	engine.Register(&sysctlCheck{Base: check.Base{
		IDValue:          "host.sysctl.unsafe",
		NameValue:        "Unsafe host sysctls visible",
		ModuleValue:      "host",
		SeverityValue:    check.SeverityMedium,
		DescriptionValue: "Inspects a curated list of /proc/sys entries (ptrace_scope, dmesg_restrict, kptr_restrict, ...) and flags non-hardened values.",
	}})
}
