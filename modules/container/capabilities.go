package container

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

// dangerousCaps maps a Linux capability bit number to a human label and
// a short note explaining the abuse pattern. Bits come from
// include/uapi/linux/capability.h in the kernel source.
var dangerousCaps = []struct {
	Bit  uint
	Name string
	Why  string
}{
	{21, "CAP_SYS_ADMIN", "near-root inside the container; many escapes pivot through it"},
	{19, "CAP_SYS_MODULE", "load arbitrary kernel modules — full host compromise"},
	{16, "CAP_SYS_PTRACE", "attach to any process in the container's pid namespace"},
	{8, "CAP_SETUID", "switch UIDs, can defeat user-namespace assumptions"},
	{9, "CAP_SETGID", "switch GIDs"},
	{12, "CAP_NET_ADMIN", "modify routing/firewalling, sniff networks"},
	{1, "CAP_DAC_READ_SEARCH", "bypass DAC for read; classic CVE-2022-0492 building block"},
	{2, "CAP_DAC_OVERRIDE", "bypass DAC for write"},
	{6, "CAP_SETFCAP", "set file capabilities; persistence vector"},
	{36, "CAP_BPF", "load eBPF programs"},
	{37, "CAP_CHECKPOINT_RESTORE", "checkpoint/restore — can read arbitrary process memory"},
	{38, "CAP_PERFMON", "perf_event_open — kernel-mode reads"},
}

type capsCheck struct{ check.Base }

func (c *capsCheck) Run(ctx context.Context) check.Result {
	data, err := DefaultFS.ReadFile("/proc/self/status")
	if err != nil {
		return check.NewError(c, fmt.Errorf("read /proc/self/status: %w", err))
	}
	mask, ok := parseCapEff(string(data))
	if !ok {
		return check.NewError(c, fmt.Errorf("CapEff not found in /proc/self/status"))
	}

	var present []string
	for _, dc := range dangerousCaps {
		if mask&(1<<dc.Bit) != 0 {
			present = append(present, fmt.Sprintf("%s (%s)", dc.Name, dc.Why))
		}
	}
	if len(present) == 0 {
		res := check.NewPass(c)
		res.Evidence = []string{fmt.Sprintf("CapEff=0x%016x — no dangerous bits set", mask)}
		return res
	}
	evidence := append([]string{fmt.Sprintf("CapEff=0x%016x", mask)}, present...)
	return check.NewFail(c, evidence,
		"Drop capabilities you don't need (--cap-drop=ALL then --cap-add only the strictly required) "+
			"or set securityContext.capabilities.drop: [\"ALL\"] in Kubernetes.")
}

func parseCapEff(status string) (uint64, bool) {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, false
			}
			v, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}

func init() {
	engine.Register(&capsCheck{Base: check.Base{
		IDValue:          "container.capabilities.dangerous",
		NameValue:        "Dangerous Linux capabilities present",
		ModuleValue:      "container",
		SeverityValue:    check.SeverityHigh,
		DescriptionValue: "Inspects CapEff in /proc/self/status and flags any capability commonly used as a stepping stone to container escape.",
		ReferencesValue: []string{
			"https://man7.org/linux/man-pages/man7/capabilities.7.html",
			"https://attack.mitre.org/techniques/T1611/",
		},
		AttackValue: []string{"T1611"},
		CVEValue:    []string{"CVE-2022-0492"},
	}})
}
