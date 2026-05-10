package chains

import (
	"github.com/tristanvaquero/escape/pkg/check"
	"github.com/tristanvaquero/escape/pkg/exploit"
)

// suidNoNewPrivs — when no_new_privs is OFF and the workload runs as
// non-root, any setuid binary inside the image is an in-container
// privilege-escalation path (linpeas-style).
type suidNoNewPrivs struct{ exploit.Base }

func (c *suidNoNewPrivs) Matches(results []check.Result) *exploit.Match {
	hasNNP := exploit.HasFailedID(results, "container.no_new_privs")
	if !hasNNP {
		return nil
	}
	// Only interesting if we're NOT already root.
	if exploit.HasFailedID(results, "container.user.root") {
		return nil
	}
	return &exploit.Match{
		ChainID:    c.ID(),
		Required:   []string{"container.no_new_privs"},
		Confidence: "low",
		Evidence:   []string{"no_new_privs is disabled and the workload is not running as root — suid escalation path may exist."},
	}
}

func (c *suidNoNewPrivs) Steps(_ *exploit.Match) []exploit.Step {
	return []exploit.Step{
		{
			Title:   "Find suid/sgid binaries inside the container",
			Command: `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null`,
			Note:    "Standard Linux PE recon. Compare against a known-clean inventory of the base image.",
		},
		{
			Title: "Check if any are GTFOBins-listable",
			Command: `# manual: check each candidate against https://gtfobins.github.io/
# offline check pattern:
for b in /usr/bin/find /usr/bin/vim /usr/bin/python*; do
  [[ -u "$b" ]] && echo "$b is suid"
done`,
			Note: "GTFOBins lists suid abuse for almost every common binary.",
		},
	}
}

func init() {
	exploit.Register(&suidNoNewPrivs{Base: exploit.Base{
		IDValue:       "chain.suid_no_new_privs",
		NameValue:     "no_new_privs disabled → suid PE",
		GoalValue:     "Escalate from a non-root user to root inside the container via a suid binary.",
		RiskValue:     exploit.RiskActiveRead,
		SeverityValue: check.SeverityMedium,
		ReferencesValue: []string{
			"https://gtfobins.github.io/",
			"https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html",
		},
		AttackValue: []string{"T1548/001"},
	}})
}
