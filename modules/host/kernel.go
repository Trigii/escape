package host

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

// kcoreCheck is one of the loudest finding ESCAPE can produce: if
// /proc/kcore is readable from inside the workload, the workload can
// read every byte of host kernel memory — including credentials,
// secrets, container tokens, and pointers needed to defeat KASLR.
type kcoreCheck struct{ check.Base }

func (c *kcoreCheck) Run(ctx context.Context) check.Result {
	st, err := DefaultFS.Stat("/proc/kcore")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return check.NewPass(c)
		}
		return check.NewError(c, err)
	}
	// /proc/kcore is always present on Linux when /proc is mounted, but
	// the masking applied by container runtimes hides it. Stat returning
	// success means it's visible. We do NOT open or read it.
	mode := st.Mode()
	return check.NewFail(c,
		[]string{
			"/proc/kcore visible (mode=" + mode.String() + ")",
			"file content intentionally NOT inspected",
		},
		"Container runtimes mask /proc/kcore by default. If you see it, the workload "+
			"is using a custom seccomp/apparmor profile that disables that masking, or "+
			"runs with --privileged. Restore default masking.")
}

// kallsymsCheck reports unrestricted kernel symbol exposure. Useful
// for KASLR bypass when chained with a memory-corruption primitive.
type kallsymsCheck struct{ check.Base }

func (c *kallsymsCheck) Run(ctx context.Context) check.Result {
	data, err := DefaultFS.ReadFile("/proc/kallsyms")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return check.NewPass(c)
		}
		return check.NewError(c, err)
	}
	// Read only the first chunk; we just need a non-zero, non-redacted address.
	// kptr_restrict=2 redacts addresses to "0000000000000000".
	scan := string(data)
	if len(scan) > 4096 {
		scan = scan[:4096]
	}
	if strings.Contains(scan, "0000000000000000 ") {
		res := check.NewPass(c)
		res.Evidence = []string{"kallsyms addresses redacted (kptr_restrict>=1)"}
		return res
	}
	return check.NewFail(c,
		[]string{"kallsyms symbols visible with non-zero addresses"},
		"On the host: echo 1 > /proc/sys/kernel/kptr_restrict (or 2 for stricter). "+
			"Inside containers this should be masked by default.")
}

// modprobePathCheck reports whether /proc/sys/kernel/modprobe is readable
// AND parses to an attacker-controllable path. The classic CVE-2022-0492
// chain ends with overwriting that file; even read access is a useful
// fingerprinting signal.
type modprobePathCheck struct{ check.Base }

func (c *modprobePathCheck) Run(ctx context.Context) check.Result {
	data, err := DefaultFS.ReadFile("/proc/sys/kernel/modprobe")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return check.NewSkip(c, "/proc/sys/kernel/modprobe not exposed")
		}
		return check.NewError(c, err)
	}
	path := strings.TrimSpace(string(data))
	return check.NewFail(c,
		[]string{
			"modprobe path: " + path,
			"if /proc/sys is also writable, this becomes the CVE-2022-0492 escape primitive",
		},
		"Mask /proc/sys/kernel/modprobe in the container. Default seccomp/apparmor profiles do this.")
}

// kernelVersionCheck reports /proc/version. Informational, but a small
// kernel-version-to-known-CVE check would slot in here later.
type kernelVersionCheck struct{ check.Base }

func (c *kernelVersionCheck) Run(ctx context.Context) check.Result {
	data, err := DefaultFS.ReadFile("/proc/version")
	if err != nil {
		return check.NewError(c, err)
	}
	v := strings.TrimSpace(string(data))
	res := check.NewPass(c)
	res.Status = check.StatusFail
	res.Severity = check.SeverityInfo
	res.SeverityLabel = res.Severity.String()
	res.Evidence = []string{v}
	res.Recommendation = "Informational. Cross-reference with vendor CVE feeds."
	return res
}

func init() {
	engine.Register(&kcoreCheck{Base: check.Base{
		IDValue:          "host.proc_kcore",
		NameValue:        "/proc/kcore exposed",
		ModuleValue:      "host",
		SeverityValue:    check.SeverityCritical,
		DescriptionValue: "Detects whether /proc/kcore — a virtual file mapping all of host kernel memory — is visible inside the workload.",
		ReferencesValue: []string{
			"https://man7.org/linux/man-pages/man5/proc.5.html",
		},
	}})
	engine.Register(&kallsymsCheck{Base: check.Base{
		IDValue:          "host.proc_kallsyms",
		NameValue:        "Unredacted /proc/kallsyms",
		ModuleValue:      "host",
		SeverityValue:    check.SeverityMedium,
		DescriptionValue: "Reports whether kernel symbol addresses are exposed (kptr_restrict=0). Useful to attackers for KASLR bypass.",
	}})
	engine.Register(&modprobePathCheck{Base: check.Base{
		IDValue:          "host.modprobe_path",
		NameValue:        "modprobe path readable",
		ModuleValue:      "host",
		SeverityValue:    check.SeverityHigh,
		DescriptionValue: "Reports whether /proc/sys/kernel/modprobe is readable inside the container — a building block for the CVE-2022-0492 family of escapes.",
		ReferencesValue: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2022-0492",
		},
	}})
	engine.Register(&kernelVersionCheck{Base: check.Base{
		IDValue:          "host.kernel.version",
		NameValue:        "Host kernel version",
		ModuleValue:      "host",
		SeverityValue:    check.SeverityInfo,
		DescriptionValue: "Reports /proc/version for cross-referencing with kernel CVE feeds.",
	}})
}
