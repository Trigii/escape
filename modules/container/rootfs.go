package container

import (
	"context"
	"fmt"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

type readOnlyRootCheck struct{ check.Base }

// readOnlyRootCheck reports whether the container's root filesystem is
// writable. Read-only root + a tmpfs for /tmp is a strong, cheap defence:
// it neutralises a large class of post-exploitation payloads.
func (c *readOnlyRootCheck) Run(ctx context.Context) check.Result {
	data, err := DefaultFS.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return check.NewError(c, fmt.Errorf("read mountinfo: %w", err))
	}
	for _, m := range parseMountInfo(string(data)) {
		if m.MountPoint == "/" {
			if strings.Contains(m.Options, "ro") && !strings.Contains(m.Options, "rw") {
				res := check.NewPass(c)
				res.Evidence = []string{"/ mounted read-only (" + m.Options + ")"}
				return res
			}
			return check.NewFail(c,
				[]string{"/ mounted read-write (" + m.Options + ")"},
				"Set readOnlyRootFilesystem: true (Kubernetes) or pass --read-only to docker run, "+
					"and mount writable areas (e.g. /tmp, /var/run) as tmpfs.")
		}
	}
	return check.NewSkip(c, "no entry for / in mountinfo")
}

type userNamespaceCheck struct{ check.Base }

// userNamespaceCheck reports whether the workload runs in a user
// namespace. /proc/self/uid_map shows the mapping; the unmapped default
// is "0 0 4294967295" — i.e. root inside == root outside. A non-default
// mapping like "0 100000 65536" means rootless / userns-remap is active.
func (c *userNamespaceCheck) Run(ctx context.Context) check.Result {
	data, err := DefaultFS.ReadFile("/proc/self/uid_map")
	if err != nil {
		return check.NewError(c, err)
	}
	mapping := strings.TrimSpace(string(data))
	if mapping == "" {
		// On some configurations the mapping is empty — still informational.
		return check.NewSkip(c, "uid_map empty")
	}
	fields := strings.Fields(mapping)
	if len(fields) >= 3 && fields[0] == "0" && fields[1] == "0" {
		return check.NewFail(c,
			[]string{"uid_map: " + mapping, "root inside == root on host"},
			"Enable user-namespace remapping: dockerd --userns-remap=default, "+
				"or PSS Restricted with runAsNonRoot: true.")
	}
	res := check.NewPass(c)
	res.Evidence = []string{"uid_map: " + mapping, "user namespace appears to be remapped"}
	return res
}

type sandboxedRuntimeCheck struct{ check.Base }

// sandboxedRuntimeCheck looks for fingerprints of sandboxed runtimes
// (gVisor, Kata, Firecracker). These don't replace the other checks
// but the report should make it visible — a finding inside gVisor has
// a different threat model than the same finding under runc.
func (c *sandboxedRuntimeCheck) Run(ctx context.Context) check.Result {
	var hits []string

	// gVisor: /proc/version contains "gVisor"
	if data, err := DefaultFS.ReadFile("/proc/version"); err == nil {
		v := string(data)
		switch {
		case strings.Contains(v, "gVisor"):
			hits = append(hits, "gVisor: /proc/version contains 'gVisor'")
		case strings.Contains(v, "kata"):
			hits = append(hits, "Kata: /proc/version contains 'kata'")
		}
	}
	// Firecracker: /sys/devices/virtual/dmi/id/* often has "Firecracker"
	if data, err := DefaultFS.ReadFile("/sys/devices/virtual/dmi/id/sys_vendor"); err == nil {
		if strings.Contains(string(data), "Firecracker") {
			hits = append(hits, "Firecracker: DMI sys_vendor")
		}
	}
	if len(hits) == 0 {
		res := check.NewPass(c)
		res.Evidence = []string{"no sandboxed-runtime fingerprint found"}
		return res
	}
	res := check.NewPass(c)
	res.Status = check.StatusFail // = "the condition is present", informational
	res.Severity = check.SeverityInfo
	res.SeverityLabel = res.Severity.String()
	res.Evidence = hits
	res.Recommendation = "Informational. Re-evaluate the severity of other findings under this runtime."
	return res
}

func init() {
	engine.Register(&readOnlyRootCheck{Base: check.Base{
		IDValue:          "container.fs.read_only_root",
		NameValue:        "Read-only root filesystem",
		ModuleValue:      "container",
		SeverityValue:    check.SeverityMedium,
		DescriptionValue: "Reports whether / is mounted read-only. A writable rootfs lets attackers persist payloads anywhere.",
		ReferencesValue: []string{
			"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
		},
	}})
	engine.Register(&userNamespaceCheck{Base: check.Base{
		IDValue:          "container.user_namespace",
		NameValue:        "User namespace remapping",
		ModuleValue:      "container",
		SeverityValue:    check.SeverityMedium,
		DescriptionValue: "Inspects /proc/self/uid_map to detect whether root in the container maps to root on the host.",
	}})
	engine.Register(&sandboxedRuntimeCheck{Base: check.Base{
		IDValue:          "container.runtime.sandboxed",
		NameValue:        "Sandboxed runtime fingerprint",
		ModuleValue:      "container",
		SeverityValue:    check.SeverityInfo,
		DescriptionValue: "Detects gVisor / Kata / Firecracker fingerprints to contextualise other findings.",
	}})
}
