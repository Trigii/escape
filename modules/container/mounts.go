package container

import (
	"context"
	"fmt"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

// mountInfoEntry represents a single line of /proc/self/mountinfo.
// We only keep what the checks care about.
type mountInfoEntry struct {
	MountPoint string
	FSType     string
	Source     string
	Options    string // mount option string, e.g. "rw,nosuid"
}

// parseMountInfo parses the kernel's mountinfo format:
//
//	36 35 98:0 /mnt1 /mnt parent shared:1 - ext3 /dev/root rw,errors=continue
//
// Field layout: man 5 proc, "mountinfo" section.
func parseMountInfo(s string) []mountInfoEntry {
	var out []mountInfoEntry
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		// Split on " - " separator that divides the optional fields from
		// the per-fs fields.
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left := strings.Fields(parts[0])
		right := strings.Fields(parts[1])
		if len(left) < 6 || len(right) < 3 {
			continue
		}
		out = append(out, mountInfoEntry{
			MountPoint: left[4],
			Options:    left[5],
			FSType:     right[0],
			Source:     right[1],
		})
	}
	return out
}

func isSysWritable(mountinfo string) bool {
	for _, m := range parseMountInfo(mountinfo) {
		if m.MountPoint == "/sys" && strings.Contains(m.Options, "rw") {
			return true
		}
	}
	return false
}

// dockerSockCheck flags /var/run/docker.sock visible to the workload.
type dockerSockCheck struct{ check.Base }

func (c *dockerSockCheck) Run(ctx context.Context) check.Result {
	candidates := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/var/run/containerd/containerd.sock",
		"/run/containerd/containerd.sock",
		"/var/run/crio/crio.sock",
	}
	var found []string
	for _, p := range candidates {
		if _, err := DefaultFS.Stat(p); err == nil {
			found = append(found, p)
		}
	}
	if len(found) == 0 {
		return check.NewPass(c)
	}
	return check.NewFail(c,
		append([]string{"runtime socket(s) reachable from inside the container:"}, found...),
		"Never bind-mount the runtime socket into a workload. If the container needs to "+
			"talk to the cluster API, use a ServiceAccount with a least-privilege RBAC role instead.")
}

// sensitiveMountsCheck flags host paths bind-mounted into the container.
type sensitiveMountsCheck struct{ check.Base }

func (c *sensitiveMountsCheck) Run(ctx context.Context) check.Result {
	data, err := DefaultFS.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return check.NewError(c, fmt.Errorf("read mountinfo: %w", err))
	}
	mounts := parseMountInfo(string(data))

	// Highly suspicious mount points — the host root or its sensitive
	// subtrees being visible inside the container.
	suspicious := map[string]string{
		"/host":         "host root commonly bind-mounted at /host",
		"/hostroot":     "host root commonly bind-mounted at /hostroot",
		"/host-etc":     "host /etc accessible",
		"/host/etc":     "host /etc accessible",
		"/host/var/run": "host /var/run accessible (sockets, runtime state)",
	}
	var ev []string
	for _, m := range mounts {
		if reason, ok := suspicious[m.MountPoint]; ok {
			ev = append(ev, fmt.Sprintf("%s -> %s (%s) [%s]", m.MountPoint, m.Source, m.FSType, reason))
		}
		// Bind mounts of /proc, /sys, or /etc from the host inside the container.
		if m.FSType == "proc" && m.MountPoint != "/proc" {
			ev = append(ev, fmt.Sprintf("nested proc mount at %s", m.MountPoint))
		}
		if (m.MountPoint == "/etc/shadow" || m.MountPoint == "/etc/passwd") &&
			m.Source != "" {
			ev = append(ev, fmt.Sprintf("%s bind-mounted from %s", m.MountPoint, m.Source))
		}
	}
	if len(ev) == 0 {
		return check.NewPass(c)
	}
	return check.NewFail(c, ev,
		"Avoid mounting host paths into containers. If unavoidable, mount the smallest "+
			"specific path you need and use readOnly: true.")
}

func init() {
	engine.Register(&dockerSockCheck{Base: check.Base{
		IDValue:          "container.mounts.docker_sock",
		NameValue:        "Container runtime socket exposed",
		ModuleValue:      "container",
		SeverityValue:    check.SeverityCritical,
		DescriptionValue: "Detects whether docker.sock, containerd.sock or crio.sock are reachable from inside the container — equivalent to giving root on the host.",
		ReferencesValue: []string{
			"https://attack.mitre.org/techniques/T1611/",
		},
	}})
	engine.Register(&sensitiveMountsCheck{Base: check.Base{
		IDValue:          "container.mounts.sensitive",
		NameValue:        "Sensitive host paths mounted",
		ModuleValue:      "container",
		SeverityValue:    check.SeverityHigh,
		DescriptionValue: "Flags well-known host paths that are bind-mounted into the workload (/host, host /etc, etc.).",
		ReferencesValue: []string{
			"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
		},
	}})
}
