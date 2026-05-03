package container

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

// runtimeCheck is informational: it reports the detected container runtime
// (or absence of one) so downstream checks can be interpreted in context.
type runtimeCheck struct{ check.Base }

func (c *runtimeCheck) Run(ctx context.Context) check.Result {
	runtime, evidence := DetectRuntime(DefaultFS)
	res := check.NewPass(c)
	if runtime == "" {
		res.Evidence = []string{"no container runtime artifacts found"}
		return res
	}
	res.Status = check.StatusFail // "fail" here means "the condition is present"
	res.Severity = check.SeverityInfo
	res.SeverityLabel = res.Severity.String()
	res.Evidence = append([]string{"detected runtime: " + runtime}, evidence...)
	res.Recommendation = "Informational. Use this signal to scope follow-up checks."
	return res
}

// DetectRuntime returns ("docker"|"containerd"|"podman"|"cri-o"|"") and
// the lines of evidence that led to the conclusion. It only inspects
// well-known marker files — no commands are executed.
func DetectRuntime(filesystem FS) (string, []string) {
	var ev []string

	if _, err := filesystem.Stat("/.dockerenv"); err == nil {
		ev = append(ev, "/.dockerenv exists")
		return "docker", ev
	}
	if _, err := filesystem.Stat("/run/.containerenv"); err == nil {
		ev = append(ev, "/run/.containerenv exists (podman/cri-o)")
	}
	if data, err := filesystem.ReadFile("/proc/1/cgroup"); err == nil {
		txt := string(data)
		switch {
		case strings.Contains(txt, "docker"):
			ev = append(ev, "/proc/1/cgroup contains 'docker'")
			return "docker", ev
		case strings.Contains(txt, "containerd"):
			ev = append(ev, "/proc/1/cgroup contains 'containerd'")
			return "containerd", ev
		case strings.Contains(txt, "kubepods"):
			ev = append(ev, "/proc/1/cgroup contains 'kubepods'")
			return "kubernetes", ev
		case strings.Contains(txt, "crio"):
			ev = append(ev, "/proc/1/cgroup contains 'crio'")
			return "cri-o", ev
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		ev = append(ev, "could not read /proc/1/cgroup: "+err.Error())
	}
	return "", ev
}

func init() {
	engine.Register(&runtimeCheck{Base: check.Base{
		IDValue:          "container.runtime",
		NameValue:        "Container runtime detection",
		ModuleValue:      "container",
		SeverityValue:    check.SeverityInfo,
		DescriptionValue: "Identifies the container runtime by inspecting marker files. Read-only.",
		ReferencesValue:  []string{"https://man7.org/linux/man-pages/man7/cgroups.7.html"},
	}})
}
