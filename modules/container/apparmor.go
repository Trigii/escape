package container

import (
	"context"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

type apparmorCheck struct{ check.Base }

func (c *apparmorCheck) Run(ctx context.Context) check.Result {
	data, err := DefaultFS.ReadFile("/proc/self/attr/current")
	if err != nil {
		// AppArmor not present on this host — not a finding, just informational.
		return check.NewSkip(c, "no AppArmor LSM detected (/proc/self/attr/current unreadable)")
	}
	profile := strings.TrimSpace(string(data))
	if profile == "" || profile == "unconfined" {
		return check.NewFail(c,
			[]string{"AppArmor profile: " + profile},
			"Apply an AppArmor profile (e.g. runtime/default in Kubernetes, or "+
				"--security-opt apparmor=docker-default in Docker).")
	}
	res := check.NewPass(c)
	res.Evidence = []string{"AppArmor profile: " + profile}
	return res
}

func init() {
	engine.Register(&apparmorCheck{Base: check.Base{
		IDValue:          "container.apparmor",
		NameValue:        "AppArmor profile applied",
		ModuleValue:      "container",
		SeverityValue:    check.SeverityLow,
		DescriptionValue: "Reports the active AppArmor profile or 'unconfined'.",
		ReferencesValue: []string{
			"https://kubernetes.io/docs/tutorials/security/apparmor/",
		},
	}})
}
