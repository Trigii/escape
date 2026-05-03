package container

import (
	"context"
	"fmt"
	"os"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

type userCheck struct{ check.Base }

func (c *userCheck) Run(ctx context.Context) check.Result {
	uid := os.Getuid()
	gid := os.Getgid()
	if uid != 0 {
		res := check.NewPass(c)
		res.Evidence = []string{fmt.Sprintf("running as uid=%d gid=%d", uid, gid)}
		return res
	}
	return check.NewFail(
		c,
		[]string{fmt.Sprintf("running as uid=%d gid=%d (root)", uid, gid)},
		"Set a non-root USER in the Dockerfile or runAsNonRoot: true in the PodSecurityContext.",
	)
}

func init() {
	engine.Register(&userCheck{Base: check.Base{
		IDValue:          "container.user.root",
		NameValue:        "Container running as root",
		ModuleValue:      "container",
		SeverityValue:    check.SeverityHigh,
		DescriptionValue: "Detects whether the workload's effective UID is 0. Root inside a container, combined with any kernel CVE or misconfiguration, often becomes root on the host.",
		ReferencesValue: []string{
			"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
			"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
		},
	}})
}
