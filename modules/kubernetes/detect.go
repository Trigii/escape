// Package kubernetes contains read-only enumeration checks for the
// in-pod Kubernetes environment. Nothing in this package authenticates
// to the API server or performs exploit-grade probing — by design.
package kubernetes

import (
	"context"
	"fmt"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

type detectCheck struct{ check.Base }

// Detect inspects environment variables and the SA token path to decide
// whether the workload is running under Kubernetes.
func Detect() (in bool, evidence []string) {
	host := Env("KUBERNETES_SERVICE_HOST")
	port := Env("KUBERNETES_SERVICE_PORT")
	if host != "" {
		evidence = append(evidence, fmt.Sprintf("KUBERNETES_SERVICE_HOST=%s", host))
		in = true
	}
	if port != "" {
		evidence = append(evidence, fmt.Sprintf("KUBERNETES_SERVICE_PORT=%s", port))
		in = true
	}
	if _, err := DefaultFS.Stat(SATokenPath); err == nil {
		evidence = append(evidence, "service account token mounted at "+SATokenPath)
		in = true
	}
	return in, evidence
}

func (c *detectCheck) Run(ctx context.Context) check.Result {
	in, ev := Detect()
	if !in {
		return check.NewSkip(c, "no Kubernetes environment indicators found")
	}
	res := check.NewPass(c)
	res.Status = check.StatusFail // "fail" = the condition holds; severity=info
	res.Severity = check.SeverityInfo
	res.SeverityLabel = res.Severity.String()
	res.Evidence = ev
	res.Recommendation = "Informational. Subsequent k8s.* checks will run."
	return res
}

func init() {
	engine.Register(&detectCheck{Base: check.Base{
		IDValue:          "k8s.detect",
		NameValue:        "Kubernetes environment detection",
		ModuleValue:      "kubernetes",
		SeverityValue:    check.SeverityInfo,
		DescriptionValue: "Detects whether the workload is running inside a Kubernetes pod by inspecting env vars and ServiceAccount artefacts.",
	}})
}
