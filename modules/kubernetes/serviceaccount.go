package kubernetes

import (
	"context"
	"fmt"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

type saTokenCheck struct{ check.Base }

func (c *saTokenCheck) Run(ctx context.Context) check.Result {
	in, _ := Detect()
	if !in {
		return check.NewSkip(c, "not running in Kubernetes")
	}
	data, err := DefaultFS.ReadFile(SATokenPath)
	if err != nil {
		res := check.NewPass(c)
		res.Evidence = []string{"no service account token mounted (automountServiceAccountToken: false)"}
		return res
	}
	// We DO NOT decode or print the token. We only confirm presence
	// and shape. This is intentional: the token is a secret and must
	// not be exfiltrated by an audit tool.
	tok := strings.TrimSpace(string(data))
	parts := strings.Split(tok, ".")
	shape := "unknown"
	if len(parts) == 3 {
		shape = "JWT (3 dot-separated segments)"
	}
	return check.NewFail(c,
		[]string{
			fmt.Sprintf("token mounted at %s (%d bytes, %s)", SATokenPath, len(tok), shape),
			"token VALUE intentionally not displayed",
		},
		"If the workload doesn't talk to the Kubernetes API, set automountServiceAccountToken: false on the pod or ServiceAccount.")
}

type saNamespaceCheck struct{ check.Base }

func (c *saNamespaceCheck) Run(ctx context.Context) check.Result {
	in, _ := Detect()
	if !in {
		return check.NewSkip(c, "not running in Kubernetes")
	}
	data, err := DefaultFS.ReadFile(SANamespacePath)
	if err != nil {
		res := check.NewPass(c)
		res.Evidence = []string{"namespace file not present"}
		return res
	}
	ns := strings.TrimSpace(string(data))
	res := check.NewPass(c)
	res.Status = check.StatusFail
	res.Severity = check.SeverityInfo
	res.SeverityLabel = res.Severity.String()
	res.Evidence = []string{"pod namespace: " + ns}
	res.Recommendation = "Informational. Useful for scoping RBAC review."
	return res
}

type saCACheck struct{ check.Base }

func (c *saCACheck) Run(ctx context.Context) check.Result {
	in, _ := Detect()
	if !in {
		return check.NewSkip(c, "not running in Kubernetes")
	}
	st, err := DefaultFS.Stat(SACAPath)
	if err != nil {
		res := check.NewPass(c)
		res.Evidence = []string{"no API server CA mounted"}
		return res
	}
	res := check.NewPass(c)
	res.Status = check.StatusFail
	res.Severity = check.SeverityInfo
	res.SeverityLabel = res.Severity.String()
	res.Evidence = []string{fmt.Sprintf("API CA at %s (%d bytes)", SACAPath, st.Size())}
	return res
}

func init() {
	engine.Register(&saTokenCheck{Base: check.Base{
		IDValue:          "k8s.sa.token",
		NameValue:        "ServiceAccount token mounted",
		ModuleValue:      "kubernetes",
		SeverityValue:    check.SeverityMedium,
		DescriptionValue: "Reports whether a ServiceAccount token is bind-mounted into the pod. Tokens are commonly used for lateral movement after RCE.",
		ReferencesValue: []string{
			"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/",
			"https://attack.mitre.org/techniques/T1552/007/",
		},
		AttackValue: []string{"T1552/007"},
	}})
	engine.Register(&saNamespaceCheck{Base: check.Base{
		IDValue:          "k8s.sa.namespace",
		NameValue:        "Pod namespace identification",
		ModuleValue:      "kubernetes",
		SeverityValue:    check.SeverityInfo,
		DescriptionValue: "Reads the projected namespace file to identify the pod's namespace.",
	}})
	engine.Register(&saCACheck{Base: check.Base{
		IDValue:          "k8s.sa.ca",
		NameValue:        "API server CA bundle present",
		ModuleValue:      "kubernetes",
		SeverityValue:    check.SeverityInfo,
		DescriptionValue: "Reports the presence of the API server CA bundle, indicating that TLS verification can be performed.",
	}})
}
