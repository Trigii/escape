package kubernetes

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

// Dialer is the network layer used by API reachability checks.
// Tests can swap it for a no-op. In production we use a strict
// timeout so the check never blocks the runner.
var Dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	return d.DialContext(ctx, network, address)
}

type apiReachableCheck struct{ check.Base }

// Run performs a single, unauthenticated TCP connect to the in-cluster
// API endpoint. It does NOT send any HTTP request, does NOT use the
// ServiceAccount token, and does NOT perform any kind of probing
// against the cluster. Reachability alone is the signal.
func (c *apiReachableCheck) Run(ctx context.Context) check.Result {
	in, _ := Detect()
	if !in {
		return check.NewSkip(c, "not running in Kubernetes")
	}
	host := Env("KUBERNETES_SERVICE_HOST")
	port := Env("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return check.NewSkip(c, "KUBERNETES_SERVICE_HOST/PORT not set")
	}
	addr := net.JoinHostPort(host, port)

	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	conn, err := Dialer(dialCtx, "tcp", addr)
	if err != nil {
		res := check.NewPass(c)
		res.Evidence = []string{fmt.Sprintf("API endpoint %s NOT reachable: %v", addr, err)}
		return res
	}
	_ = conn.Close()
	return check.NewFail(c,
		[]string{
			"API server reachable at " + addr + " (TCP connect only — no HTTP, no auth)",
			"this is the in-cluster default; combined with a mounted SA token it is the lateral-movement vector",
		},
		"If the workload doesn't need API access, deny egress to the kubernetes Service via NetworkPolicy and unset automountServiceAccountToken.")
}

func init() {
	engine.Register(&apiReachableCheck{Base: check.Base{
		IDValue:          "k8s.api.reachable",
		NameValue:        "Kubernetes API reachable from pod",
		ModuleValue:      "kubernetes",
		SeverityValue:    check.SeverityMedium,
		DescriptionValue: "Performs an unauthenticated TCP connect to the in-cluster API endpoint to confirm reachability. No HTTP requests are issued.",
		ReferencesValue: []string{
			"https://kubernetes.io/docs/concepts/services-networking/network-policies/",
		},
	}})
}
