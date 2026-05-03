// Package cloud detects whether the workload can reach a cloud
// instance-metadata service (IMDS). All checks are passive TCP probes;
// no API calls and no IMDSv1 token requests are made.
package cloud

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

// Dialer is overridable for tests.
var Dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{Timeout: 1500 * time.Millisecond}
	return d.DialContext(ctx, network, address)
}

// imdsTargets are the well-known link-local endpoints used by AWS, GCP
// and Azure. All three share 169.254.169.254 — we differentiate later
// from environment variables.
var imdsTargets = []struct {
	Name string
	Addr string
}{
	{"AWS / Azure / GCP IMDS", "169.254.169.254:80"},
	{"AlibabaCloud IMDS", "100.100.100.200:80"},
}

type imdsCheck struct{ check.Base }

func (c *imdsCheck) Run(ctx context.Context) check.Result {
	type res struct {
		name, addr string
		ok         bool
		err        string
	}
	results := make([]res, len(imdsTargets))
	var wg sync.WaitGroup
	for i, t := range imdsTargets {
		i, t := i, t
		wg.Add(1)
		go func() {
			defer wg.Done()
			dCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			conn, err := Dialer(dCtx, "tcp", t.Addr)
			if err != nil {
				results[i] = res{t.Name, t.Addr, false, err.Error()}
				return
			}
			_ = conn.Close()
			results[i] = res{t.Name, t.Addr, true, ""}
		}()
	}
	wg.Wait()

	var reachable []string
	for _, r := range results {
		if r.ok {
			reachable = append(reachable, r.name+" @ "+r.addr+" — TCP open")
		}
	}
	if len(reachable) == 0 {
		return check.NewPass(c)
	}
	return check.NewFail(c, reachable,
		"Block egress to 169.254.169.254 from workloads that don't need it. "+
			"On EKS, require IMDSv2 (HttpTokens=required, hop-limit=1). "+
			"On GKE, prefer Workload Identity over node-level service accounts.")
}

func init() {
	engine.Register(&imdsCheck{Base: check.Base{
		IDValue:          "cloud.imds.reachable",
		NameValue:        "Cloud instance metadata reachable",
		ModuleValue:      "cloud",
		SeverityValue:    check.SeverityHigh,
		DescriptionValue: "Performs a passive TCP probe of well-known IMDS endpoints. No HTTP, no token requests.",
		ReferencesValue: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
			"https://attack.mitre.org/techniques/T1552/005/",
		},
	}})
}
