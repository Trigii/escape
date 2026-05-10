package cloud

import (
	"context"
	"os"
	"strings"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

// Env is overridable for tests.
var Env = os.Environ

type envLeakCheck struct{ check.Base }

// suspicious environment variable names that frequently carry credentials.
var suspiciousEnvKeys = []string{
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AZURE_CLIENT_SECRET",
	"AZURE_TENANT_ID",
	"AZURE_SUBSCRIPTION_ID",
	"GOOGLE_APPLICATION_CREDENTIALS",
	"GCP_SERVICE_ACCOUNT_KEY",
	"DIGITALOCEAN_TOKEN",
	"DO_API_TOKEN",
}

func (c *envLeakCheck) Run(ctx context.Context) check.Result {
	var found []string
	for _, e := range Env() {
		key := e
		if i := strings.IndexByte(e, '='); i > 0 {
			key = e[:i]
		}
		for _, s := range suspiciousEnvKeys {
			if key == s {
				// VALUE intentionally not displayed.
				found = append(found, key+"=<redacted>")
			}
		}
	}
	if len(found) == 0 {
		return check.NewPass(c)
	}
	return check.NewFail(c, found,
		"Inject cloud credentials via short-lived workload identity (IRSA, Workload Identity, "+
			"Azure Workload Identity) instead of static env vars.")
}

func init() {
	engine.Register(&envLeakCheck{Base: check.Base{
		IDValue:          "cloud.env.credentials",
		NameValue:        "Cloud credentials in environment",
		ModuleValue:      "cloud",
		SeverityValue:    check.SeverityHigh,
		DescriptionValue: "Detects suspicious env var names commonly carrying long-lived cloud credentials. Values are never logged.",
		AttackValue:      []string{"T1552/001"},
	}})
}
