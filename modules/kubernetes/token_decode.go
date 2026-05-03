package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/pkg/check"
)

// tokenDecodeCheck decodes the JWT *claims* — header and payload only.
// We deliberately do NOT verify the signature: that would require either
// the public key (active probing of the API server) or the symmetric
// secret. The claims alone are enough to tell an auditor the token's
// audience, expiry, ServiceAccount name, and namespace.
//
// This check exists because attackers do exactly this on day one of a
// post-RCE engagement. Telling defenders what an attacker would learn,
// without ever touching the network, is more useful than treating the
// token as opaque.
//
// CRITICAL: the raw token value is never logged. Only structured claim
// fields appear in the output.
type tokenDecodeCheck struct{ check.Base }

// jwtClaims is a subset of the standard + Kubernetes-specific claims.
type jwtClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud any    `json:"aud"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	K8s struct {
		Namespace string `json:"namespace"`
		Pod       struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"pod"`
		ServiceAccount struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

func (c *tokenDecodeCheck) Run(ctx context.Context) check.Result {
	in, _ := Detect()
	if !in {
		return check.NewSkip(c, "not running in Kubernetes")
	}
	raw, err := DefaultFS.ReadFile(SATokenPath)
	if err != nil {
		return check.NewSkip(c, "no service account token mounted")
	}
	tok := strings.TrimSpace(string(raw))
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return check.NewError(c, fmt.Errorf("not a JWT (expected 3 segments, got %d)", len(parts)))
	}

	// Decode the payload (segment 1). JWTs use URL-safe base64 *without* padding.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return check.NewError(c, fmt.Errorf("decode payload: %w", err))
	}
	var claims jwtClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return check.NewError(c, fmt.Errorf("parse claims: %w", err))
	}

	var ev []string
	if claims.Iss != "" {
		ev = append(ev, "iss: "+claims.Iss)
	}
	if claims.Sub != "" {
		ev = append(ev, "sub: "+claims.Sub)
	}
	if aud := formatAudience(claims.Aud); aud != "" {
		ev = append(ev, "aud: "+aud)
	}
	if claims.Exp != 0 {
		exp := time.Unix(claims.Exp, 0).UTC()
		remaining := time.Until(exp).Round(time.Second)
		ev = append(ev, fmt.Sprintf("exp: %s (in %s)", exp.Format(time.RFC3339), remaining))
		if remaining > 365*24*time.Hour {
			ev = append(ev, "WARNING: token lifetime > 1 year (legacy long-lived token?)")
		}
	}
	ns := claims.K8s.Namespace
	saName := claims.K8s.ServiceAccount.Name
	if ns != "" {
		ev = append(ev, "namespace: "+ns)
	}
	if saName != "" {
		ev = append(ev, "serviceaccount: "+saName)
	}
	if claims.K8s.Pod.Name != "" {
		ev = append(ev, "pod: "+claims.K8s.Pod.Name)
	}
	ev = append(ev, "(claims decoded passively; signature NOT verified, token VALUE not logged)")

	return check.NewFail(c, ev,
		"Confirm the token's audience and lifetime match what the workload actually needs. "+
			"For SA tokens older than 1 year, migrate to bound (projected) tokens.")
}

func formatAudience(aud any) string {
	switch v := aud.(type) {
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	}
	return ""
}

func init() {
	engine.Register(&tokenDecodeCheck{Base: check.Base{
		IDValue:          "k8s.token.decoded",
		NameValue:        "ServiceAccount token claims",
		ModuleValue:      "kubernetes",
		SeverityValue:    check.SeverityMedium,
		DescriptionValue: "Decodes the SA token JWT *claims* (header+payload, no signature verification, no network call) so the report shows audience, expiry, namespace and SA name. Token value is never logged.",
		ReferencesValue: []string{
			"https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-token-volume",
		},
	}})
}
