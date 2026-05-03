package tests

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tristanvaquero/escape/internal/engine"
	"github.com/tristanvaquero/escape/modules/container"
	"github.com/tristanvaquero/escape/modules/host"
	"github.com/tristanvaquero/escape/modules/kubernetes"
	"github.com/tristanvaquero/escape/pkg/check"
)

// findCheck returns the registered check with the given ID, or t.Fatal()s.
func findCheck(t *testing.T, id string) check.Check {
	t.Helper()
	for _, c := range engine.All() {
		if c.ID() == id {
			return c
		}
	}
	t.Fatalf("check %q not registered", id)
	return nil
}

func TestSeverityParse(t *testing.T) {
	cases := []struct {
		in   string
		want check.Severity
		ok   bool
	}{
		{"critical", check.SeverityCritical, true},
		{"HIGH", check.SeverityHigh, true},
		{"med", check.SeverityMedium, true},
		{"low", check.SeverityLow, true},
		{"info", check.SeverityInfo, true},
		{"bogus", check.SeverityInfo, false},
	}
	for _, c := range cases {
		got, ok := check.ParseSeverity(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseSeverity(%q) = %v,%v want %v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestEngineFilter(t *testing.T) {
	all := engine.All()
	if len(all) == 0 {
		t.Fatal("no checks registered")
	}
	mods := engine.Filter{Modules: []string{"container"}}.Apply(all)
	if len(mods) == 0 {
		t.Fatal("expected container checks")
	}
	for _, c := range mods {
		if c.Module() != "container" {
			t.Errorf("filter leaked module: %s", c.Module())
		}
	}
	ids := engine.Filter{IDs: []string{"container.privileged"}}.Apply(all)
	if len(ids) != 1 {
		t.Fatalf("ID filter: got %d want 1", len(ids))
	}
	glob := engine.Filter{IDs: []string{"k8s.*"}}.Apply(all)
	for _, c := range glob {
		if !strings.HasPrefix(c.ID(), "k8s.") {
			t.Errorf("glob leak: %s", c.ID())
		}
	}
}

// --- container checks ---

func TestCapabilitiesCheckDangerous(t *testing.T) {
	mock := New()
	// Bit 21 (CAP_SYS_ADMIN) set → 0x0000000000200000
	mock.Files["/proc/self/status"] = "Name:\ttest\nCapEff:\t0000000000200000\n"
	old := container.DefaultFS
	container.DefaultFS = mock
	defer func() { container.DefaultFS = old }()

	c := findCheck(t, "container.capabilities.dangerous")
	res := c.Run(context.Background())
	if res.Status != check.StatusFail {
		t.Fatalf("status = %s, want fail; evidence=%v err=%s", res.Status, res.Evidence, res.Err)
	}
	if !strings.Contains(strings.Join(res.Evidence, "\n"), "CAP_SYS_ADMIN") {
		t.Errorf("expected CAP_SYS_ADMIN in evidence, got: %v", res.Evidence)
	}
}

func TestCapabilitiesCheckBenign(t *testing.T) {
	mock := New()
	mock.Files["/proc/self/status"] = "CapEff:\t0000000000000000\n"
	old := container.DefaultFS
	container.DefaultFS = mock
	defer func() { container.DefaultFS = old }()

	c := findCheck(t, "container.capabilities.dangerous")
	res := c.Run(context.Background())
	if res.Status != check.StatusPass {
		t.Fatalf("status = %s, want pass", res.Status)
	}
}

func TestSeccompDisabled(t *testing.T) {
	mock := New()
	mock.Files["/proc/self/status"] = "Seccomp:\t0\n"
	old := container.DefaultFS
	container.DefaultFS = mock
	defer func() { container.DefaultFS = old }()

	c := findCheck(t, "container.seccomp")
	res := c.Run(context.Background())
	if res.Status != check.StatusFail {
		t.Fatalf("status = %s, want fail", res.Status)
	}
}

func TestNoNewPrivsSet(t *testing.T) {
	mock := New()
	mock.Files["/proc/self/status"] = "NoNewPrivs:\t1\n"
	old := container.DefaultFS
	container.DefaultFS = mock
	defer func() { container.DefaultFS = old }()

	c := findCheck(t, "container.no_new_privs")
	res := c.Run(context.Background())
	if res.Status != check.StatusPass {
		t.Fatalf("status = %s, want pass", res.Status)
	}
}

func TestDockerSockExposed(t *testing.T) {
	mock := New()
	mock.Files["/var/run/docker.sock"] = ""
	old := container.DefaultFS
	container.DefaultFS = mock
	defer func() { container.DefaultFS = old }()

	c := findCheck(t, "container.mounts.docker_sock")
	res := c.Run(context.Background())
	if res.Status != check.StatusFail {
		t.Fatalf("status = %s, want fail", res.Status)
	}
}

func TestRuntimeDetection(t *testing.T) {
	mock := New()
	mock.Files["/.dockerenv"] = ""
	old := container.DefaultFS
	container.DefaultFS = mock
	defer func() { container.DefaultFS = old }()

	rt, ev := container.DetectRuntime(mock)
	if rt != "docker" {
		t.Fatalf("runtime = %q, want docker; evidence=%v", rt, ev)
	}
}

// --- kubernetes checks ---

func TestK8sDetectFromEnv(t *testing.T) {
	old := kubernetes.Env
	kubernetes.Env = func(k string) string {
		if k == "KUBERNETES_SERVICE_HOST" {
			return "10.0.0.1"
		}
		return ""
	}
	defer func() { kubernetes.Env = old }()

	in, ev := kubernetes.Detect()
	if !in {
		t.Fatalf("expected k8s detected; evidence=%v", ev)
	}
}

func TestSATokenPresent(t *testing.T) {
	mock := New()
	mock.Files[kubernetes.SATokenPath] = "header.payload.signature"
	oldFS := kubernetes.DefaultFS
	kubernetes.DefaultFS = mock
	defer func() { kubernetes.DefaultFS = oldFS }()

	oldEnv := kubernetes.Env
	kubernetes.Env = func(k string) string { return "10.0.0.1" }
	defer func() { kubernetes.Env = oldEnv }()

	c := findCheck(t, "k8s.sa.token")
	res := c.Run(context.Background())
	if res.Status != check.StatusFail {
		t.Fatalf("status = %s want fail; ev=%v", res.Status, res.Evidence)
	}
	// Critical: the test asserts we DO NOT leak the token value.
	for _, e := range res.Evidence {
		if strings.Contains(e, "header.payload.signature") {
			t.Fatalf("token value leaked into evidence: %q", e)
		}
	}
}

// --- runner sanity ---

func TestRunnerHonoursTimeout(t *testing.T) {
	all := engine.Filter{IDs: []string{"k8s.api.reachable"}}.Apply(engine.All())
	if len(all) != 1 {
		t.Fatal("expected exactly one check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	res := engine.Run(ctx, all, engine.RunnerOptions{Parallelism: 1, PerCheckTimeout: 50 * time.Millisecond})
	if len(res) != 1 {
		t.Fatal("expected one result")
	}
	// Without K8s env, it skips.
	if res[0].Status != check.StatusSkip && res[0].Status != check.StatusError && res[0].Status != check.StatusPass {
		t.Errorf("unexpected status %s", res[0].Status)
	}
	_ = host.DefaultFS // touch host package so its init() is in graph
}
