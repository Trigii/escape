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

// --- new checks (host kernel, sysctls, network, rootfs, userns, JWT) ---

func TestKcoreVisible(t *testing.T) {
	mock := New()
	mock.Files["/proc/kcore"] = "" // mere existence is enough
	old := host.DefaultFS
	host.DefaultFS = mock
	defer func() { host.DefaultFS = old }()

	c := findCheck(t, "host.proc_kcore")
	res := c.Run(context.Background())
	if res.Status != check.StatusFail {
		t.Fatalf("kcore visible should fail, got %s", res.Status)
	}
}

func TestKcoreAbsent(t *testing.T) {
	mock := New()
	old := host.DefaultFS
	host.DefaultFS = mock
	defer func() { host.DefaultFS = old }()

	c := findCheck(t, "host.proc_kcore")
	res := c.Run(context.Background())
	if res.Status != check.StatusPass {
		t.Fatalf("kcore absent should pass, got %s ev=%v", res.Status, res.Evidence)
	}
}

func TestModprobePathReadable(t *testing.T) {
	mock := New()
	mock.Files["/proc/sys/kernel/modprobe"] = "/sbin/modprobe\n"
	old := host.DefaultFS
	host.DefaultFS = mock
	defer func() { host.DefaultFS = old }()

	c := findCheck(t, "host.modprobe_path")
	res := c.Run(context.Background())
	if res.Status != check.StatusFail {
		t.Fatalf("modprobe readable should fail, got %s", res.Status)
	}
}

func TestSysctlSafe(t *testing.T) {
	mock := New()
	mock.Files["/proc/sys/kernel/yama/ptrace_scope"] = "1\n"
	mock.Files["/proc/sys/kernel/dmesg_restrict"] = "1\n"
	old := host.DefaultFS
	host.DefaultFS = mock
	defer func() { host.DefaultFS = old }()

	c := findCheck(t, "host.sysctl.unsafe")
	res := c.Run(context.Background())
	if res.Status != check.StatusPass {
		t.Fatalf("safe sysctls should pass, got %s ev=%v", res.Status, res.Evidence)
	}
}

func TestSysctlUnsafe(t *testing.T) {
	mock := New()
	mock.Files["/proc/sys/kernel/yama/ptrace_scope"] = "0\n"
	mock.Files["/proc/sys/kernel/kptr_restrict"] = "0\n"
	old := host.DefaultFS
	host.DefaultFS = mock
	defer func() { host.DefaultFS = old }()

	c := findCheck(t, "host.sysctl.unsafe")
	res := c.Run(context.Background())
	if res.Status != check.StatusFail {
		t.Fatalf("unsafe sysctls should fail, got %s", res.Status)
	}
}

func TestRootfsReadOnly(t *testing.T) {
	mock := New()
	mock.Files["/proc/self/mountinfo"] = "1 0 8:1 / / parent shared:1 - ext4 /dev/root ro,noatime\n"
	old := container.DefaultFS
	container.DefaultFS = mock
	defer func() { container.DefaultFS = old }()

	c := findCheck(t, "container.fs.read_only_root")
	res := c.Run(context.Background())
	if res.Status != check.StatusPass {
		t.Fatalf("ro root should pass, got %s ev=%v", res.Status, res.Evidence)
	}
}

func TestRootfsWritable(t *testing.T) {
	mock := New()
	mock.Files["/proc/self/mountinfo"] = "1 0 8:1 / / parent shared:1 - ext4 /dev/root rw,noatime\n"
	old := container.DefaultFS
	container.DefaultFS = mock
	defer func() { container.DefaultFS = old }()

	c := findCheck(t, "container.fs.read_only_root")
	res := c.Run(context.Background())
	if res.Status != check.StatusFail {
		t.Fatalf("rw root should fail, got %s", res.Status)
	}
}

func TestUserNamespaceUnmapped(t *testing.T) {
	mock := New()
	mock.Files["/proc/self/uid_map"] = "         0          0 4294967295\n"
	old := container.DefaultFS
	container.DefaultFS = mock
	defer func() { container.DefaultFS = old }()

	c := findCheck(t, "container.user_namespace")
	res := c.Run(context.Background())
	if res.Status != check.StatusFail {
		t.Fatalf("unmapped userns should fail, got %s", res.Status)
	}
}

func TestUserNamespaceRemapped(t *testing.T) {
	mock := New()
	mock.Files["/proc/self/uid_map"] = "         0     100000      65536\n"
	old := container.DefaultFS
	container.DefaultFS = mock
	defer func() { container.DefaultFS = old }()

	c := findCheck(t, "container.user_namespace")
	res := c.Run(context.Background())
	if res.Status != check.StatusPass {
		t.Fatalf("remapped userns should pass, got %s ev=%v", res.Status, res.Evidence)
	}
}

func TestTokenDecodeClaimsButNotValue(t *testing.T) {
	// Hand-crafted unsigned JWT: header.payload.signature
	// Payload is base64url of:
	//   {"iss":"k","sub":"system:serviceaccount:demo:reader","exp":4102444800,
	//    "kubernetes.io":{"namespace":"demo","serviceaccount":{"name":"reader"}}}
	header := "eyJhbGciOiJSUzI1NiJ9"
	payload := "eyJpc3MiOiJrIiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlbW86cmVhZGVyIiwiZXhwIjo0MTAyNDQ0ODAwLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImRlbW8iLCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoicmVhZGVyIn19fQ"
	sig := "DEADBEEF"
	tok := header + "." + payload + "." + sig

	mock := New()
	mock.Files[kubernetes.SATokenPath] = tok
	oldFS := kubernetes.DefaultFS
	kubernetes.DefaultFS = mock
	defer func() { kubernetes.DefaultFS = oldFS }()

	oldEnv := kubernetes.Env
	kubernetes.Env = func(k string) string { return "10.0.0.1" }
	defer func() { kubernetes.Env = oldEnv }()

	c := findCheck(t, "k8s.token.decoded")
	res := c.Run(context.Background())
	if res.Status != check.StatusFail {
		t.Fatalf("decoded token check should produce a finding, got %s", res.Status)
	}
	joined := strings.Join(res.Evidence, "\n")
	if !strings.Contains(joined, "namespace: demo") {
		t.Errorf("expected namespace claim in evidence, got: %v", res.Evidence)
	}
	if !strings.Contains(joined, "serviceaccount: reader") {
		t.Errorf("expected serviceaccount claim, got: %v", res.Evidence)
	}
	// CRITICAL: the raw token MUST NOT appear in evidence.
	if strings.Contains(joined, sig) || strings.Contains(joined, payload) {
		t.Fatalf("token VALUE leaked into evidence: %v", res.Evidence)
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
