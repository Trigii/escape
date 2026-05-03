package tests

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tristanvaquero/escape/internal/output"
	"github.com/tristanvaquero/escape/pkg/check"
)

func sampleResults() []check.Result {
	return []check.Result{
		{
			ID:            "container.privileged",
			Name:          "Privileged container",
			Module:        "container",
			Severity:      check.SeverityCritical,
			SeverityLabel: "critical",
			Status:        check.StatusFail,
			Description:   "Full caps + writable /sys",
			Evidence:      []string{"CapEff full", "/sys rw"},
			Recommendation: "Drop --privileged",
			StartedAt:     time.Now(),
			Duration:      time.Millisecond,
		},
		{
			ID: "container.apparmor", Name: "AppArmor",
			Module: "container", Severity: check.SeverityLow,
			SeverityLabel: "low", Status: check.StatusPass,
			Description: "AppArmor profile applied",
		},
		{
			ID: "k8s.detect", Name: "K8s detect", Module: "kubernetes",
			Severity: check.SeverityInfo, SeverityLabel: "info",
			Status: check.StatusSkip, Evidence: []string{"not in k8s"},
		},
	}
}

func TestWriteJSONIsValid(t *testing.T) {
	var buf bytes.Buffer
	if err := output.WriteJSON(&buf, sampleResults(), "v0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if doc["tool"] != "escape" {
		t.Errorf("unexpected tool field: %v", doc["tool"])
	}
}

func TestWriteSARIFIsValid(t *testing.T) {
	var buf bytes.Buffer
	if err := output.WriteSARIF(&buf, sampleResults(), "v0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("expected SARIF 2.1.0, got %v", doc["version"])
	}
}

func TestWriteHTMLContainsFinding(t *testing.T) {
	var buf bytes.Buffer
	if err := output.WriteHTML(&buf, sampleResults(), "v0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if !strings.Contains(s, "Privileged container") {
		t.Errorf("HTML did not include finding name")
	}
	if !strings.Contains(s, "<style>") {
		t.Errorf("HTML missing inline CSS")
	}
}

func TestWriteMarkdownContainsFinding(t *testing.T) {
	var buf bytes.Buffer
	if err := output.WriteMarkdown(&buf, sampleResults(), "v0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "container.privileged") {
		t.Errorf("markdown missing finding ID")
	}
}

func TestTableOnlyFailures(t *testing.T) {
	var buf bytes.Buffer
	if err := output.WriteTable(&buf, sampleResults(), output.TableOptions{
		NoColor: true, OnlyFailures: true,
	}); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if !strings.Contains(s, "container.privileged") {
		t.Errorf("expected privileged in only-failures output")
	}
	if strings.Contains(s, "container.apparmor") {
		t.Errorf("only-failures should hide passing checks; got:\n%s", s)
	}
}
