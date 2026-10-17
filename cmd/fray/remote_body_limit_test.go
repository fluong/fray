package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
)

func TestReadRemoteScanResponseBodyScanLimit(t *testing.T) {
	t.Run("at_limit", func(t *testing.T) {
		body := make([]byte, maxScanResponseBody)
		body[0] = '{'
		body[len(body)-1] = '}'
		_, err := readRemoteScanResponseBody(http.StatusOK, io.NopCloser(strings.NewReader(string(body))))
		if err != nil {
			t.Fatalf("at limit: %v", err)
		}
	})
	t.Run("over_limit", func(t *testing.T) {
		body := make([]byte, maxScanResponseBody+1)
		_, err := readRemoteScanResponseBody(http.StatusOK, io.NopCloser(strings.NewReader(string(body))))
		if err == nil {
			t.Fatal("want error")
		}
		if !strings.Contains(err.Error(), "remote scan: response body too large") {
			t.Fatalf("msg=%q", err.Error())
		}
		if !strings.Contains(err.Error(), "8 MiB") {
			t.Fatalf("want 8 MiB in error: %q", err.Error())
		}
	})
}

func TestRemoteScanAcceptsMaxScanResponseBody(t *testing.T) {
	body := mustScanResponseJSON(t, maxScanResponseBody)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(body); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	writeMinimalScanInputs(t, dir)
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))
	opt := options{
		Plan:          filepath.Join(dir, "plan.json"),
		Source:        filepath.Join(dir, "infra"),
		Config:        filepath.Join(dir, "fray.yaml"),
		Mitigations:   filepath.Join(dir, "mitigations.yaml"),
		Remote:        srv.URL,
		Repo:          "acme/widgets",
		Commit:        "abc123",
		Branch:        "main",
		DefaultBranch: "main",
		OIDCToken:     "test-oidc-token",
		Out:           filepath.Join(dir, "out"),
	}
	if _, err := runRemote(opt); err != nil {
		t.Fatalf("runRemote: %v", err)
	}
}

func TestRemoteScanRejectsOverMaxScanResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(make([]byte, maxScanResponseBody+1))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	writeMinimalScanInputs(t, dir)
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))
	opt := options{
		Plan:          filepath.Join(dir, "plan.json"),
		Source:        filepath.Join(dir, "infra"),
		Config:        filepath.Join(dir, "fray.yaml"),
		Mitigations:   filepath.Join(dir, "mitigations.yaml"),
		Remote:        srv.URL,
		Repo:          "acme/widgets",
		Commit:        "abc123",
		Branch:        "main",
		DefaultBranch: "main",
		OIDCToken:     "test-oidc-token",
		Out:           filepath.Join(dir, "out"),
	}
	_, err := runRemote(opt)
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "remote scan: response body too large") {
		t.Fatalf("err=%v", err)
	}
}

func TestRemoteEnrollmentBodyLimitUnchanged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		body := make([]byte, maxEnrollmentBody+1)
		copy(body, []byte(`{"error":"repo_not_enrolled"}`))
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	writeMinimalScanInputs(t, dir)
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))
	opt := options{
		Plan:          filepath.Join(dir, "plan.json"),
		Source:        filepath.Join(dir, "infra"),
		Config:        filepath.Join(dir, "fray.yaml"),
		Mitigations:   filepath.Join(dir, "mitigations.yaml"),
		Remote:        srv.URL,
		Repo:          "acme/widgets",
		Commit:        "abc123",
		Branch:        "main",
		DefaultBranch: "main",
		OIDCToken:     "test-oidc-token",
		Out:           filepath.Join(dir, "out"),
	}
	_, err := runRemote(opt)
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "remote scan: response body too large") {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(err.Error(), "MiB") {
		t.Fatalf("enrollment over-limit must not use scan MiB message: %v", err)
	}
}

func TestRemoteEnrollmentSkipStillWithinLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": codeRepoNotEnrolled})
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	writeMinimalScanInputs(t, dir)
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))
	summary := filepath.Join(dir, "summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	opt := options{
		Plan:          filepath.Join(dir, "plan.json"),
		Source:        filepath.Join(dir, "infra"),
		Config:        filepath.Join(dir, "fray.yaml"),
		Mitigations:   filepath.Join(dir, "mitigations.yaml"),
		Remote:        srv.URL,
		Repo:          "acme/widgets",
		Commit:        "abc123",
		Branch:        "main",
		DefaultBranch: "main",
		OIDCToken:     "test-oidc-token",
		Out:           filepath.Join(dir, "out"),
	}
	_, err := runRemote(opt)
	if err != nil {
		t.Fatalf("skip path: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "out", enrollmentMarkerFile))
	if err != nil {
		t.Fatalf("marker: %v", err)
	}
	if !strings.Contains(string(raw), codeRepoNotEnrolled) {
		t.Fatalf("marker=%s", raw)
	}
}

func mustScanResponseJSON(t *testing.T, wantLen int) []byte {
	t.Helper()
	base := apiv1.ScanResponse{
		ScanID: "s1",
		Findings: apiv1.Findings{
			SchemaVersion: "finding/v1",
			Findings:      []apiv1.Finding{},
		},
		RuleTexts: map[string]apiv1.RuleText{},
	}
	pad := 0
	for {
		base.RuleTexts = map[string]apiv1.RuleText{
			"FR-PAD": {ID: "FR-PAD", Title: strings.Repeat("x", pad), Target: "element", Severity: "low"},
		}
		raw, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case len(raw) < wantLen:
			pad += wantLen - len(raw)
		case len(raw) > wantLen:
			pad -= len(raw) - wantLen
		default:
			return raw
		}
		if pad < 0 {
			t.Fatalf("cannot size response to %d bytes (got %d)", wantLen, len(raw))
		}
	}
}
