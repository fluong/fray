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
	"github.com/fluong/fray/version"
)

func TestRemoteSendsClientVersionAndUserAgent(t *testing.T) {
	var gotUA, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(apiv1.ScanResponse{
			ScanID: "s1",
			Findings: apiv1.Findings{
				SchemaVersion: "finding/v1",
				Findings:      []apiv1.Finding{},
			},
			RuleTexts: map[string]apiv1.RuleText{},
		})
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	writeMinimalScanInputs(t, dir)
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))

	_, err := runRemote(options{
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
	})
	if err != nil {
		t.Fatal(err)
	}
	wantUA := "fray-action/" + version.Version
	if gotUA != wantUA {
		t.Fatalf("User-Agent=%q want %q", gotUA, wantUA)
	}
	var req apiv1.ScanRequest
	if err := json.Unmarshal([]byte(gotBody), &req); err != nil {
		t.Fatal(err)
	}
	if req.ClientVersion != version.Version {
		t.Fatalf("client_version=%q want %q", req.ClientVersion, version.Version)
	}
	if !strings.Contains(gotBody, `"client_version":"`+version.Version+`"`) {
		t.Fatalf("request JSON missing client_version: %s", gotBody)
	}
}

func TestDefaultReadinessGETSetsUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ready":true,"checks":[]}`))
	}))
	t.Cleanup(srv.Close)

	_, _, _, err := defaultReadinessGET(srv.URL, "oidc-tok")
	if err != nil {
		t.Fatal(err)
	}
	want := "fray-action/" + version.Version
	if gotUA != want {
		t.Fatalf("User-Agent=%q want %q", gotUA, want)
	}
}

func TestReportRulesSkippedJobSummary(t *testing.T) {
	dir := t.TempDir()
	summary := filepath.Join(dir, "summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldErr := os.Stderr
	os.Stderr = w
	reportRulesSkipped([]apiv1.RuleSkipped{
		{RuleID: "FR-029", MinAction: "v0.13.0"},
	})
	_ = w.Close()
	os.Stderr = oldErr
	stderr, _ := io.ReadAll(r)
	_ = r.Close()

	body, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	want := "1 rule not evaluated because this Fray Action is older than it requires: [FR-029](https://github.com/fluong/fray/blob/main/docs/rules/FR-029.md) (needs v0.13.0). Upgrade for full results.\n"
	if string(body) != want {
		t.Fatalf("summary=%q", body)
	}
	if string(stderr) != want {
		t.Fatalf("stderr=%q", stderr)
	}

	reportRulesSkipped(nil)
	body2, _ := os.ReadFile(summary)
	if string(body2) != want {
		t.Fatalf("nil skipped must not append: %q", body2)
	}
}
