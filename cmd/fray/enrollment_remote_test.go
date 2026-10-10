package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimalScanFixture is enough for Parse to succeed without hitting network
// until the POST — used only for enrollment HTTP handling tests via a stub.
func TestRemoteEnrollmentSkipAndFail(t *testing.T) {
	codes := []string{codeInstallationInactive, codeRepoNotEnrolled, codeInstallationOverCap}

	for _, code := range codes {
		for _, failFlag := range []bool{false, true} {
			t.Run(code+"_fail="+boolStr(failFlag), func(t *testing.T) {
				var posted bool
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					posted = true
					if r.URL.Path != "/v1/scans" {
						t.Errorf("path=%s", r.URL.Path)
					}
					// Never log Authorization.
					if r.Header.Get("Authorization") == "" {
						t.Error("missing Authorization")
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error":   code,
						"message": "server detail",
					})
				}))
				t.Cleanup(srv.Close)

				dir := t.TempDir()
				writeMinimalScanInputs(t, dir)

				summary := filepath.Join(dir, "summary.md")
				t.Setenv("GITHUB_STEP_SUMMARY", summary)
				t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32)) // 64 hex chars = 32 bytes

				outDir := filepath.Join(dir, "out")
				opt := options{
					Plan:             filepath.Join(dir, "plan.json"),
					Source:           filepath.Join(dir, "infra"),
					Config:           filepath.Join(dir, "fray.yaml"),
					Mitigations:      filepath.Join(dir, "mitigations.yaml"),
					Remote:           srv.URL,
					Repo:             "acme/widgets",
					Commit:           "abc123",
					Branch:           "main",
					DefaultBranch:    "main",
					OIDCToken:        "test-oidc-token-not-for-logging",
					Out:              outDir,
					FailOnUnenrolled: failFlag,
				}

				r, w, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				oldOut := os.Stdout
				os.Stdout = w
				blocked, err := runRemote(opt)
				_ = w.Close()
				os.Stdout = oldOut
				annBuf := make([]byte, 8192)
				n, _ := r.Read(annBuf)
				_ = r.Close()
				annotation := string(annBuf[:n])

				if !posted {
					t.Fatal("expected POST to stub")
				}
				if blocked {
					t.Fatal("must not report gate blocked")
				}

				if failFlag {
					if !errors.Is(err, errEnrollmentRejected) {
						t.Fatalf("err=%v want errEnrollmentRejected", err)
					}
					if !strings.HasPrefix(annotation, "::error::") {
						t.Fatalf("want ::error::, got %q", annotation)
					}
				} else {
					if err != nil {
						t.Fatalf("skip path err=%v", err)
					}
					if !strings.HasPrefix(annotation, "::warning::") {
						t.Fatalf("want ::warning::, got %q", annotation)
					}
				}

				if _, err := os.Stat(filepath.Join(outDir, "findings.sarif")); !os.IsNotExist(err) {
					t.Fatalf("SARIF must not be written on enrollment skip/fail, err=%v", err)
				}
				if _, err := os.Stat(filepath.Join(outDir, "pr-comment.md")); !os.IsNotExist(err) {
					t.Fatalf("PR comment must not be written on enrollment skip/fail, err=%v", err)
				}

				raw, err := os.ReadFile(filepath.Join(outDir, enrollmentMarkerFile))
				if err != nil {
					t.Fatalf("enrollment.json missing: %v", err)
				}
				if strings.Contains(string(raw), "server detail") {
					t.Fatalf("server message leaked into marker: %s", raw)
				}
				var marker enrollmentMarker
				if err := json.Unmarshal(raw, &marker); err != nil {
					t.Fatal(err)
				}
				if marker.Code != code {
					t.Fatalf("marker.code=%q want %q", marker.Code, code)
				}
				if marker.Failed != failFlag {
					t.Fatalf("marker.failed=%v want %v", marker.Failed, failFlag)
				}

				sum, err := os.ReadFile(summary)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(sum), "## Fray") {
					t.Fatalf("summary=%s", sum)
				}
			})
		}
	}
}

func TestRemoteUnknownCodeStillFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"not_a_real_code"}`)
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
		OIDCToken:     "tok",
		Out:           filepath.Join(dir, "out"),
	}
	_, err := runRemote(opt)
	if err == nil {
		t.Fatal("expected failure for unknown code")
	}
	if errors.Is(err, errEnrollmentRejected) {
		t.Fatal("unknown code must not use enrollment skip path")
	}
	if !strings.Contains(err.Error(), "403") && !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("want ordinary remote error, got %v", err)
	}
}

func writeMinimalScanInputs(t *testing.T, dir string) {
	t.Helper()
	infra := filepath.Join(dir, "infra")
	if err := os.MkdirAll(infra, 0o755); err != nil {
		t.Fatal(err)
	}
	// Empty root module is enough for ModuleArguments/ResourceLocations.
	if err := os.WriteFile(filepath.Join(infra, "main.tf"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	// One managed resource so Parse yields a non-empty DFD and remote tests
	// reach the HTTP stub (empty plans now fail before the API call).
	plan := `{
  "format_version": "1.2",
  "terraform_version": "1.5.0",
  "planned_values": {"root_module": {}},
  "resource_changes": [{
    "address": "aws_s3_bucket.a",
    "mode": "managed",
    "type": "aws_s3_bucket",
    "name": "a",
    "change": {"actions": ["no-op"], "after": {"bucket": "keep-me"}}
  }],
  "configuration": {"root_module": {"resources": [
    {"address":"aws_s3_bucket.a","type":"aws_s3_bucket","name":"a","mode":"managed","expressions":{}}
  ]}}
}`
	if err := os.WriteFile(filepath.Join(dir, "plan.json"), []byte(plan), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fray.yaml"), []byte("schema_version: fray-config/v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mitigations.yaml"), []byte("schema_version: mitigation/v1\nentries: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
