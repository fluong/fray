package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func parseGitHubOutput(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("bad GITHUB_OUTPUT line: %q", line)
		}
		out[k] = v
	}
	return out
}

// actionStepWouldRun evaluates the subset of composite if: expressions we use
// after the scan step (fork + skipped + has_* + show-payload + event).
func actionStepWouldRun(ifExpr string, outs map[string]string, showPayload bool, isPR bool) bool {
	if strings.Contains(ifExpr, "steps.fork.outputs.is_fork != 'true'") && outs["is_fork"] == "true" {
		return false
	}
	if strings.Contains(ifExpr, "steps.scan.outputs.skipped != 'true'") && outs["skipped"] == "true" {
		return false
	}
	if strings.Contains(ifExpr, "steps.scan.outputs.has_sarif == 'true'") && outs["has_sarif"] != "true" {
		return false
	}
	if strings.Contains(ifExpr, "steps.scan.outputs.has_comment == 'true'") && outs["has_comment"] != "true" {
		return false
	}
	if strings.Contains(ifExpr, "steps.scan.outputs.has_payload == 'true'") && outs["has_payload"] != "true" {
		return false
	}
	if strings.Contains(ifExpr, "inputs.show-payload == 'true'") && !showPayload {
		return false
	}
	if strings.Contains(ifExpr, "github.event_name == 'pull_request'") && !isPR {
		return false
	}
	return true
}

func TestClassifyScanExitTable(t *testing.T) {
	tests := []struct {
		name       string
		rc         int
		markerOK   bool
		marker     enrollmentMarker
		hasSARIF   bool
		wantSkip   bool
		wantReason string
		wantBlock  bool
		wantExit   int
		wantErr    string // substring; empty if no error msg required
	}{
		{
			name:       "rc0_marker_failed_false_skip",
			rc:         0,
			markerOK:   true,
			marker:     enrollmentMarker{Code: codeRepoNotEnrolled, Failed: false},
			wantSkip:   true,
			wantReason: codeRepoNotEnrolled,
		},
		{
			name:     "rc0_no_marker_with_sarif_success",
			rc:       0,
			hasSARIF: true,
		},
		{
			name:     "rc0_no_marker_no_sarif_error",
			rc:       0,
			wantExit: 1,
			wantErr:  "fray exited 0 without results",
		},
		{
			name:     "rc1_marker_failed_true_fail_on_unenrolled",
			rc:       1,
			markerOK: true,
			marker:   enrollmentMarker{Code: codeInstallationInactive, Failed: true},
			wantExit: 1,
		},
		{
			name:      "rc1_no_marker_with_sarif_blocked",
			rc:        1,
			hasSARIF:  true,
			wantBlock: true,
		},
		{
			name:     "rc1_no_marker_no_sarif_error",
			rc:       1,
			wantExit: 1,
			wantErr:  "fray exited 1 without findings.sarif",
		},
		{
			name:     "rc0_marker_unknown_code",
			rc:       0,
			markerOK: true,
			marker:   enrollmentMarker{Code: "not_a_real_code", Failed: false},
			wantExit: 1,
			wantErr:  "invalid enrollment marker code",
		},
		{
			name:     "rc1_marker_unknown_code",
			rc:       1,
			markerOK: true,
			marker:   enrollmentMarker{Code: "not_a_real_code", Failed: true},
			wantExit: 1,
			wantErr:  "invalid enrollment marker code",
		},
		{
			name:     "rc0_marker_failed_true_mismatch",
			rc:       0,
			markerOK: true,
			marker:   enrollmentMarker{Code: codeInstallationOverCap, Failed: true},
			wantExit: 1,
			wantErr:  "enrollment marker/rc mismatch",
		},
		{
			name:     "rc1_marker_failed_false_mismatch",
			rc:       1,
			markerOK: true,
			marker:   enrollmentMarker{Code: codeInstallationOverCap, Failed: false},
			wantExit: 1,
			wantErr:  "enrollment marker/rc mismatch",
		},
		{
			name:     "rc2_unchanged",
			rc:       2,
			wantExit: 2,
			wantErr:  "fray exited with status 2",
		},
		{
			name:       "rc0_each_known_code_installation_inactive",
			rc:         0,
			markerOK:   true,
			marker:     enrollmentMarker{Code: codeInstallationInactive, Failed: false},
			wantSkip:   true,
			wantReason: codeInstallationInactive,
		},
		{
			name:       "rc0_each_known_code_installation_over_cap",
			rc:         0,
			markerOK:   true,
			marker:     enrollmentMarker{Code: codeInstallationOverCap, Failed: false},
			wantSkip:   true,
			wantReason: codeInstallationOverCap,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyScanExit(tc.rc, tc.markerOK, tc.marker, tc.hasSARIF)
			if got.Skipped != tc.wantSkip {
				t.Fatalf("Skipped=%v want %v", got.Skipped, tc.wantSkip)
			}
			if got.SkipReason != tc.wantReason {
				t.Fatalf("SkipReason=%q want %q", got.SkipReason, tc.wantReason)
			}
			if got.Blocked != tc.wantBlock {
				t.Fatalf("Blocked=%v want %v", got.Blocked, tc.wantBlock)
			}
			if got.ExitCode != tc.wantExit {
				t.Fatalf("ExitCode=%d want %d (err=%q)", got.ExitCode, tc.wantExit, got.ErrMsg)
			}
			if tc.wantErr != "" && !strings.Contains(got.ErrMsg, tc.wantErr) {
				t.Fatalf("ErrMsg=%q want substring %q", got.ErrMsg, tc.wantErr)
			}
			if got.Skipped && !knownEnrollmentCode(got.SkipReason) {
				t.Fatalf("skip_reason %q must be a known code", got.SkipReason)
			}
		})
	}
}

func TestEnrollmentSkipWritesMarkerAndGatesArtifacts(t *testing.T) {
	dir := t.TempDir()
	writeMinimalScanInputs(t, dir)
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))
	t.Setenv("GITHUB_STEP_SUMMARY", filepath.Join(dir, "summary.md"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"repo_not_enrolled","message":"server detail with secrets"}`))
	}))
	t.Cleanup(srv.Close)

	outDir := filepath.Join(dir, "out")
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
		Out:           outDir,
	}
	blocked, err := runRemote(opt)
	if err != nil {
		t.Fatalf("skip path err=%v", err)
	}
	if blocked {
		t.Fatal("must not be gate-blocked")
	}
	if _, err := os.Stat(filepath.Join(outDir, "findings.sarif")); !os.IsNotExist(err) {
		t.Fatalf("findings.sarif must not exist on skip: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(outDir, enrollmentMarkerFile))
	if err != nil {
		t.Fatalf("enrollment.json: %v", err)
	}
	if strings.Contains(string(raw), "server detail") {
		t.Fatalf("server message must not appear in marker: %s", raw)
	}
	var marker enrollmentMarker
	if err := json.Unmarshal(raw, &marker); err != nil {
		t.Fatal(err)
	}
	if marker.Code != codeRepoNotEnrolled || marker.Failed {
		t.Fatalf("marker=%+v", marker)
	}

	dec := classifyScanExit(0, true, marker, false)
	if !dec.Skipped || dec.SkipReason != codeRepoNotEnrolled || dec.ExitCode != 0 {
		t.Fatalf("decision=%+v", dec)
	}

	// Simulate scan.sh GITHUB_OUTPUT for this decision.
	ghOut := filepath.Join(dir, "github_output")
	if err := os.WriteFile(ghOut, []byte(
		"skipped=true\nskip_reason="+dec.SkipReason+"\nblocked=false\nhas_sarif=false\nhas_comment=false\nhas_payload=false\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	outs := parseGitHubOutput(t, ghOut)
	outs["is_fork"] = "false"

	yml, err := os.ReadFile(filepath.Join(repoRoot(t), "action.yml"))
	if err != nil {
		t.Fatalf("read action.yml: %v", err)
	}
	steps := map[string]string{
		"Upload sent payload": "",
		"Update PR comment":   "",
		"Upload SARIF":        "",
		"Gate":                "",
	}
	blocks := strings.Split(string(yml), "\n    - name: ")
	ifRe := regexp.MustCompile(`(?m)^      if: >-\n((?:        .+\n)+)`)
	for _, block := range blocks[1:] {
		name, _, _ := strings.Cut(block, "\n")
		name = strings.TrimSpace(name)
		if _, ok := steps[name]; !ok {
			continue
		}
		m := ifRe.FindStringSubmatch(block)
		if m == nil {
			t.Fatalf("action.yml step %q has no if: >- block", name)
		}
		cond := regexp.MustCompile(`\s+`).ReplaceAllString(strings.TrimSpace(strings.ReplaceAll(m[1], "\n", " ")), " ")
		steps[name] = cond
	}
	for name, cond := range steps {
		if !strings.Contains(cond, "steps.scan.outputs.skipped != 'true'") {
			t.Fatalf("step %q if: must gate on skipped != true\ngot: %s", name, cond)
		}
		if actionStepWouldRun(cond, outs, true, true) {
			t.Fatalf("step %q would still run on enrollment skip", name)
		}
	}
}

func TestEnrollmentFailWritesMarkerFailedTrue(t *testing.T) {
	dir := t.TempDir()
	writeMinimalScanInputs(t, dir)
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))
	t.Setenv("GITHUB_STEP_SUMMARY", filepath.Join(dir, "summary.md"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"installation_over_cap","message":"grants 9"}`))
	}))
	t.Cleanup(srv.Close)

	outDir := filepath.Join(dir, "out")
	_, err := runRemote(options{
		Plan:             filepath.Join(dir, "plan.json"),
		Source:           filepath.Join(dir, "infra"),
		Config:           filepath.Join(dir, "fray.yaml"),
		Mitigations:      filepath.Join(dir, "mitigations.yaml"),
		Remote:           srv.URL,
		Repo:             "acme/widgets",
		Commit:           "abc123",
		Branch:           "main",
		DefaultBranch:    "main",
		OIDCToken:        "tok",
		Out:              outDir,
		FailOnUnenrolled: true,
	})
	if err == nil {
		t.Fatal("want errEnrollmentRejected")
	}
	raw, err := os.ReadFile(filepath.Join(outDir, enrollmentMarkerFile))
	if err != nil {
		t.Fatal(err)
	}
	var marker enrollmentMarker
	if err := json.Unmarshal(raw, &marker); err != nil {
		t.Fatal(err)
	}
	if marker.Code != codeInstallationOverCap || !marker.Failed {
		t.Fatalf("marker=%+v", marker)
	}
	dec := classifyScanExit(1, true, marker, false)
	if dec.ExitCode != 1 || dec.Skipped || dec.Blocked {
		t.Fatalf("decision=%+v", dec)
	}
}
