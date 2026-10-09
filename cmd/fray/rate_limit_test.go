package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRateLimited(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		hdr         string
		wantMsg     string
		wantRetry   int
		wantOK      bool
	}{
		{
			name:        "json body",
			status:      429,
			contentType: "application/json",
			body:        `{"error":"rate_limited","message":"Hourly scan limit for this repository reached","retry_after":42}`,
			wantMsg:     "Hourly scan limit for this repository reached",
			wantRetry:   42,
			wantOK:      true,
		},
		{
			name:        "retry_after 0 uses header then ok",
			status:      429,
			contentType: "application/json; charset=utf-8",
			body:        `{"error":"rate_limited","message":"Daily scan limit for this organization reached","retry_after":0}`,
			hdr:         "90",
			wantMsg:     "Daily scan limit for this organization reached",
			wantRetry:   90,
			wantOK:      true,
		},
		{
			name:        "retry_after 0 with no header raises to 1",
			status:      429,
			contentType: "application/json",
			body:        `{"error":"rate_limited","message":"Hourly scan limit for this repository reached","retry_after":0}`,
			wantMsg:     "Hourly scan limit for this repository reached",
			wantRetry:   1,
			wantOK:      true,
		},
		{
			name:        "non-json 429",
			status:      429,
			contentType: "text/plain",
			body:        `slow down`,
			wantOK:      false,
		},
		{
			name:        "malformed json",
			status:      429,
			contentType: "application/json",
			body:        `{not json`,
			wantOK:      false,
		},
		{
			name:        "wrong error code",
			status:      429,
			contentType: "application/json",
			body:        `{"error":"other","message":"x","retry_after":5}`,
			wantOK:      false,
		},
		{
			name:        "missing retry_after raises to 1",
			status:      429,
			contentType: "application/json",
			body:        `{"error":"rate_limited","message":"x"}`,
			wantMsg:     "x",
			wantRetry:   1,
			wantOK:      true,
		},
		{
			name:        "403 is not rate_limited",
			status:      403,
			contentType: "application/json",
			body:        `{"error":"rate_limited","message":"x","retry_after":5}`,
			wantOK:      false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg, ra, ok := parseRateLimited(tc.status, tc.contentType, []byte(tc.body), tc.hdr)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v (msg=%q ra=%d)", ok, tc.wantOK, msg, ra)
			}
			if !tc.wantOK {
				return
			}
			if msg != tc.wantMsg || ra != tc.wantRetry {
				t.Fatalf("msg=%q ra=%d want %q %d", msg, ra, tc.wantMsg, tc.wantRetry)
			}
		})
	}
}

func TestRemoteRateLimitedSoftSkip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate_limited","message":"Hourly scan limit for this repository reached","retry_after":60}`))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	writeMinimalScanInputs(t, dir)
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))

	stderrPath := filepath.Join(dir, "stderr.txt")
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	oldErr := os.Stderr
	os.Stderr = stderrFile
	outDir := filepath.Join(dir, "out")
	blocked, err := runRemote(options{
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
	})
	_ = stderrFile.Close()
	os.Stderr = oldErr

	if err != nil {
		t.Fatalf("soft-skip err=%v", err)
	}
	if blocked {
		t.Fatal("must not be gate-blocked")
	}
	if _, err := os.Stat(filepath.Join(outDir, "findings.sarif")); !os.IsNotExist(err) {
		t.Fatalf("SARIF must not exist: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(outDir, enrollmentMarkerFile))
	if err != nil {
		t.Fatalf("marker: %v", err)
	}
	var marker rateLimitedMarker
	if err := json.Unmarshal(raw, &marker); err != nil {
		t.Fatal(err)
	}
	if marker.Status != statusRateLimited || marker.RetryAfter != 60 {
		t.Fatalf("marker=%+v", marker)
	}
	if marker.Message != "Hourly scan limit for this repository reached" {
		t.Fatalf("message=%q", marker.Message)
	}

	stderrBytes, err := os.ReadFile(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	stderr := string(stderrBytes)
	if !strings.Contains(stderr, "fray: rate limited:") {
		t.Fatalf("stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "retry after 60 s") {
		t.Fatalf("stderr missing retry: %q", stderr)
	}
	if !strings.Contains(stderr, "30 scans/repo/hour") {
		t.Fatalf("stderr missing free-plan limits: %q", stderr)
	}
	if !strings.Contains(stderr, "https://github.com/fluong/fray#troubleshooting") {
		t.Fatalf("stderr missing troubleshooting: %q", stderr)
	}
}

func TestRemoteRateLimitedNonJSONFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("too many requests"))
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
		OIDCToken:     "tok",
		Out:           filepath.Join(dir, "out"),
	})
	if err == nil {
		t.Fatal("expected generic error for non-JSON 429")
	}
	if !strings.Contains(err.Error(), "429") && !strings.Contains(err.Error(), "Too Many") {
		t.Fatalf("want ordinary remote error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out", enrollmentMarkerFile)); !os.IsNotExist(statErr) {
		t.Fatal("must not write marker on generic 429")
	}
}

func TestRateLimitedHostileMessageEscaped(t *testing.T) {
	hostile := "%0A::error::x"
	notice := formatRateLimitedNotice(hostile, 15)
	escaped := escapeWorkflowCommand(notice)
	if strings.Contains(escaped, "\n") {
		t.Fatalf("newline survived: %q", escaped)
	}
	// Leading % in %0A must become %25 so the sequence cannot decode to a newline command.
	if !strings.Contains(escaped, "%250A::error::x") {
		t.Fatalf("want escaped %%0A sequence, got %q", escaped)
	}
	summary := sanitizeSummaryText(notice)
	if strings.Contains(summary, "\n::error::") {
		t.Fatalf("command injection in summary text: %q", summary)
	}
}
