package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEnrollmentRejection(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		wantCode    string
		wantOK      bool
	}{
		{
			name:        "installation_inactive",
			status:      403,
			contentType: "application/json",
			body:        `{"error":"installation_inactive"}`,
			wantCode:    codeInstallationInactive,
			wantOK:      true,
		},
		{
			name:        "repo_not_enrolled charset",
			status:      403,
			contentType: "application/json; charset=utf-8",
			body:        `{"error":"repo_not_enrolled","message":""}`,
			wantCode:    codeRepoNotEnrolled,
			wantOK:      true,
		},
		{
			name:        "installation_over_cap with message",
			status:      403,
			contentType: "application/json",
			body:        `{"error":"installation_over_cap","message":"grants 4 repositories; free plan allows 3"}`,
			wantCode:    codeInstallationOverCap,
			wantOK:      true,
		},
		{
			name:        "unknown code fails closed",
			status:      403,
			contentType: "application/json",
			body:        `{"error":"something_else"}`,
			wantOK:      false,
		},
		{
			name:        "plain text 403",
			status:      403,
			contentType: "text/plain",
			body:        `forbidden`,
			wantOK:      false,
		},
		{
			name:        "401",
			status:      401,
			contentType: "application/json",
			body:        `{"error":"installation_inactive"}`,
			wantOK:      false,
		},
		{
			name:        "malformed json",
			status:      403,
			contentType: "application/json",
			body:        `{not json`,
			wantOK:      false,
		},
		{
			name:        "empty body",
			status:      403,
			contentType: "application/json",
			body:        ``,
			wantOK:      false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, msg, ok := parseEnrollmentRejection(tc.status, tc.contentType, []byte(tc.body))
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v (code=%q msg=%q)", ok, tc.wantOK, code, msg)
			}
			if !tc.wantOK {
				return
			}
			if code != tc.wantCode {
				t.Fatalf("code=%q want %q", code, tc.wantCode)
			}
		})
	}
}

func TestEnrollmentMessagesAndFailFlag(t *testing.T) {
	codes := []string{codeInstallationInactive, codeRepoNotEnrolled, codeInstallationOverCap}
	for _, code := range codes {
		for _, fail := range []bool{false, true} {
			t.Run(code+"_fail="+boolStr(fail), func(t *testing.T) {
				dir := t.TempDir()
				summary := filepath.Join(dir, "summary.md")
				t.Setenv("GITHUB_STEP_SUMMARY", summary)

				r, w, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				old := os.Stdout
				os.Stdout = w
				reportEnrollment(code, "", fail)
				_ = w.Close()
				os.Stdout = old
				out := make([]byte, 4096)
				n, _ := r.Read(out)
				_ = r.Close()
				got := string(out[:n])

				wantCmd := "::warning::"
				if fail {
					wantCmd = "::error::"
				}
				if !strings.HasPrefix(got, wantCmd) {
					t.Fatalf("annotation=%q want prefix %q", got, wantCmd)
				}
				primary := enrollmentPrimaryMessage(code)
				if !strings.Contains(got, escapeWorkflowCommand(primary)) {
					t.Fatalf("annotation missing primary message: %q", got)
				}

				sum, err := os.ReadFile(summary)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(sum), "## Fray — enrollment") {
					t.Fatalf("summary missing heading: %s", sum)
				}
				if !strings.Contains(got, "https://github.com/fluong/fray#troubleshooting") {
					t.Fatalf("annotation missing troubleshooting: %q", got)
				}
				if !strings.Contains(string(sum), sanitizeSummaryText(primary)) {
					t.Fatalf("summary missing message: %s", sum)
				}
			})
		}
	}
}

func TestServerMessageEscapedForCommandsAndSummary(t *testing.T) {
	hostile := "detail\n::error::injected <img src=x onerror=alert(1)>"
	dir := t.TempDir()
	summary := filepath.Join(dir, "summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	reportEnrollment(codeInstallationOverCap, hostile, false)
	_ = w.Close()
	os.Stdout = old
	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	_ = r.Close()
	annotation := string(buf[:n])

	// Workflow commands are line-oriented: a literal newline before ::error::
	// would inject a second command. After escape, the newline must be %0A.
	if strings.Contains(annotation, "\n::error::injected") {
		t.Fatalf("unescaped newline+command survived in annotation: %q", annotation)
	}
	if !strings.Contains(annotation, "%0A::error::injected") {
		t.Fatalf("expected newline escaped before ::error:: (%%0A…): %q", annotation)
	}
	// Only the leading ::warning:: delimiters should start a line.
	for _, line := range strings.Split(strings.TrimSuffix(annotation, "\n"), "\n") {
		if strings.HasPrefix(line, "::") && !strings.HasPrefix(line, "::warning::") {
			t.Fatalf("unexpected workflow command line: %q", line)
		}
	}

	sum, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	sumStr := string(sum)
	if strings.Contains(sumStr, "<img src=x") {
		t.Fatalf("unescaped HTML survived in summary: %s", sumStr)
	}
	if !strings.Contains(sumStr, "&lt;img src=x") {
		t.Fatalf("expected escaped img tag in summary: %s", sumStr)
	}
	if strings.Contains(sumStr, "\n::error::") {
		t.Fatalf("command injection in summary: %s", sumStr)
	}
}

func TestTruncateServerMessage(t *testing.T) {
	long := strings.Repeat("あ", maxServerMessageChars+10)
	got := formatEnrollmentNotice(codeInstallationOverCap, long)
	// Primary + " (" + truncated + "…)"
	if strings.Count(got, "あ") != maxServerMessageChars {
		t.Fatalf("rune count of server portion wrong in %q", got)
	}
	if !strings.HasSuffix(got, "…)") {
		t.Fatalf("want ellipsis suffix, got %q", got)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
