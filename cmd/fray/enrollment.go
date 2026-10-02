package main

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Enrollment rejection codes from POST /v1/scans when OIDC is valid but the
// GitHub App installation does not cover this repository.
const (
	codeInstallationInactive = "installation_inactive"
	codeRepoNotEnrolled      = "repo_not_enrolled"
	codeInstallationOverCap  = "installation_over_cap"
)

const enrollmentMarkerFile = "enrollment.json"

const maxEnrollmentBody = 64 << 10 // 64 KiB
const maxServerMessageChars = 300

// Fixed Action messages (server message is untrusted and never used alone).
var enrollmentMessages = map[string]string{
	codeInstallationInactive: "The Fray GitHub App is not installed (or is suspended) for this account. Install it: https://github.com/apps/fray-getfray-dev",
	codeRepoNotEnrolled:      "This repository is not selected in the Fray GitHub App installation. Add it under Repository access: https://github.com/settings/installations",
	codeInstallationOverCap:  "The Fray installation grants access to more repositories than the free plan allows. Narrow repository access to the repos you want scanned: https://github.com/settings/installations",
}

func knownEnrollmentCode(code string) bool {
	_, ok := enrollmentMessages[code]
	return ok
}

type enrollmentBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// enrollmentMarker is written to ${FRAY_OUT}/enrollment.json on enrollment
// rejection. It never includes the untrusted server message.
type enrollmentMarker struct {
	Code   string `json:"code"`
	Failed bool   `json:"failed"`
}

// parseEnrollmentRejection returns the enrollment code and server message when
// the response is exactly a known enrollment rejection. Anything else is ok=false
// (caller must fail as a normal auth/transport error).
func parseEnrollmentRejection(status int, contentType string, body []byte) (code, serverMsg string, ok bool) {
	if status != 403 {
		return "", "", false
	}
	media := strings.TrimSpace(strings.Split(contentType, ";")[0])
	if !strings.EqualFold(media, "application/json") {
		return "", "", false
	}
	if len(body) == 0 {
		return "", "", false
	}
	var parsed enrollmentBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", "", false
	}
	if !knownEnrollmentCode(parsed.Error) {
		return "", "", false
	}
	return parsed.Error, parsed.Message, true
}

func enrollmentPrimaryMessage(code string) string {
	return enrollmentMessages[code]
}

// writeEnrollmentMarker records a known enrollment outcome for action/scan.sh.
func writeEnrollmentMarker(outDir, code string, failed bool) error {
	if !knownEnrollmentCode(code) {
		return fmt.Errorf("write enrollment marker: unknown code %q", code)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	body, err := json.Marshal(enrollmentMarker{Code: code, Failed: failed})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, enrollmentMarkerFile), append(body, '\n'), 0o644)
}

// escapeWorkflowCommand escapes text for GitHub Actions workflow-command
// properties so a hostile server message cannot inject "::error::" lines.
func escapeWorkflowCommand(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// sanitizeSummaryText makes untrusted text safe for $GITHUB_STEP_SUMMARY
// (Markdown that GitHub renders as HTML). Escapes HTML and collapses newlines.
func sanitizeSummaryText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\n", " ")
	return html.EscapeString(s)
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String() + "…"
}

// formatEnrollmentNotice builds the primary Action message, optionally
// appending a sanitized/truncated server message (for over_cap counts).
func formatEnrollmentNotice(code, serverMsg string) string {
	primary := enrollmentPrimaryMessage(code)
	serverMsg = strings.TrimSpace(serverMsg)
	if serverMsg == "" {
		return primary
	}
	serverMsg = truncateRunes(serverMsg, maxServerMessageChars)
	return primary + " (" + serverMsg + ")"
}

// reportEnrollment emits a workflow annotation and job-summary line.
// It never prints tokens or response headers.
func reportEnrollment(code, serverMsg string, fail bool) {
	notice := formatEnrollmentNotice(code, serverMsg)
	cmd := "warning"
	if fail {
		cmd = "error"
	}
	fmt.Fprintf(os.Stdout, "::%s::%s\n", cmd, escapeWorkflowCommand(notice))

	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		defer f.Close()
		_, _ = fmt.Fprintf(f, "## Fray\n\n%s\n", sanitizeSummaryText(notice))
	}
}

// scanExitDecision is what action/scan.sh does after the fray binary exits.
// ExitCode 0 means continue and write GITHUB_OUTPUT; non-zero means exit that status.
type scanExitDecision struct {
	Skipped    bool
	SkipReason string
	Blocked    bool
	ExitCode   int
	ErrMsg     string
}

// classifyScanExit mirrors action/scan.sh's rc + enrollment.json + SARIF table.
// markerOK is false when enrollment.json is missing; when true, marker is the
// parsed file (code may still be unknown).
func classifyScanExit(rc int, markerOK bool, marker enrollmentMarker, hasSARIF bool) scanExitDecision {
	if rc >= 2 || (rc != 0 && rc != 1) {
		return scanExitDecision{ExitCode: rc, ErrMsg: fmt.Sprintf("fray exited with status %d", rc)}
	}

	if markerOK {
		if !knownEnrollmentCode(marker.Code) {
			return scanExitDecision{ExitCode: 1, ErrMsg: "invalid enrollment marker code"}
		}
		switch rc {
		case 0:
			if marker.Failed {
				return scanExitDecision{ExitCode: 1, ErrMsg: "enrollment marker/rc mismatch"}
			}
			return scanExitDecision{Skipped: true, SkipReason: marker.Code}
		case 1:
			if !marker.Failed {
				return scanExitDecision{ExitCode: 1, ErrMsg: "enrollment marker/rc mismatch"}
			}
			return scanExitDecision{ExitCode: 1} // fail-on-unenrolled; annotation already emitted
		}
	}

	switch rc {
	case 0:
		if hasSARIF {
			return scanExitDecision{} // success
		}
		return scanExitDecision{ExitCode: 1, ErrMsg: "fray exited 0 without results"}
	case 1:
		if hasSARIF {
			return scanExitDecision{Blocked: true}
		}
		return scanExitDecision{ExitCode: 1, ErrMsg: "fray exited 1 without findings.sarif"}
	}
	return scanExitDecision{ExitCode: 1, ErrMsg: "unreachable"}
}
