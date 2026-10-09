package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanShFailOnRateLimit(t *testing.T) {
	script := filepath.Join(repoRoot(t), "action", "scan.sh")
	hostile := "%0A::error::x"

	for _, fail := range []bool{false, true} {
		t.Run("fail="+boolStr(fail), func(t *testing.T) {
			dir := t.TempDir()
			summary := filepath.Join(dir, "summary.md")
			cmd := exec.Command("bash", script, "--self-test-rate-limit", hostile, "45")
			cmd.Env = append(os.Environ(),
				"FRAY_FAIL_ON_RATE_LIMIT="+boolStr(fail),
				"GITHUB_STEP_SUMMARY="+summary,
			)
			out, err := cmd.CombinedOutput()
			got := string(out)

			if fail {
				if err == nil {
					t.Fatalf("want non-zero exit, got output %q", got)
				}
				if !strings.HasPrefix(strings.TrimSpace(got), "::error::") {
					t.Fatalf("want ::error::, got %q", got)
				}
			} else {
				if err != nil {
					t.Fatalf("want exit 0, err=%v out=%q", err, got)
				}
				if !strings.HasPrefix(strings.TrimSpace(got), "::warning::") {
					t.Fatalf("want ::warning::, got %q", got)
				}
			}

			if strings.Contains(got, "\n::error::x") {
				t.Fatalf("unescaped workflow injection survived: %q", got)
			}
			if !strings.Contains(got, "%250A::error::x") {
				t.Fatalf("want escaped %%0A in annotation: %q", got)
			}
			if !strings.Contains(got, "retry after 45 s") {
				t.Fatalf("missing retry after: %q", got)
			}
			if !strings.Contains(got, "30 scans/repo/hour") {
				t.Fatalf("missing free-plan limits: %q", got)
			}
			if !strings.Contains(got, "https://github.com/fluong/fray#troubleshooting") {
				t.Fatalf("missing troubleshooting anchor: %q", got)
			}

			sum, err := os.ReadFile(summary)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(sum), "## Fray") {
				t.Fatalf("summary=%s", sum)
			}
			if !strings.Contains(string(sum), "retry after 45 s") {
				t.Fatalf("summary missing retry: %s", sum)
			}
		})
	}
}

func TestScanShFailOnSkipRateLimit(t *testing.T) {
	script := filepath.Join(repoRoot(t), "action", "scan.sh")
	cmd := exec.Command("bash", script, "--self-test-rate-limit", "quota", "9")
	cmd.Env = append(os.Environ(),
		"FRAY_FAIL_ON_SKIP=true",
		"FRAY_FAIL_ON_RATE_LIMIT=false",
	)
	out, err := cmd.CombinedOutput()
	got := string(out)
	if err == nil {
		t.Fatalf("fail-on-skip should fail soft rate-limit skip, got %q", got)
	}
	if !strings.HasPrefix(strings.TrimSpace(got), "::error::") {
		t.Fatalf("want ::error::, got %q", got)
	}
	if !strings.Contains(got, "30 scans/repo/hour") || !strings.Contains(got, "https://github.com/fluong/fray#troubleshooting") {
		t.Fatalf("want limits + troubleshooting: %q", got)
	}
}

func TestScanShParseRateLimitedMultilineMessage(t *testing.T) {
	script := filepath.Join(repoRoot(t), "action", "scan.sh")
	dir := t.TempDir()
	marker := filepath.Join(dir, "enrollment.json")
	// Newlines in the message must not shift retry_after off line 2.
	body := "{\n  \"status\": \"rate_limited\",\n  \"message\": \"hello\\n2\\n::error::x\",\n  \"retry_after\": 7\n}\n"
	if err := os.WriteFile(marker, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	summary := filepath.Join(dir, "summary.md")
	cmd := exec.Command("bash", script, "--self-test-parse-marker", marker)
	cmd.Env = append(os.Environ(),
		"FRAY_FAIL_ON_RATE_LIMIT=false",
		"GITHUB_STEP_SUMMARY="+summary,
	)
	out, err := cmd.CombinedOutput()
	got := string(out)
	if err != nil {
		t.Fatalf("parse+handle err=%v out=%q", err, got)
	}
	if !strings.Contains(got, "retry after 7 s") {
		t.Fatalf("want retry 7 in notice, got %q", got)
	}
	if strings.Contains(got, "\n::error::x") {
		t.Fatalf("unescaped injection: %q", got)
	}
	// Collapsed newlines become spaces; ::error:: remains but is on the warning line (escaped % if needed).
	if !strings.Contains(got, "::warning::") {
		t.Fatalf("want ::warning::, got %q", got)
	}
	if !strings.Contains(got, "hello 2 ::error::x") && !strings.Contains(got, "hello 2 %3A%3Aerror%3A%3Ax") {
		// escape_workflow_command does not escape ':' — plain "::error::" on same line after ::warning:: is OK
		// as long as it is not a new command line.
		if !strings.Contains(got, "hello 2 ::error::x") {
			t.Fatalf("collapsed message missing: %q", got)
		}
	}
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if strings.HasPrefix(line, "::") && !strings.HasPrefix(line, "::warning::") {
			t.Fatalf("unexpected workflow command line: %q", line)
		}
	}
}

func TestScanShRejectsBoolRetryAfter(t *testing.T) {
	script := filepath.Join(repoRoot(t), "action", "scan.sh")
	dir := t.TempDir()
	marker := filepath.Join(dir, "enrollment.json")
	if err := os.WriteFile(marker, []byte(`{"status":"rate_limited","message":"x","retry_after":true}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script, "--self-test-parse-marker", marker)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("want invalid marker, got %q", out)
	}
	got := string(out)
	if !strings.Contains(got, "invalid enrollment.json") && !strings.Contains(got, "invalid rate_limited marker") {
		t.Fatalf("want invalid marker error, got %q", got)
	}
}

func TestScanShClearsStaleMarker(t *testing.T) {
	script := filepath.Join(repoRoot(t), "action", "scan.sh")
	dir := t.TempDir()
	marker := filepath.Join(dir, "enrollment.json")
	if err := os.WriteFile(marker, []byte(`{"status":"rate_limited","message":"stale","retry_after":9}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script, "--self-test-clear-stale-marker")
	cmd.Env = append(os.Environ(), "FRAY_OUT="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clear err=%v out=%q", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("stale marker still present: %v", err)
	}

	// Production path: same rm -f runs immediately before the fray binary.
	raw, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	idxClear := strings.Index(src, `rm -f "${FRAY_OUT}/enrollment.json"`)
	idxFray := strings.Index(src, `"$FRAY_BIN" "${args[@]}"`)
	if idxClear < 0 {
		t.Fatal("missing rm -f of enrollment.json before fray")
	}
	if idxFray < 0 || idxClear > idxFray {
		t.Fatal("enrollment.json clear must run before invoking fray")
	}
}
