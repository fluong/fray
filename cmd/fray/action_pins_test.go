package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckActionPinsRejectsNonSHARefs(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, "scripts", "check-action-pins.sh")
	dir := t.TempDir()
	docs := filepath.Join(dir, "docs")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	good := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	body := "" +
		"- uses: actions/checkout@" + good + " # v7.0.1\n" +
		"- uses: actions/setup-go@<full-commit-sha> # placeholder\n" +
		"- uses: actions/setup-node@v4\n" +
		"- uses: actions/cache@main\n" +
		"- uses: actions/checkout@abc1234\n"
	if err := os.WriteFile(filepath.Join(docs, "pins.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script)
	cmd.Env = append(os.Environ(), "FRAY_ACTION_PINS_ROOT="+dir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit, got ok:\n%s", out)
	}
	text := string(out)
	for _, bad := range []string{
		"actions/setup-go@<full-commit-sha>",
		"actions/setup-node@v4",
		"actions/cache@main",
		"actions/checkout@abc1234",
	} {
		if !strings.Contains(text, bad) {
			t.Errorf("missing report for %q in:\n%s", bad, text)
		}
	}
	if !strings.Contains(text, "docs/pins.md:") {
		t.Errorf("want file:line reporting, got:\n%s", text)
	}
	if strings.Contains(text, "actions/checkout@"+good) && strings.Count(text, "unpinned uses:") < 4 {
		// good pin must not be the only reported line; ensure we still have 4 bad reports
	}
	if strings.Count(text, "unpinned uses:") < 4 {
		t.Fatalf("want ≥4 unpinned reports, got:\n%s", text)
	}
}
