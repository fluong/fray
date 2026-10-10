package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func parseActionStepConditions(t *testing.T) (conds map[string]string, bodies map[string]string) {
	t.Helper()
	yml, err := os.ReadFile(filepath.Join(repoRoot(t), "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(yml)
	conds = map[string]string{}
	bodies = map[string]string{}
	ifMulti := regexp.MustCompile(`(?m)^      if: >-\n((?:        .+\n)+)`)
	ifSingle := regexp.MustCompile(`(?m)^      if: (.+)\n`)
	for _, block := range strings.Split(text, "\n    - name: ")[1:] {
		name, rest, _ := strings.Cut(block, "\n")
		name = strings.TrimSpace(name)
		bodies[name] = rest
		if m := ifMulti.FindStringSubmatch(block); m != nil {
			conds[name] = regexp.MustCompile(`\s+`).ReplaceAllString(strings.TrimSpace(strings.ReplaceAll(m[1], "\n", " ")), " ")
			continue
		}
		if m := ifSingle.FindStringSubmatch(block); m != nil {
			conds[name] = strings.TrimSpace(m[1])
		}
	}
	return conds, bodies
}

func actionStepWouldRunMode(ifExpr string, outs map[string]string, mode string, showPayload, isPR, uploadSARIF bool) bool {
	if strings.Contains(ifExpr, "inputs.mode != 'check'") && mode == "check" {
		return false
	}
	if strings.Contains(ifExpr, "inputs.mode == 'check'") && mode != "check" {
		return false
	}
	return actionStepWouldRun(ifExpr, outs, showPayload, isPR, uploadSARIF)
}

func TestModeCheckInputContract(t *testing.T) {
	yml, err := os.ReadFile(filepath.Join(repoRoot(t), "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(yml)
	if !strings.Contains(text, "mode:") {
		t.Fatal("missing mode input")
	}
	if !strings.Contains(text, `default: "scan"`) {
		t.Fatal("mode default must be scan")
	}
	if !strings.Contains(text, "action/check.sh") {
		t.Fatal("missing check.sh step")
	}

	conds, bodies := parseActionStepConditions(t)

	scanCond, ok := conds["Fray scan"]
	if !ok {
		t.Fatal("Fray scan missing if:")
	}
	if !strings.Contains(scanCond, "inputs.mode != 'check'") {
		t.Fatalf("Fray scan must skip in check mode: %s", scanCond)
	}
	checkCond, ok := conds["Fray setup check"]
	if !ok {
		t.Fatal("Fray setup check missing if:")
	}
	if !strings.Contains(checkCond, "inputs.mode == 'check'") {
		t.Fatalf("setup check must require mode=check: %s", checkCond)
	}
	if !strings.Contains(bodies["Fray setup check"], "check.sh") {
		t.Fatal("setup check must run check.sh")
	}

	for _, name := range []string{"Upload sent payload", "Update PR comment", "Upload SARIF", "Gate"} {
		cond, ok := conds[name]
		if !ok {
			t.Fatalf("missing step %q", name)
		}
		if !strings.Contains(cond, "inputs.mode != 'check'") {
			t.Fatalf("step %q must gate on mode != check: %s", name, cond)
		}
	}

	forkFail, ok := conds["Fail setup check on fork PR"]
	if !ok {
		t.Fatal("missing Fail setup check on fork PR")
	}
	if !strings.Contains(forkFail, "inputs.mode == 'check'") {
		t.Fatalf("fork fail: %s", forkFail)
	}
	if !strings.Contains(bodies["Fail setup check on fork PR"], "workflow_dispatch") {
		t.Fatal("fork fail message must mention workflow_dispatch")
	}
	if !strings.Contains(bodies["Fail setup check on fork PR"], "::error::") {
		t.Fatal("fork setup check must hard-fail with ::error::")
	}

	// mode=check: post-scan steps must not run even if scan outputs look "ready".
	outs := map[string]string{
		"is_fork":     "false",
		"skipped":     "false",
		"has_sarif":   "true",
		"has_comment": "true",
		"has_payload": "true",
	}
	for _, name := range []string{"Upload sent payload", "Update PR comment", "Upload SARIF", "Gate", "Fray scan"} {
		if actionStepWouldRunMode(conds[name], outs, "check", true, true, true) {
			t.Fatalf("step %q must not run in mode=check", name)
		}
	}
	if !actionStepWouldRunMode(conds["Fray setup check"], outs, "check", true, true, true) {
		t.Fatal("Fray setup check should run in mode=check")
	}
	if actionStepWouldRunMode(conds["Fray setup check"], outs, "scan", true, true, true) {
		t.Fatal("Fray setup check must not run in mode=scan")
	}
	// mode=scan: scan runs; setup check does not.
	if !actionStepWouldRunMode(conds["Fray scan"], outs, "scan", true, true, true) {
		t.Fatal("Fray scan should run in mode=scan")
	}
}

func TestModeCheckNoTerraformPlanInCheckSh(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "action", "check.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, banned := range []string{"/v1/scans", "pr-comment.md", "findings.sarif", "upload-sarif"} {
		if strings.Contains(text, banned) {
			t.Fatalf("check.sh must not contain %q", banned)
		}
	}
	if regexp.MustCompile(`(?m)^\s*terraform\s+(plan|show)\b`).MatchString(text) {
		t.Fatal("check.sh must not run terraform plan/show")
	}
	if !strings.Contains(text, "-check") {
		t.Fatal("check.sh must invoke fray -check")
	}
}

func TestSetupTerraformRunsForCheckWithoutPlanFile(t *testing.T) {
	conds, _ := parseActionStepConditions(t)
	setup := conds["Setup Terraform"]
	if setup == "" {
		t.Fatal("Setup Terraform missing")
	}
	// Same as scan: run when plan-file empty (covers check mode validate path).
	if !strings.Contains(setup, "inputs.plan-file == ''") {
		t.Fatalf("%s", setup)
	}
	// Must not exclude check mode.
	if strings.Contains(setup, "mode") {
		t.Fatalf("Setup Terraform should not special-case mode (needed for check validate): %s", setup)
	}
}
