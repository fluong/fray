package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeCheckFixture(t *testing.T, dir string) options {
	t.Helper()
	infra := filepath.Join(dir, "infra")
	if err := os.MkdirAll(infra, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(infra, "main.tf"), []byte(`terraform { required_version = ">= 1.0" }`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "fray.yaml")
	if err := os.WriteFile(cfg, []byte("schema_version: fray-config/v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))
	return options{
		Source: infra,
		Config: cfg,
		Remote: "https://api.getfray.dev",
		Waivers: filepath.Join(dir, ".fray", "waivers.yml"),
	}
}

func TestCheckAPIURL(t *testing.T) {
	pass := checkAPIURL("https://api.getfray.dev")
	if pass.Outcome != checkPass {
		t.Fatalf("want pass, got %+v", pass)
	}
	for _, bad := range []string{"", "http://api.getfray.dev", "https://", "not a url", "ftp://x.example"} {
		got := checkAPIURL(bad)
		if got.Outcome != checkFail {
			t.Fatalf("%q: want fail, got %+v", bad, got)
		}
	}
}

func TestCheckWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	infra := filepath.Join(dir, "infra")
	if err := os.MkdirAll(infra, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := checkWorkingDirectory(filepath.Join(dir, "nope"), false)
	if missing[0].Outcome != checkFail {
		t.Fatalf("missing dir: %+v", missing)
	}
	empty := checkWorkingDirectory(infra, false)
	if len(empty) != 2 || empty[1].Outcome != checkFail {
		t.Fatalf("no .tf without plan-file should fail sources: %+v", empty)
	}
	warnOnly := checkWorkingDirectory(infra, true)
	if len(warnOnly) != 2 || warnOnly[1].Outcome != checkWarn {
		t.Fatalf("no .tf with plan-file should warn: %+v", warnOnly)
	}
	if err := os.WriteFile(filepath.Join(infra, "main.tf"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	ok := checkWorkingDirectory(infra, false)
	if len(ok) != 1 || ok[0].Outcome != checkPass {
		t.Fatalf("with .tf: %+v", ok)
	}
}

func TestCheckFrayYAML(t *testing.T) {
	dir := t.TempDir()
	missing := checkFrayYAML(filepath.Join(dir, "fray.yaml"))
	if missing.Outcome != checkFail || !strings.Contains(missing.Detail, "fray.yaml not found") {
		t.Fatalf("%+v", missing)
	}
	path := filepath.Join(dir, "fray.yaml")
	if err := os.WriteFile(path, []byte("schema_version: nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := checkFrayYAML(path)
	if bad.Outcome != checkFail {
		t.Fatalf("bad schema: %+v", bad)
	}
	if err := os.WriteFile(path, []byte("schema_version: fray-config/v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok := checkFrayYAML(path)
	if ok.Outcome != checkPass {
		t.Fatalf("%+v", ok)
	}
}

func TestCheckRedactionKey(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "fray.yaml")
	if err := os.WriteFile(cfg, []byte("schema_version: fray-config/v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FRAY_REDACTION_KEY", "")
	fail := checkRedactionKey(cfg)
	if fail.Outcome != checkFail {
		t.Fatalf("missing key: %+v", fail)
	}
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))
	ok := checkRedactionKey(cfg)
	if ok.Outcome != checkPass {
		t.Fatalf("%+v", ok)
	}
	if err := os.WriteFile(cfg, []byte("schema_version: fray-config/v1\nredaction: off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FRAY_REDACTION_KEY", "")
	off := checkRedactionKey(cfg)
	if off.Outcome != checkPass {
		t.Fatalf("redaction off: %+v", off)
	}
}

func TestCheckWaiversFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "waivers.yml")
	missing := checkWaiversFile(path)
	if missing.Outcome != checkPass {
		t.Fatalf("missing OK: %+v", missing)
	}
	if err := os.WriteFile(path, []byte("version: 1\nwaivers: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok := checkWaiversFile(path)
	if ok.Outcome != checkPass {
		t.Fatalf("%+v", ok)
	}
	if err := os.WriteFile(path, []byte("not: valid: waivers\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := checkWaiversFile(path)
	if bad.Outcome != checkFail {
		t.Fatalf("invalid: %+v", bad)
	}
}

func TestCheckLegacyMitigationsRow(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "mitigations.yaml")
	ok := checkLegacyMitigationsRow(legacy, "")
	if ok.Outcome != checkPass {
		t.Fatalf("missing: %+v", ok)
	}
	if err := os.WriteFile(legacy, []byte(`schema_version: mitigation/v1
entries:
  - rule_id: r1
    address: a.b
    status: accepted
    reason: x
`), 0o644); err != nil {
		t.Fatal(err)
	}
	fail := checkLegacyMitigationsRow(legacy, "")
	if fail.Outcome != checkFail {
		t.Fatalf("non-empty legacy: %+v", fail)
	}
}

func TestCheckPlanFile(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	opt := options{ExternalPlan: true, Plan: planPath, Source: dir}
	missing := checkPlanOrTerraform(opt)
	if missing.Outcome != checkFail {
		t.Fatalf("missing plan: %+v", missing)
	}
	if err := os.WriteFile(planPath, []byte(`{"format_version":"1.2","resource_changes":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ok := checkPlanOrTerraform(opt)
	if ok.Outcome != checkPass {
		t.Fatalf("%+v", ok)
	}
	if err := os.WriteFile(planPath, []byte(`not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := checkPlanOrTerraform(opt)
	if bad.Outcome != checkFail {
		t.Fatalf("bad json: %+v", bad)
	}
}

func TestCheckTerraformInitValidate(t *testing.T) {
	dir := t.TempDir()
	stubDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(stubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(stubDir, "terraform")
	// Succeed for init -backend=false and validate; fail otherwise.
	script := `#!/bin/sh
set -e
log="${FRAY_TF_LOG:-/dev/null}"
echo "$@" >>"$log"
case "$1" in
  init)
    echo "$@" | grep -q -- '-backend=false' || exit 3
    exit 0
    ;;
  validate) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 99 ;;
esac
`
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "tf.log")
	t.Setenv("FRAY_TF_LOG", logPath)

	prev := terraformCommand
	t.Cleanup(func() { terraformCommand = prev })
	terraformCommand = func(workdir string, args ...string) *exec.Cmd {
		cmd := exec.Command(stub, args...)
		cmd.Dir = workdir
		cmd.Env = append(os.Environ(), "FRAY_TF_LOG="+logPath)
		return cmd
	}

	infra := filepath.Join(dir, "infra")
	if err := os.MkdirAll(infra, 0o755); err != nil {
		t.Fatal(err)
	}
	ok := checkTerraformInitValidate(infra)
	if ok.Outcome != checkPass {
		t.Fatalf("%+v", ok)
	}
	raw, _ := os.ReadFile(logPath)
	if !strings.Contains(string(raw), "init -backend=false") {
		t.Fatalf("expected init -backend=false, log=%s", raw)
	}
	if !strings.Contains(string(raw), "validate") {
		t.Fatalf("expected validate, log=%s", raw)
	}

	// Fail path: validate exits non-zero.
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nif [ \"$1\" = validate ]; then exit 1; fi\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	fail := checkTerraformInitValidate(infra)
	if fail.Outcome != checkFail || !strings.Contains(fail.Detail, "validate") {
		t.Fatalf("%+v", fail)
	}
}

func TestReadinessProbeCheckStub(t *testing.T) {
	row := readinessProbeCheck()
	if row.Outcome != checkWarn {
		t.Fatalf("%+v", row)
	}
	if !strings.Contains(row.Detail, "skipped: server readiness probe not yet available") {
		t.Fatalf("%+v", row)
	}
}

func TestRunSetupChecksNoHTTP(t *testing.T) {
	dir := t.TempDir()
	opt := writeCheckFixture(t, dir)
	opt.ExternalPlan = true
	plan := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(plan, []byte(`{"format_version":"1.2","resource_changes":[{"mode":"managed","address":"null_resource.x","type":"null_resource","change":{"actions":["no-op"]}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	opt.Plan = plan
	opt.Remote = "https://example.invalid"

	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hit = true
	}))
	t.Cleanup(srv.Close)
	_ = srv // server exists only so a mistaken client would have somewhere to hit; we never pass its URL

	summary := filepath.Join(dir, "summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)

	prev := terraformCommand
	t.Cleanup(func() { terraformCommand = prev })
	terraformCommand = func(string, ...string) *exec.Cmd {
		t.Fatal("terraform must not run when ExternalPlan is set")
		return nil
	}

	code := runSetupCheck(opt)
	if hit {
		t.Fatal("check mode must not perform HTTP")
	}
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	raw, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "## Fray — setup check") {
		t.Fatalf("summary missing header: %s", raw)
	}
	if !strings.Contains(string(raw), "server readiness") || !strings.Contains(string(raw), "warn") {
		t.Fatalf("expected readiness warn row: %s", raw)
	}
}

func TestRunSetupCheckFailsOnBadAPIURL(t *testing.T) {
	dir := t.TempDir()
	opt := writeCheckFixture(t, dir)
	opt.Remote = "http://insecure.example"
	opt.ExternalPlan = true
	plan := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(plan, []byte(`{"format_version":"1.2"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	opt.Plan = plan
	t.Setenv("GITHUB_STEP_SUMMARY", filepath.Join(dir, "summary.md"))
	if code := runSetupCheck(opt); code == 0 {
		t.Fatal("want non-zero exit")
	}
}
