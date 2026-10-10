package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fluong/fray/client"
	"gopkg.in/yaml.v3"
)

func TestActionYMLSkipsTerraformWhenPlanFileSet(t *testing.T) {
	yml, err := os.ReadFile(filepath.Join(repoRoot(t), "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(yml)
	if !strings.Contains(text, "plan-file:") {
		t.Fatal("missing plan-file input")
	}
	if !strings.Contains(text, "FRAY_PLAN_FILE:") {
		t.Fatal("scan step must pass FRAY_PLAN_FILE")
	}
	setup := ""
	for _, block := range strings.Split(text, "\n    - name: ")[1:] {
		name, rest, _ := strings.Cut(block, "\n")
		if strings.TrimSpace(name) == "Setup Terraform" {
			setup = rest
			break
		}
	}
	if setup == "" {
		t.Fatal("Setup Terraform step missing")
	}
	if !strings.Contains(setup, "inputs.plan-file == ''") {
		t.Fatalf("Setup Terraform must skip when plan-file is set; got:\n%s", setup)
	}
}

func TestScanShPlanFileSkipsTerraformBinary(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()
	workdir := filepath.Join(dir, "infra")
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "main.tf"), []byte(`resource "null_resource" "x" {}`), 0o644); err != nil {
		t.Fatal(err)
	}
	plan := `{
	  "format_version": "1.2",
	  "resource_changes": [{
	    "address": "null_resource.x",
	    "mode": "managed",
	    "type": "null_resource",
	    "change": {"actions": ["no-op"], "after": {}}
	  }]
	}`
	if err := os.WriteFile(filepath.Join(workdir, "plan.json"), []byte(plan), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fray.yaml"), []byte("schema_version: fray-config/v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tfStub := filepath.Join(binDir, "terraform")
	// Fail loudly if terraform is invoked — plan-file path must not call it.
	if err := os.WriteFile(tfStub, []byte("#!/bin/sh\necho terraform-was-invoked >&2\nexit 99\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	frayStub := filepath.Join(binDir, "fray")
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Minimal successful fray stub: require -external-plan and write SARIF so scan.sh exits 0.
	frayScript := `#!/bin/sh
set -e
has_external=
for a in "$@"; do
  if [ "$a" = "-external-plan" ]; then has_external=1; fi
done
if [ -z "$has_external" ]; then
  echo "missing -external-plan" >&2
  exit 2
fi
out=.
prev=
for a in "$@"; do
  if [ "$prev" = "-out" ]; then out=$a; fi
  prev=$a
done
printf '%s\n' '{"version":"2.1.0","runs":[]}' > "${out}/findings.sarif"
exit 0
`
	if err := os.WriteFile(frayStub, []byte(frayScript), 0o755); err != nil {
		t.Fatal(err)
	}

	ghOut := filepath.Join(dir, "github_output")
	cmd := exec.Command("bash", filepath.Join(root, "action", "scan.sh"))
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FRAY_BIN="+frayStub,
		"FRAY_API_URL=https://example.invalid",
		"FRAY_OIDC_TOKEN=test-token",
		"FRAY_WORKDIR=infra",
		"FRAY_CONFIG=fray.yaml",
		"FRAY_WAIVERS_FILE=.fray/waivers.yml",
		"FRAY_OUT="+outDir,
		"FRAY_PLAN_FILE=plan.json",
		"GITHUB_WORKSPACE="+dir,
		"GITHUB_OUTPUT="+ghOut,
		"GITHUB_REPOSITORY=acme/demo",
		"GITHUB_SHA=abcdef1",
		"GITHUB_EVENT_NAME=push",
		"GITHUB_REF_NAME=main",
		"GITHUB_REF=refs/heads/main",
		"GITHUB_EVENT_PATH="+filepath.Join(dir, "event.json"),
	)
	if err := os.WriteFile(filepath.Join(dir, "event.json"), []byte(`{"repository":{"default_branch":"main"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scan.sh failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "terraform-was-invoked") {
		t.Fatalf("terraform stub was invoked:\n%s", out)
	}
	if !strings.Contains(string(out), "Fray scan complete") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestExternalPlanEmptyDFDNoAPI(t *testing.T) {
	dir := t.TempDir()
	writeMinimalScanInputs(t, dir)
	// All-delete managed plan: passes ValidatePlanJSON, Parse yields zero elements.
	plan := `{
	  "format_version": "1.2",
	  "terraform_version": "1.5.0",
	  "planned_values": {"root_module": {}},
	  "resource_changes": [{
	    "address": "aws_s3_bucket.gone",
	    "mode": "managed",
	    "type": "aws_s3_bucket",
	    "change": {"actions": ["delete"], "before": {"bucket": "x"}, "after": null}
	  }],
	  "configuration": {"root_module": {}}
	}`
	if err := os.WriteFile(filepath.Join(dir, "plan.json"), []byte(plan), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))

	var called atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	_, err := runRemote(options{
		Plan:          filepath.Join(dir, "plan.json"),
		Source:        filepath.Join(dir, "infra"),
		Config:        filepath.Join(dir, "fray.yaml"),
		Mitigations:   filepath.Join(dir, "mitigations.yaml"),
		Remote:        srv.URL,
		Repo:          "acme/demo",
		Commit:        "abcdef1",
		Branch:        "main",
		DefaultBranch: "main",
		Out:           dir,
		ExternalPlan:  true,
		APIKey:        "test",
	})
	if err == nil {
		t.Fatal("expected empty-DFD error")
	}
	if !errors.Is(err, client.ErrPlanEmptyDFD) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "all changes are deletes") {
		t.Fatalf("all-delete plan should mention deletes: %v", err)
	}
	if called.Load() {
		t.Fatal("API must not be called for empty DFD on external plan")
	}
}

// actionCompositeYML is the subset of action.yml we need for interpolation checks.
type actionCompositeYML struct {
	Runs struct {
		Using string `yaml:"using"`
		Steps []struct {
			Name string         `yaml:"name"`
			Run  string         `yaml:"run"`
			If   string         `yaml:"if"`
			Env  map[string]any `yaml:"env"`
		} `yaml:"steps"`
	} `yaml:"runs"`
}

// exprInRunRe finds ${{ ... }} expressions inside a run: script.
var exprInRunRe = regexp.MustCompile(`\$\{\{\s*([^}]+?)\s*\}\}`)

// runExprForbidden reports whether an expression body (inside ${{ }}) is not
// allowed in run:. Inputs and untrusted github/steps contexts belong in env:/if:.
func runExprForbidden(expr string) bool {
	e := strings.TrimSpace(expr)
	switch {
	case strings.Contains(e, "inputs."):
		return true
	case strings.Contains(e, "github.event"): // event_name, event.pull_request, …
		return true
	case strings.Contains(e, "github.head_ref"):
		return true
	case strings.Contains(e, "steps."):
		// Step outputs (including fork/event-derived) must be passed via env:.
		return true
	default:
		return false
	}
}

func TestActionYMLNoInputInterpolationInRun(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc actionCompositeYML
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse action.yml: %v", err)
	}
	if doc.Runs.Using != "composite" {
		t.Fatalf("using=%q want composite", doc.Runs.Using)
	}

	var offenders []string
	for _, step := range doc.Runs.Steps {
		if step.Run == "" {
			continue
		}
		for _, m := range exprInRunRe.FindAllStringSubmatch(step.Run, -1) {
			if runExprForbidden(m[1]) {
				name := step.Name
				if name == "" {
					name = "(unnamed)"
				}
				offenders = append(offenders, name+": ${{ "+strings.TrimSpace(m[1])+" }}")
			}
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("run: must not interpolate inputs./github.event/github.head_ref/steps.* (use env: or if:):\n  - %s",
			strings.Join(offenders, "\n  - "))
	}
}

func TestScanShPlanFilePathContainment(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, "action", "scan.sh")

	mkWorkspace := func(t *testing.T) (dir, workdir, binDir, frayStub string) {
		t.Helper()
		dir = t.TempDir()
		workdir = filepath.Join(dir, "infra")
		if err := os.MkdirAll(workdir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(workdir, "main.tf"), []byte(`resource "null_resource" "x" {}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "fray.yaml"), []byte("schema_version: fray-config/v1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "event.json"), []byte(`{"repository":{"default_branch":"main"}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		binDir = filepath.Join(dir, "bin")
		if err := os.MkdirAll(binDir, 0o755); err != nil {
			t.Fatal(err)
		}
		frayStub = filepath.Join(binDir, "fray")
		// If scan.sh reaches fray, the path check failed.
		if err := os.WriteFile(frayStub, []byte("#!/bin/sh\necho fray-was-invoked >&2\nexit 99\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return dir, workdir, binDir, frayStub
	}

	run := func(t *testing.T, dir, binDir, frayStub, planFile string) (out []byte, err error) {
		t.Helper()
		cmd := exec.Command("bash", script)
		cmd.Env = append(os.Environ(),
			"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
			"FRAY_BIN="+frayStub,
			"FRAY_API_URL=https://example.invalid",
			"FRAY_OIDC_TOKEN=test-token",
			"FRAY_WORKDIR=infra",
			"FRAY_CONFIG=fray.yaml",
			"FRAY_WAIVERS_FILE=.fray/waivers.yml",
			"FRAY_OUT="+filepath.Join(dir, "out"),
			"FRAY_PLAN_FILE="+planFile,
			"GITHUB_WORKSPACE="+dir,
			"GITHUB_OUTPUT="+filepath.Join(dir, "github_output"),
			"GITHUB_REPOSITORY=acme/demo",
			"GITHUB_SHA=abcdef1",
			"GITHUB_EVENT_NAME=push",
			"GITHUB_REF_NAME=main",
			"GITHUB_REF=refs/heads/main",
			"GITHUB_EVENT_PATH="+filepath.Join(dir, "event.json"),
		)
		return cmd.CombinedOutput()
	}

	t.Run("dotdot_escape", func(t *testing.T) {
		dir, workdir, binDir, frayStub := mkWorkspace(t)
		outside := filepath.Join(dir, "..", "outside-plan.json")
		// Put a file as sibling of workspace via temp parent — use path with ..
		_ = workdir
		out, err := run(t, dir, binDir, frayStub, "../secrets.json")
		if err == nil {
			t.Fatalf("expected failure, got:\n%s", out)
		}
		if strings.Contains(string(out), "fray-was-invoked") {
			t.Fatal("fray ran before path rejection")
		}
		if !strings.Contains(string(out), "must stay under the GitHub workspace") {
			t.Fatalf("want containment error, got:\n%s", out)
		}
		_ = outside
	})

	t.Run("absolute_outside", func(t *testing.T) {
		dir, workdir, binDir, frayStub := mkWorkspace(t)
		abs := filepath.Join(t.TempDir(), "plan.json")
		if err := os.WriteFile(abs, []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = workdir
		out, err := run(t, dir, binDir, frayStub, abs)
		if err == nil {
			t.Fatalf("expected failure, got:\n%s", out)
		}
		if strings.Contains(string(out), "fray-was-invoked") {
			t.Fatal("fray ran before path rejection")
		}
		if !strings.Contains(string(out), "must stay under the GitHub workspace") {
			t.Fatalf("want containment error, got:\n%s", out)
		}
	})

	t.Run("symlink_outside", func(t *testing.T) {
		dir, workdir, binDir, frayStub := mkWorkspace(t)
		outsideDir := t.TempDir()
		outsideFile := filepath.Join(outsideDir, "plan.json")
		if err := os.WriteFile(outsideFile, []byte(`{"format_version":"1.2","resource_changes":[{"address":"null_resource.x","mode":"managed","change":{"after":{}}}]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(workdir, "linked-plan.json")
		if err := os.Symlink(outsideFile, link); err != nil {
			t.Fatal(err)
		}
		out, err := run(t, dir, binDir, frayStub, "linked-plan.json")
		if err == nil {
			t.Fatalf("expected failure, got:\n%s", out)
		}
		if strings.Contains(string(out), "fray-was-invoked") {
			t.Fatal("fray ran before path rejection")
		}
		if !strings.Contains(string(out), "must stay under the GitHub workspace") {
			t.Fatalf("want containment error, got:\n%s", out)
		}
	})
}
