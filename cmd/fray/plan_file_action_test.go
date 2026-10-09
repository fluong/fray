package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fluong/fray/client"
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

	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
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
	if err != client.ErrPlanEmptyDFD && !strings.Contains(err.Error(), "no resources Fray can analyse") {
		t.Fatalf("got %v", err)
	}
	if called {
		t.Fatal("API must not be called for empty DFD on external plan")
	}
}
