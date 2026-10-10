package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fluong/fray/client"
)

func TestGeneratedPlanEmptyConfigNoAPI(t *testing.T) {
	dir := t.TempDir()
	writeGeneratedScanScaffold(t, dir)
	plan := `{
	  "format_version": "1.2",
	  "terraform_version": "1.5.0",
	  "planned_values": {"root_module": {}},
	  "resource_changes": [],
	  "configuration": {"root_module": {}}
	}`
	if err := os.WriteFile(filepath.Join(dir, "plan.json"), []byte(plan), 0o644); err != nil {
		t.Fatal(err)
	}
	assertGeneratedRefuseNoAPI(t, dir, client.ErrPlanNoResources, "check working-directory")
}

func TestGeneratedPlanAllDeleteNoAPI(t *testing.T) {
	dir := t.TempDir()
	writeGeneratedScanScaffold(t, dir)
	plan := `{
	  "format_version": "1.2",
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
	assertGeneratedRefuseNoAPI(t, dir, client.ErrPlanEmptyDFD, "all changes are deletes")
}

func TestGeneratedPlanUnsupportedOnlyNoAPI(t *testing.T) {
	dir := t.TempDir()
	writeGeneratedScanScaffold(t, dir)
	plan := `{
	  "format_version": "1.2",
	  "resource_changes": [{
	    "address": "null_resource.x",
	    "mode": "managed",
	    "type": "null_resource",
	    "change": {"actions": ["no-op"], "after": {}}
	  }],
	  "configuration": {"root_module": {"resources": [
	    {"address":"null_resource.x","type":"null_resource","name":"x","mode":"managed","expressions":{}}
	  ]}}
	}`
	if err := os.WriteFile(filepath.Join(dir, "plan.json"), []byte(plan), 0o644); err != nil {
		t.Fatal(err)
	}
	assertGeneratedRefuseNoAPI(t, dir, client.ErrPlanEmptyDFD, "no resources Fray can analyse")
}

func TestGeneratedPlanNormalStillCallsAPI(t *testing.T) {
	dir := t.TempDir()
	writeMinimalScanInputs(t, dir) // includes analysable S3 bucket
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))

	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"repo_not_enrolled","message":"x"}`))
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
		Out:           filepath.Join(dir, "out"),
		ExternalPlan:  false,
		APIKey:        "test",
	})
	if err != nil {
		t.Fatalf("enrollment skip should succeed: %v", err)
	}
	if !called {
		t.Fatal("normal generated plan must reach the API")
	}
}

func TestGeneratedPlanOver32MiBNotRejectedForSize(t *testing.T) {
	dir := t.TempDir()
	writeGeneratedScanScaffold(t, dir)
	planPath := filepath.Join(dir, "plan.json")
	f, err := os.Create(planPath)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse fixture: small valid JSON plan, then pad the file past the
	// plan-file 32 MiB cap. json.Decoder stops at the first value, so Strip /
	// Parse stay cheap; only the generated path's os.ReadFile accepts this.
	small := `{
	  "format_version": "1.2",
	  "resource_changes": [{
	    "address": "aws_s3_bucket.a",
	    "mode": "managed",
	    "type": "aws_s3_bucket",
	    "name": "a",
	    "change": {"actions": ["no-op"], "after": {"bucket": "keep-me"}}
	  }],
	  "configuration": {"root_module": {"resources": [
	    {"address":"aws_s3_bucket.a","type":"aws_s3_bucket","name":"a","mode":"managed","expressions":{}}
	  ]}}
	}`
	if _, err := f.WriteString(small); err != nil {
		t.Fatal(err)
	}
	const wantSize = client.MaxPlanFileBytes + (1 << 20)
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = ' '
	}
	for {
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() >= wantSize {
			break
		}
		n := wantSize - fi.Size()
		if n > int64(len(chunk)) {
			n = int64(len(chunk))
		}
		if _, err := f.Write(chunk[:n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() <= client.MaxPlanFileBytes {
		t.Fatalf("fixture size %d must exceed %d", fi.Size(), client.MaxPlanFileBytes)
	}

	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"repo_not_enrolled","message":"x"}`))
	}))
	t.Cleanup(srv.Close)

	_, err = runRemote(options{
		Plan:          planPath,
		Source:        filepath.Join(dir, "infra"),
		Config:        filepath.Join(dir, "fray.yaml"),
		Mitigations:   filepath.Join(dir, "mitigations.yaml"),
		Remote:        srv.URL,
		Repo:          "acme/demo",
		Commit:        "abcdef1",
		Branch:        "main",
		DefaultBranch: "main",
		Out:           filepath.Join(dir, "out"),
		ExternalPlan:  false,
		APIKey:        "test",
	})
	if err != nil {
		t.Fatalf("generated plan over 32 MiB must not fail for size: %v", err)
	}
	if !called {
		t.Fatal("API must be reached; size cap applies only to plan-file")
	}
	if errors.Is(err, client.ErrPlanTooLarge) {
		t.Fatal("must not return ErrPlanTooLarge on generated path")
	}
}

func writeGeneratedScanScaffold(t *testing.T, dir string) {
	t.Helper()
	infra := filepath.Join(dir, "infra")
	if err := os.MkdirAll(infra, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(infra, "main.tf"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fray.yaml"), []byte("schema_version: fray-config/v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mitigations.yaml"), []byte("schema_version: mitigation/v1\nentries: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertGeneratedRefuseNoAPI(t *testing.T, dir string, want error, substr string) {
	t.Helper()
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut := os.Stdout
	os.Stdout = w
	_, runErr := runRemote(options{
		Plan:          filepath.Join(dir, "plan.json"),
		Source:        filepath.Join(dir, "infra"),
		Config:        filepath.Join(dir, "fray.yaml"),
		Mitigations:   filepath.Join(dir, "mitigations.yaml"),
		Remote:        srv.URL,
		Repo:          "acme/demo",
		Commit:        "abcdef1",
		Branch:        "main",
		DefaultBranch: "main",
		Out:           filepath.Join(dir, "out"),
		ExternalPlan:  false,
		APIKey:        "test",
	})
	_ = w.Close()
	os.Stdout = oldOut
	ann := make([]byte, 8192)
	n, _ := r.Read(ann)
	_ = r.Close()

	if runErr == nil {
		t.Fatal("expected refuse error")
	}
	if !errors.Is(runErr, want) {
		t.Fatalf("got %v, want %v", runErr, want)
	}
	if !strings.Contains(runErr.Error(), substr) {
		t.Fatalf("error %q missing %q", runErr, substr)
	}
	if called {
		t.Fatal("API must not be called")
	}
	if _, err := os.Stat(filepath.Join(dir, "out", "pr-comment.md")); !os.IsNotExist(err) {
		t.Fatal("must not write PR comment")
	}
	if _, err := os.Stat(filepath.Join(dir, "out", "findings.sarif")); !os.IsNotExist(err) {
		t.Fatal("must not write SARIF")
	}
	if !strings.HasPrefix(string(ann[:n]), "::error::") {
		t.Fatalf("want ::error:: annotation, got %q", string(ann[:n]))
	}
}
