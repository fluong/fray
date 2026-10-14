package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
)

func TestRemoteOmitsEmptyStackByteIdentical(t *testing.T) {
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, append([]byte(nil), raw...))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(apiv1.ScanResponse{
			ScanID: "s1",
			Findings: apiv1.Findings{
				SchemaVersion: "finding/v1",
				Findings:      []apiv1.Finding{},
			},
			RuleTexts: map[string]apiv1.RuleText{},
		})
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	writeMinimalScanInputs(t, dir)
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))

	base := options{
		Plan:          filepath.Join(dir, "plan.json"),
		Source:        filepath.Join(dir, "infra"),
		Config:        filepath.Join(dir, "fray.yaml"),
		Mitigations:   filepath.Join(dir, "mitigations.yaml"),
		Remote:        srv.URL,
		Repo:          "acme/widgets",
		Commit:        "abc123",
		Branch:        "main",
		DefaultBranch: "main",
		OIDCToken:     "test-oidc-token",
		Out:           filepath.Join(dir, "out"),
	}
	if _, err := runRemote(base); err != nil {
		t.Fatal(err)
	}
	withEmpty := base
	withEmpty.Stack = ""
	withEmpty.Out = filepath.Join(dir, "out2")
	if _, err := runRemote(withEmpty); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 {
		t.Fatalf("want 2 bodies, got %d", len(bodies))
	}
	if !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("empty Stack must be byte-identical to omitted\n%s\n%s", bodies[0], bodies[1])
	}
	if bytes.Contains(bodies[0], []byte(`"stack"`)) {
		t.Fatalf("unexpected stack key: %s", bodies[0])
	}

	named := base
	named.Stack = "infra-aws"
	named.Out = filepath.Join(dir, "out3")
	if _, err := runRemote(named); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 3 {
		t.Fatalf("want 3 bodies, got %d", len(bodies))
	}
	if !bytes.Contains(bodies[2], []byte(`"stack":"infra-aws"`)) {
		t.Fatalf("named stack missing: %s", bodies[2])
	}
	comment, err := os.ReadFile(filepath.Join(dir, "out3", "pr-comment.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(comment), "## Fray · stack `infra-aws`\n\n") {
		t.Fatalf("named comment heading missing: %q", comment)
	}
	defComment, err := os.ReadFile(filepath.Join(dir, "out", "pr-comment.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(defComment), "Fray · stack") {
		t.Fatalf("default comment must not name a stack: %q", defComment)
	}
}

func TestRunRemoteRejectsInvalidStack(t *testing.T) {
	dir := t.TempDir()
	writeMinimalScanInputs(t, dir)
	t.Setenv("FRAY_REDACTION_KEY", strings.Repeat("ab", 32))
	for _, stack := range []string{"Infra", "a/b", "-x", "a" + strings.Repeat("b", 32)} {
		_, err := runRemote(options{
			Plan:          filepath.Join(dir, "plan.json"),
			Source:        filepath.Join(dir, "infra"),
			Config:        filepath.Join(dir, "fray.yaml"),
			Remote:        "http://127.0.0.1:1",
			Repo:          "acme/widgets",
			Commit:        "abc123",
			Branch:        "main",
			DefaultBranch: "main",
			OIDCToken:     "tok",
			Out:           filepath.Join(dir, "out"),
			Stack:         stack,
			DryRun:        true,
		})
		if err == nil {
			t.Fatalf("%q: want error", stack)
		}
		if !strings.Contains(err.Error(), "invalid stack") {
			t.Fatalf("%q: %v", stack, err)
		}
	}
}

func TestCLIRejectsInvalidStack(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "fray")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot(t), "cmd", "fray")
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for _, stack := range []string{"Infra", "a/b", "-x", strings.Repeat("a", 33)} {
		cmd := exec.Command(bin, "-stack", stack, "-plan", "p", "-source", "s", "-config", "c", "-remote", "http://example", "-default-branch", "main")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("%q: want non-zero exit", stack)
		}
		if !strings.Contains(string(out), "invalid stack") {
			t.Fatalf("%q: want invalid stack error, got %q", stack, out)
		}
	}
}
