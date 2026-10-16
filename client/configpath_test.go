package client

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
)

func TestReportConfigPath(t *testing.T) {
	ws := t.TempDir()
	t.Setenv("GITHUB_WORKSPACE", ws)

	if got := ReportConfigPath(filepath.Join(ws, "fray.yaml")); got != "fray.yaml" {
		t.Fatalf("workspace root file: %q", got)
	}
	if got := ReportConfigPath(filepath.Join(ws, "infra", "fray.yaml")); got != "infra/fray.yaml" {
		t.Fatalf("workspace subdir: %q", got)
	}
	if got := ReportConfigPath("infra/fray.yaml"); got != "infra/fray.yaml" {
		t.Fatalf("relative: %q", got)
	}
	if got := ReportConfigPath(filepath.Join("infra", "..", "fray.yaml")); got != "fray.yaml" {
		t.Fatalf("relative cleaned: %q", got)
	}

	t.Setenv("GITHUB_WORKSPACE", "")
	abs := filepath.Join(ws, "infra", "fray.yaml")
	if got := ReportConfigPath(abs); got != "fray.yaml" {
		t.Fatalf("absolute without workspace: %q", got)
	}
	if got := ReportConfigPath("fray.yaml"); got != "fray.yaml" {
		t.Fatalf("relative without workspace: %q", got)
	}
}

func TestCoverageDeclaredScopeFingerprint(t *testing.T) {
	cause := "fray.yaml#aws_ecs_service.declared -> aws_db_instance.main unknown"
	sum := sha256.Sum256([]byte("FR-028|" + cause))
	const want = "2ceb9c0694eeb830628b056e16c9b14fce050c8e07f3f42c77089d2b3abcdcaa"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("fingerprint %s", got)
	}
}
