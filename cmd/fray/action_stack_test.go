package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActionYMLCommentMatchExact(t *testing.T) {
	yml, err := os.ReadFile(filepath.Join(repoRoot(t), "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(yml)
	if !strings.Contains(s, "c.body === marker") || !strings.Contains(s, "startsWith(marker") {
		t.Fatal("action.yml must exact-match comment markers (=== and startsWith)")
	}
	if strings.Contains(s, "c.body.includes(marker)") || strings.Contains(s, "body.includes(marker)") {
		t.Fatal("action.yml must not use includes(marker) for PR comment lookup")
	}
	if !strings.Contains(s, "FRAY_COMMENT_MARKER") {
		t.Fatal("action.yml must pass FRAY_COMMENT_MARKER")
	}
	if !strings.Contains(s, "id: stack") {
		t.Fatal("action.yml missing Resolve Fray stack step")
	}
	if !strings.Contains(s, "inputs.stack") && !strings.Contains(s, "FRAY_STACK_INPUT") {
		t.Fatal("action.yml must read stack input")
	}
}
