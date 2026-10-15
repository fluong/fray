package validate_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fluong/fray/schema/validate"
)

func TestRuleSchemaCopiesMatch(t *testing.T) {
	root, err := os.ReadFile(filepath.Join("..", "rule.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	embed, err := os.ReadFile("rule.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, embed) {
		t.Fatal("schema/rule.schema.json and schema/validate/rule.schema.json must be byte-identical")
	}
}

func TestRuleSchemaFixtures(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "rule.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "..", "testdata", "fixtures", "rules")

	for _, name := range []string{
		"valid-min-action-catalog.json",
		"valid-any-prefer-false.json",
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := validate.Schema(schema, raw); err != nil {
				t.Fatalf("want accept: %v", err)
			}
		})
	}

	negatives := []struct {
		file string
		want string
	}{
		{"negative-min-action-no-v.json", "min_action"},
		{"negative-min-action-short.json", "min_action"},
		{"negative-empty-catalog-text.json", "catalog_text"},
		{"negative-unknown-remediation-key.json", "additional properties"},
		{"negative-unknown-op.json", "op"},
	}
	for _, tc := range negatives {
		t.Run(tc.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			err = validate.Schema(schema, raw)
			if err == nil {
				t.Fatal("want schema rejection")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("want failure mentioning %q, got:\n%s", tc.want, err)
			}
		})
	}
}
