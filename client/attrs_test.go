package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestSanitizeAttributesDropsUnknownAndBadValues(t *testing.T) {
	els := []*Element{{
		Attributes: map[string]any{
			"public":            true,
			"encrypted_at_rest": true,
			"max_instances":     3,
			"evil_secret":       "should-drop",
			"region":            "TOTALLY_INVALID_REGION!!!",
		},
	}}
	sanitizeAttributes(els)
	got := els[0].Attributes
	if got["public"] != true || got["encrypted_at_rest"] != true || got["max_instances"] != 3 {
		t.Fatalf("kept attrs: %#v", got)
	}
	if _, ok := got["evil_secret"]; ok {
		t.Fatal("unknown key was kept")
	}
	if _, ok := got["region"]; ok {
		t.Fatal("invalid region was kept")
	}

	els[0].Attributes = map[string]any{"region": "us-east-1"}
	sanitizeAttributes(els)
	if els[0].Attributes["region"] != "us-east-1" {
		t.Fatalf("valid region dropped: %#v", els[0].Attributes)
	}
}

func TestAllowedAttributesMatchSchemaAndCode(t *testing.T) {
	// Attributes accepted by the schema before the client emits them (schema-first).
	// Remove from this list in the client change that adds them to the allow-list.
	pendingSchemaOnly := []string{}

	schemaKeys := loadSchemaAttributeKeys(t)
	allow := AllowedAttributeKeys()
	slices.Sort(schemaKeys)
	slices.Sort(allow)
	slices.Sort(pendingSchemaOnly)

	schemaMinusAllow := setDiff(schemaKeys, allow)
	allowMinusSchema := setDiff(allow, schemaKeys)
	if !slices.Equal(schemaMinusAllow, pendingSchemaOnly) {
		t.Fatalf("schema − allow-list = %#v want %#v", schemaMinusAllow, pendingSchemaOnly)
	}
	if len(allowMinusSchema) > 0 {
		t.Fatalf("allow-list − schema = %#v want empty", allowMinusSchema)
	}

	codeKeys := attrsAssignedInClientSource(t)
	for _, k := range codeKeys {
		if _, ok := allowedAttributes[k]; !ok {
			t.Errorf("attrs[%q] assigned in client source but missing from allowedAttributes — add it to the allow-list (and schema)", k)
		}
	}
}

func setDiff(a, b []string) []string {
	inB := map[string]bool{}
	for _, k := range b {
		inB[k] = true
	}
	var out []string
	for _, k := range a {
		if !inB[k] {
			out = append(out, k)
		}
	}
	return out
}

func loadSchemaAttributeKeys(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "schema", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Defs struct {
			Attributes struct {
				Properties map[string]any `json:"properties"`
			} `json:"attributes"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(root.Defs.Attributes.Properties))
	for k := range root.Defs.Attributes.Properties {
		out = append(out, k)
	}
	return out
}

var attrsAssignRe = regexp.MustCompile(`attrs\["([^"]+)"\]\s*=`)

func attrsAssignedInClientSource(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range attrsAssignRe.FindAllSubmatch(raw, -1) {
			seen[string(m[1])] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
