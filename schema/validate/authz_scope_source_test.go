package validate_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/fluong/fray/schema/validate"
)

func flowDoc(authzScopeSource any) []byte {
	flow := map[string]any{
		"id":          "f1111111111111111",
		"from":        "e1111111111111111",
		"to":          "e2222222222222222",
		"data_class":  "unknown",
		"transport":   "tls",
		"boundaries":  []any{},
		"authz_scope": "resource",
	}
	if authzScopeSource != nil {
		flow["authz_scope_source"] = authzScopeSource
	}
	doc := map[string]any{
		"schema_version": "dfd/v1",
		"source": map[string]any{
			"repo": "acme/app", "commit": "0000000000000000000000000000000000000001",
			"iac_tool": "terraform", "fidelity": "plan",
		},
		"elements": []any{
			map[string]any{
				"id": "e1111111111111111", "type": "process", "kind": "container_service",
				"provider": "aws", "provenance": "iac",
				"evidence": map[string]any{"addresses": []string{"aws_ecs_service.app"}},
			},
			map[string]any{
				"id": "e2222222222222222", "type": "datastore", "kind": "object_storage",
				"provider": "aws", "provenance": "iac",
				"evidence": map[string]any{"addresses": []string{"aws_s3_bucket.uploads"}},
			},
		},
		"trust_boundaries": []any{},
		"flows":            []any{flow},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestAuthzScopeSourceSchema(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		value any
		ok    bool
	}{
		{"absent", nil, true},
		{"declared", "declared", true},
		{"derived", "derived", true},
		{"bad", "fray.yaml", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validate.Schema(schema, flowDoc(tc.value))
			if tc.ok && err != nil {
				t.Fatalf("want valid: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("want schema rejection")
			}
		})
	}
}
