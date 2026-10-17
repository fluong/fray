package validate_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/fluong/fray/schema/validate"
)

const hashAddr = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func minimalNoSQLDB(plain bool, attrs map[string]any) []byte {
	el := map[string]any{
		"id":         "e9ee4a63a90c93af4",
		"type":       "datastore",
		"kind":       "nosql_db",
		"provider":   "aws",
		"provenance": "iac",
		"evidence": map[string]any{
			"addresses": []string{"aws_dynamodb_table.example"},
		},
	}
	if plain {
		el["name"] = "Example table"
	} else {
		el["evidence"] = map[string]any{
			"addresses": []string{hashAddr},
		}
	}
	if attrs != nil {
		el["attributes"] = attrs
	}
	source := map[string]any{
		"repo":     "example/resource-policy",
		"commit":   "0000000000000000000000000000000000000001",
		"iac_tool": "terraform",
		"fidelity": "plan",
	}
	if !plain {
		source["repo"] = hashAddr
	}
	doc := map[string]any{
		"schema_version":   "dfd/v1",
		"source":           source,
		"elements":         []any{el},
		"trust_boundaries": []any{},
		"flows":            []any{},
	}
	if !plain {
		doc["redaction"] = map[string]any{
			"scheme":          "hmac-sha256-v1",
			"key_fingerprint": "0123456789abcdef",
		}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestResourcePolicyAttributesPlainNoSQLDB(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		attrs map[string]any
	}{
		{"world_true", map[string]any{"resource_policy_world_principal": true}},
		{"world_false", map[string]any{"resource_policy_world_principal": false}},
		{"cross_true", map[string]any{"resource_policy_cross_account": true}},
		{"cross_false", map[string]any{"resource_policy_cross_account": false}},
		{"both", map[string]any{
			"resource_policy_world_principal": true,
			"resource_policy_cross_account":   false,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validate.DFD(schema, minimalNoSQLDB(true, tc.attrs)); err != nil {
				t.Fatalf("want valid: %v", err)
			}
		})
	}
	t.Run("non_boolean_rejected", func(t *testing.T) {
		if err := validate.DFD(schema, minimalNoSQLDB(true, map[string]any{
			"resource_policy_world_principal": "true",
		})); err == nil {
			t.Fatal("want rejection for string value")
		}
	})
}

func TestResourcePolicyAttributesRedactedNoSQLDB(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		attrs map[string]any
	}{
		{"world_true", map[string]any{"resource_policy_world_principal": true}},
		{"world_false", map[string]any{"resource_policy_world_principal": false}},
		{"cross_true", map[string]any{"resource_policy_cross_account": true}},
		{"cross_false", map[string]any{"resource_policy_cross_account": false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validate.DFD(schema, minimalNoSQLDB(false, tc.attrs)); err != nil {
				t.Fatalf("want valid: %v", err)
			}
		})
	}
	t.Run("non_boolean_rejected", func(t *testing.T) {
		if err := validate.DFD(schema, minimalNoSQLDB(false, map[string]any{
			"resource_policy_cross_account": 1,
		})); err == nil {
			t.Fatal("want rejection for non-boolean value")
		}
	})
}
