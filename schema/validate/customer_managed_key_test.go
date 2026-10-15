package validate_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/fluong/fray/schema/validate"
)

func minimalObjectStorage(attrs map[string]any) []byte {
	el := map[string]any{
		"id":         "e6e4399e2186efb58",
		"name":       "uploads",
		"type":       "datastore",
		"kind":       "object_storage",
		"provenance": "iac",
		"provider":   "aws",
		"evidence": map[string]any{
			"addresses": []string{"aws_s3_bucket.uploads"},
		},
	}
	if attrs != nil {
		el["attributes"] = attrs
	}
	doc := map[string]any{
		"schema_version": "dfd/v1",
		"source": map[string]any{
			"repo":     "example/cmk",
			"commit":   "0000000000000000000000000000000000000001",
			"iac_tool": "terraform",
			"fidelity": "static",
		},
		"elements":         []any{el},
		"trust_boundaries": []any{},
		"flows":            []any{},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestCustomerManagedKeySchema(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("object_storage_true", func(t *testing.T) {
		if err := validate.DFD(schema, minimalObjectStorage(map[string]any{
			"customer_managed_key": true,
		})); err != nil {
			t.Fatalf("want valid: %v", err)
		}
	})
	t.Run("object_storage_false", func(t *testing.T) {
		if err := validate.DFD(schema, minimalObjectStorage(map[string]any{
			"customer_managed_key": false,
		})); err != nil {
			t.Fatalf("want valid: %v", err)
		}
	})
	t.Run("string_value_rejected", func(t *testing.T) {
		err := validate.DFD(schema, minimalObjectStorage(map[string]any{
			"customer_managed_key": "true",
		}))
		if err == nil {
			t.Fatal("want rejection for string value")
		}
	})
}
