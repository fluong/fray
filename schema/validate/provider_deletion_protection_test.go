package validate_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/fluong/fray/schema/validate"
)

func minimalRelationalDB(attrs map[string]any) []byte {
	el := map[string]any{
		"id":         "e9468970500753318",
		"name":       "Postgres",
		"type":       "datastore",
		"kind":       "relational_db",
		"provenance": "iac",
		"provider":   "aws",
		"evidence": map[string]any{
			"addresses": []string{"aws_db_instance.main"},
		},
	}
	if attrs != nil {
		el["attributes"] = attrs
	}
	doc := map[string]any{
		"schema_version": "dfd/v1",
		"source": map[string]any{
			"repo":     "example/provider-dp",
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

func TestProviderDeletionProtectionSchema(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("relational_db_true", func(t *testing.T) {
		if err := validate.DFD(schema, minimalRelationalDB(map[string]any{
			"provider_deletion_protection": true,
		})); err != nil {
			t.Fatalf("want valid: %v", err)
		}
	})
	t.Run("relational_db_false", func(t *testing.T) {
		if err := validate.DFD(schema, minimalRelationalDB(map[string]any{
			"provider_deletion_protection": false,
		})); err != nil {
			t.Fatalf("want valid: %v", err)
		}
	})
	t.Run("string_value_rejected", func(t *testing.T) {
		err := validate.DFD(schema, minimalRelationalDB(map[string]any{
			"provider_deletion_protection": "true",
		}))
		if err == nil {
			t.Fatal("want rejection for string value")
		}
	})
	t.Run("non_relational_db_accepted_flat_attrs", func(t *testing.T) {
		// DFD attributes are a flat bag shared by all element kinds — not
		// scoped per kind. Putting provider_deletion_protection on a
		// secret_store is therefore schema-valid (rules still when: on
		// relational_db only).
		el := map[string]any{
			"id":         "e657a76956218614c",
			"name":       "db password",
			"type":       "datastore",
			"kind":       "secret_store",
			"provenance": "iac",
			"provider":   "aws",
			"evidence": map[string]any{
				"addresses": []string{"aws_secretsmanager_secret.db"},
			},
			"attributes": map[string]any{
				"provider_deletion_protection": true,
			},
		}
		doc := map[string]any{
			"schema_version": "dfd/v1",
			"source": map[string]any{
				"repo":     "example/provider-dp",
				"commit":   "0000000000000000000000000000000000000002",
				"iac_tool": "terraform",
				"fidelity": "static",
			},
			"elements":         []any{el},
			"trust_boundaries": []any{},
			"flows":            []any{},
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := validate.DFD(schema, raw); err != nil {
			t.Fatalf("flat attribute bag accepts attr on other kinds: %v", err)
		}
	})
}
