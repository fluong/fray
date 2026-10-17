package validate_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/fluong/fray/schema/validate"
)

func redactedCacheElement(providerSubtype string) []byte {
	el := map[string]any{
		"id":         "e1111111111111111",
		"type":       "datastore",
		"kind":       "cache",
		"provider":   "aws",
		"provenance": "iac",
		"evidence": map[string]any{
			"addresses": []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		},
		"attributes": map[string]any{"tls_enforced": true},
	}
	if providerSubtype != "" {
		el["provider_subtype"] = providerSubtype
	}
	doc := map[string]any{
		"schema_version": "dfd/v1",
		"source": map[string]any{
			"repo":     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"commit":   "0000000000000000000000000000000000000001",
			"iac_tool": "terraform", "fidelity": "plan",
		},
		"elements":         []any{el},
		"trust_boundaries": []any{},
		"flows":            []any{},
	}
	// fix redaction map - only required fields
	doc["redaction"] = map[string]any{
		"scheme":          "hmac-sha256-v1",
		"key_fingerprint": "0123456789abcdef",
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestRedactedProviderSubtypeAllowlist(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, subtype := range []string{"redis", "valkey", "memcached"} {
		t.Run("allowed_"+subtype, func(t *testing.T) {
			if err := validate.DFD(schema, redactedCacheElement(subtype)); err != nil {
				t.Fatalf("want valid: %v", err)
			}
		})
	}
	for _, bad := range []string{"postgres", "aws_db_instance", "free text"} {
		t.Run("reject_"+bad, func(t *testing.T) {
			if err := validate.DFD(schema, redactedCacheElement(bad)); err == nil {
				t.Fatal("want schema rejection")
			}
		})
	}
}
