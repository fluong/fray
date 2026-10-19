package validate_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/fluong/fray/schema/validate"
)

func externalHTTPEndpointElement(id string, redacted bool) map[string]any {
	el := map[string]any{
		"id":         id,
		"type":       "external_entity",
		"kind":       "external_http_endpoint",
		"provenance": "declared",
		"evidence": map[string]any{
			"source": "fray.yaml",
			"key":    "external-http-peer",
		},
	}
	if redacted {
		el["evidence"] = map[string]any{
			"source": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"key":    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}
	}
	return el
}

func flowWithoutTransportDoc(redacted bool) []byte {
	flow := map[string]any{
		"id":         "f1111111111111111",
		"from":       "e1111111111111111",
		"to":         "e2222222222222222",
		"data_class": "unknown",
		"boundaries": []any{},
	}
	doc := map[string]any{
		"schema_version": "dfd/v1",
		"source": map[string]any{
			"repo":     "acme/app",
			"commit":   "0000000000000000000000000000000000000001",
			"iac_tool": "terraform",
			"fidelity": "plan",
		},
		"elements": []any{
			map[string]any{
				"id": "e1111111111111111", "type": "process", "kind": "api_gateway",
				"provider": "aws", "provenance": "iac",
				"evidence": map[string]any{"addresses": []string{"aws_api_gateway_rest_api.api"}},
			},
			externalHTTPEndpointElement("e2222222222222222", redacted),
		},
		"trust_boundaries": []any{},
		"flows":            []any{flow},
	}
	if redacted {
		doc["redaction"] = map[string]any{
			"scheme":          "hmac-sha256-v1",
			"key_fingerprint": "0123456789abcdef",
		}
		doc["source"] = map[string]any{
			"repo":     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"commit":   "0000000000000000000000000000000000000001",
			"iac_tool": "terraform",
			"fidelity": "plan",
		}
		doc["elements"] = []any{
			map[string]any{
				"id": "e1111111111111111", "type": "process", "kind": "api_gateway",
				"provider": "aws", "provenance": "iac",
				"evidence": map[string]any{
					"addresses": []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
				},
			},
			externalHTTPEndpointElement("e2222222222222222", true),
		}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestSchemaAcceptsFlowWithoutTransportPlaintext(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.Schema(schema, flowWithoutTransportDoc(false)); err != nil {
		t.Fatalf("plaintext DFD without transport: %v", err)
	}
}

func TestSchemaAcceptsFlowWithoutTransportRedacted(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.Schema(schema, flowWithoutTransportDoc(true)); err != nil {
		t.Fatalf("redacted DFD without transport: %v", err)
	}
}

func TestSchemaRejectsFlowTransportBogus(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw := flowWithoutTransportDoc(false)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	flows := doc["flows"].([]any)
	f := flows[0].(map[string]any)
	f["transport"] = "bogus"
	doc["flows"] = []any{f}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.Schema(schema, b); err == nil {
		t.Fatal("want reject for transport bogus")
	}
}

func TestSchemaAcceptsExternalHTTPEndpointKindPlaintext(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{
		"schema_version": "dfd/v1",
		"source": map[string]any{
			"repo": "acme/app", "commit": "0000000000000000000000000000000000000001",
			"iac_tool": "terraform", "fidelity": "plan",
		},
		"elements":         []any{externalHTTPEndpointElement("e1111111111111111", false)},
		"trust_boundaries": []any{},
		"flows":            []any{},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.Schema(schema, raw); err != nil {
		t.Fatalf("plaintext external_http_endpoint: %v", err)
	}
}

func TestSchemaAcceptsExternalHTTPEndpointKindRedacted(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "dfd.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{
		"schema_version": "dfd/v1",
		"redaction": map[string]any{
			"scheme": "hmac-sha256-v1", "key_fingerprint": "0123456789abcdef",
		},
		"source": map[string]any{
			"repo":     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"commit":   "0000000000000000000000000000000000000001",
			"iac_tool": "terraform", "fidelity": "plan",
		},
		"elements":         []any{externalHTTPEndpointElement("e1111111111111111", true)},
		"trust_boundaries": []any{},
		"flows":            []any{},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.Schema(schema, raw); err != nil {
		t.Fatalf("redacted external_http_endpoint: %v", err)
	}
}
