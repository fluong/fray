package client

import (
	"testing"

	"github.com/fluong/fray/schema/validate"
)

func TestRedactKeepsAllowlistedProviderSubtype(t *testing.T) {
	doc, _ := parseCacheCoveragePlan(t, "coverage-cache-plan.json")
	key := make([]byte, 32)
	redacted, _, err := Redact(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, el := range redacted.Elements {
		if el.Kind != "cache" || el.ProviderSubtype == "" {
			continue
		}
		seen[el.ProviderSubtype] = true
	}
	for _, subtype := range []string{"redis", "memcached"} {
		if !seen[subtype] {
			t.Fatalf("missing redacted provider_subtype %q (got %v)", subtype, seen)
		}
	}

	schema, err := validate.CompileDFD()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.DFD(schema, raw); err != nil {
		t.Fatalf("redacted cache DFD invalid: %v", err)
	}
}

func TestRedactKeepsRESTAPIProviderSubtype(t *testing.T) {
	doc := DFD{
		SchemaVersion: "dfd/v1",
		Source: Source{
			Repo: "acme/app", Commit: "abcdef1234567890abcdef1234567890abcd", Tool: "terraform", Fidelity: "plan",
		},
		Elements: []Element{{
			ID: "e1", Type: "process", Kind: "api_gateway", Provider: "aws",
			ProviderSubtype: "rest_api",
			Provenance:      "iac",
			Evidence:        Evidence{Addresses: []string{"aws_api_gateway_rest_api.api"}},
			Attributes:      map[string]any{"public": true},
		}},
		TrustBoundaries: []Boundary{},
		Flows:           []Flow{},
	}
	finalize(&doc)
	key := make([]byte, 32)
	redacted, _, err := Redact(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	if redacted.Elements[0].ProviderSubtype != "rest_api" {
		t.Fatalf("rest_api subtype=%q want rest_api", redacted.Elements[0].ProviderSubtype)
	}
	schema, err := validate.CompileDFD()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.DFD(schema, raw); err != nil {
		t.Fatalf("redacted REST API DFD invalid: %v", err)
	}
}

func TestRedactClearsNonAllowlistedProviderSubtype(t *testing.T) {
	doc := DFD{
		SchemaVersion: "dfd/v1",
		Source: Source{
			Repo: "acme/app", Commit: "abcdef1234567890abcdef1234567890abcd", Tool: "terraform", Fidelity: "plan",
		},
		Elements: []Element{{
			ID: "e1", Type: "datastore", Kind: "relational_db", Provider: "aws",
			ProviderSubtype: "postgres",
			Provenance:      "iac",
			Evidence:        Evidence{Addresses: []string{"aws_db_instance.main"}},
		}},
		TrustBoundaries: []Boundary{},
		Flows:           []Flow{},
	}
	finalize(&doc)
	key := make([]byte, 32)
	redacted, _, err := Redact(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	if redacted.Elements[0].ProviderSubtype != "" {
		t.Fatalf("postgres subtype leaked: %q", redacted.Elements[0].ProviderSubtype)
	}
}
