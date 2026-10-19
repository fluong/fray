package client

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFlowMarshalOmitsEmptyTransport(t *testing.T) {
	doc := DFD{
		SchemaVersion: "dfd/v1",
		Source: Source{
			Repo: "acme/app", Commit: "0000000000000000000000000000000000000001",
			Tool: "terraform", Fidelity: "plan",
		},
		Elements: []Element{
			{ID: "e1111111111111111", Type: "process", Kind: "api_gateway", Provider: "aws", Provenance: "iac",
				Evidence: Evidence{Addresses: []string{"aws_api_gateway_rest_api.api"}}},
			{ID: "e2222222222222222", Type: "external_entity", Kind: "public_client", Provenance: "inferred",
				Evidence: Evidence{Signals: []Signal{{Type: "network_ingress", Name: "0.0.0.0/0"}}}},
		},
		Flows: []Flow{{
			ID: "f1111111111111111", From: "e1111111111111111", To: "e2222222222222222",
			DataClass: "unknown", Transport: "", Boundaries: []string{},
		}},
		TrustBoundaries: []Boundary{},
	}
	raw, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"transport"`) {
		t.Fatalf("want transport key omitted, got:\n%s", raw)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	flows, ok := wire["flows"].([]any)
	if !ok || len(flows) != 1 {
		t.Fatalf("flows: %#v", wire["flows"])
	}
	f0, ok := flows[0].(map[string]any)
	if !ok {
		t.Fatalf("flow[0]: %#v", flows[0])
	}
	if _, has := f0["transport"]; has {
		t.Fatal("transport key present after unmarshal")
	}
}
