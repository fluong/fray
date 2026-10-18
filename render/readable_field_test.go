package render

import (
	"testing"

	"github.com/fluong/fray/client"
)

func TestReadableFieldMatchesLookup(t *testing.T) {
	fromEl := client.Element{
		ID: "e-from", Type: "aws_lambda_function", Kind: "compute", Provenance: "managed",
		Provider: "aws",
		Attributes: map[string]any{
			"resource_policy_world_principal": true,
			"public":                          false,
		},
	}
	toEl := client.Element{
		ID: "e-to", Type: "aws_sqs_queue", Kind: "message_queue", Provenance: "managed",
		Provider: "aws",
	}
	byID := map[string]client.Element{fromEl.ID: fromEl, toEl.ID: toEl}
	flow := client.Flow{
		ID: "f1", From: fromEl.ID, To: toEl.ID,
		DataClass: "unknown", Transport: "tls", AuthzScope: "resource",
		AuthzDBControlClasses: []string{"rds:ModifyDBInstance"},
		AuthzDBControlScope:   "account",
	}

	for field := range lookupFieldTable {
		t.Run("table_"+field, func(t *testing.T) {
			if !ReadableField(field) {
				t.Fatalf("ReadableField(%q) false", field)
			}
		})
	}

	resolveCases := []struct {
		field string
		el    *client.Element
		flow  *client.Flow
	}{
		{"kind", &toEl, nil},
		{"authz_scope", nil, &flow},
		{"authz_db_control_classes", nil, &flow},
		{"from.kind", nil, &flow},
		{"to.kind", nil, &flow},
		{"attributes.resource_policy_world_principal", &fromEl, nil},
		{"attributes.public", &fromEl, nil},
	}
	for _, tc := range resolveCases {
		t.Run("lookup_"+tc.field, func(t *testing.T) {
			if !ReadableField(tc.field) {
				t.Fatalf("ReadableField(%q) false", tc.field)
			}
			_, ok := lookup(tc.field, tc.el, tc.flow, byID)
			if !ok {
				t.Fatalf("lookup(%q) not ok", tc.field)
			}
		})
	}

	unknown := []string{
		"provider_subtype",
		"attributes.",
		"attributes.a.b",
		"from.",
		"not_a_field",
		"encrypted_at_rest",
	}
	for _, field := range unknown {
		if ReadableField(field) {
			t.Errorf("ReadableField(%q) true, want false", field)
		}
	}

	// provider_subtype is an element wire field but not in lookup today.
	if _, ok := lookup("provider_subtype", &fromEl, nil, byID); ok {
		t.Fatal("lookup(provider_subtype) should stay unsupported")
	}
	if ReadableField("provider_subtype") {
		t.Fatal("ReadableField(provider_subtype) should stay false")
	}
}
