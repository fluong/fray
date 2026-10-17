package validate_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/fluong/fray/schema/validate"
)

const validResourcePolicyElementRule = `{
  "id": "FR-996",
  "title": "Synthetic NoSQL resource policy rule",
  "threat": "Synthetic threat for schema fixtures",
  "explanation": "Synthetic explanation for schema fixtures.",
  "stride": ["information_disclosure", "elevation_of_privilege"],
  "severity": "medium",
  "severity_when": [
    {
      "when": [
        { "op": "equals", "field": "attributes.resource_policy_world_principal", "value": true }
      ],
      "severity": "high"
    }
  ],
  "platforms": ["aws"],
  "category": "exposure",
  "target": "element",
  "when": [
    { "op": "equals", "field": "kind", "value": "nosql_db" },
    { "op": "in", "field": "provenance", "value": ["iac"] }
  ],
  "pass": [
    {
      "op": "all",
      "conds": [
        { "op": "equals", "field": "attributes.resource_policy_world_principal", "value": false },
        { "op": "equals", "field": "attributes.resource_policy_cross_account", "value": false }
      ]
    }
  ],
  "rationale": "Fixture only.",
  "mitigation": "Fixture only.",
  "evaluation": {
    "open": "open",
    "mitigated": "mitigated",
    "unverified": "unverified"
  }
}`

const invalidUnknownResourcePolicyField = `{
  "id": "FR-995",
  "title": "Synthetic rule with unknown attribute field",
  "threat": "Synthetic threat for schema fixtures",
  "explanation": "Synthetic explanation for schema fixtures.",
  "stride": ["information_disclosure"],
  "severity": "medium",
  "platforms": ["aws"],
  "category": "exposure",
  "target": "element",
  "when": [
    { "op": "equals", "field": "kind", "value": "nosql_db" }
  ],
  "pass": [
    { "op": "equals", "field": "attributes.resource_policy_unknown", "value": false }
  ],
  "rationale": "Fixture only.",
  "mitigation": "Fixture only.",
  "evaluation": {
    "open": "open",
    "mitigated": "mitigated",
    "unverified": "unverified"
  }
}`

func TestResourcePolicyRuleSchemaFields(t *testing.T) {
	schema, err := validate.Compile(filepath.Join("..", "rule.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("element_rule_pass_all_and_severity_when", func(t *testing.T) {
		if err := validate.Schema(schema, []byte(validResourcePolicyElementRule)); err != nil {
			t.Fatalf("want accept: %v", err)
		}
	})
	t.Run("unknown_attribute_field_rejected", func(t *testing.T) {
		err := validate.Schema(schema, []byte(invalidUnknownResourcePolicyField))
		if err == nil {
			t.Fatal("want schema rejection")
		}
		if !strings.Contains(strings.ToLower(err.Error()), "field") {
			t.Fatalf("want failure mentioning field, got:\n%s", err)
		}
	})
}
