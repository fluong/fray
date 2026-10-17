package client

import (
	"path/filepath"
	"testing"
)

func TestCoverageB73ResourcePolicyAttrs(t *testing.T) {
	modDir := filepath.Join("testdata", "b73_hcl")
	doc, warnings := parseCoveragePlanModule(t, "coverage-b73-plan.json", modDir)

	assertRP := func(t *testing.T, table string, world *bool, cross *bool, cause string) {
		t.Helper()
		el, ok := elementByAddress(doc, table)
		if !ok {
			t.Fatalf("missing element %s", table)
		}
		gotW, okW := el.Attributes["resource_policy_world_principal"].(bool)
		if world == nil {
			if okW {
				t.Fatalf("%s: world attr set=%v want omitted", table, gotW)
			}
		} else if !okW || gotW != *world {
			t.Fatalf("%s: world=%v ok=%v want %v", table, gotW, okW, *world)
		}
		gotC, okC := el.Attributes["resource_policy_cross_account"].(bool)
		if cross == nil {
			if okC {
				t.Fatalf("%s: cross attr set=%v want omitted", table, gotC)
			}
		} else if !okC || gotC != *cross {
			t.Fatalf("%s: cross=%v ok=%v want %v", table, gotC, okC, *cross)
		}
		if cause != "" {
			if el.Causes["resource_policy_world_principal"] != cause && el.Causes["resource_policy_cross_account"] != cause {
				if !(world != nil && el.Causes["resource_policy_world_principal"] == cause) &&
					!(cross != nil && el.Causes["resource_policy_cross_account"] == cause) {
					t.Fatalf("%s: causes=%v want %q on set axis", table, el.Causes, cause)
				}
			}
		}
	}

	falseVal := false
	trueVal := true

	t.Run("no_policy_mitigated", func(t *testing.T) {
		for _, addr := range []string{
			"aws_dynamodb_table.sessions",
			"aws_dynamodb_table.audit",
			"aws_dynamodb_table.ddb_rp_none",
		} {
			assertRP(t, addr, &falseVal, &falseVal, "")
		}
	})
	t.Run("K_world", func(t *testing.T) {
		assertRP(t, "aws_dynamodb_table.ddb_rp_world", &trueVal, &falseVal, "aws_dynamodb_resource_policy.ddb_rp_world")
	})
	t.Run("L_foreign_cross_omitted", func(t *testing.T) {
		assertRP(t, "aws_dynamodb_table.ddb_rp_foreign", &falseVal, nil, "aws_dynamodb_resource_policy.ddb_rp_foreign")
	})
	t.Run("L2_same_account_role", func(t *testing.T) {
		assertRP(t, "aws_dynamodb_table.ddb_rp_same", &falseVal, &falseVal, "aws_dynamodb_resource_policy.ddb_rp_same")
	})
	t.Run("M_org_restricted", func(t *testing.T) {
		assertRP(t, "aws_dynamodb_table.ddb_rp_org", &falseVal, &falseVal, "aws_dynamodb_resource_policy.ddb_rp_org")
	})
	t.Run("N_deny_cond_unverified", func(t *testing.T) {
		assertRP(t, "aws_dynamodb_table.ddb_rp_deny_cond", nil, nil, "")
	})
	t.Run("O_data_doc_restricted", func(t *testing.T) {
		assertRP(t, "aws_dynamodb_table.ddb_rp_doc", &falseVal, &falseVal, "data.aws_iam_policy_document.ddb_rp_doc")
	})

	for _, w := range warnings {
		if w == "no mapping for aws_dynamodb_resource_policy.ddb_rp_world; skipped" {
			t.Fatalf("unexpected no-mapping warning: %s", w)
		}
	}
}
