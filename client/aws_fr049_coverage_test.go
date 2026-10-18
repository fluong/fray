package client

import (
	"path/filepath"
	"testing"
)

func TestFr049HCLSecretPoliciesIndexed(t *testing.T) {
	modDir := filepath.Join("testdata", "fr049_hcl")
	idx, err := readRootIAMPolicyLiterals(modDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{
		"aws_secretsmanager_secret_policy.sm_rp_world",
		"aws_secretsmanager_secret_policy.sm_rp_block",
		"aws_secretsmanager_secret_policy.sm_rp_same",
	} {
		if _, ok := idx[addr]; !ok {
			t.Fatalf("missing HCL policy literal for %s", addr)
		}
	}
}

func TestCoverageFR049FR050ResourcePolicyAttrs(t *testing.T) {
	modDir := filepath.Join("testdata", "fr049_hcl")
	doc, warnings := parseCoveragePlanModule(t, "coverage-fr049-plan.json", modDir)

	assertRP := func(t *testing.T, addr string, world *bool, cross *bool, cause string) {
		t.Helper()
		el, ok := elementByAddress(doc, addr)
		if !ok {
			t.Fatalf("missing element %s", addr)
		}
		gotW, okW := el.Attributes["resource_policy_world_principal"].(bool)
		if world == nil {
			if okW {
				t.Fatalf("%s: world attr set=%v want omitted", addr, gotW)
			}
		} else if !okW || gotW != *world {
			t.Fatalf("%s: world=%v ok=%v want %v", addr, gotW, okW, *world)
		}
		gotC, okC := el.Attributes["resource_policy_cross_account"].(bool)
		if cross == nil {
			if okC {
				t.Fatalf("%s: cross attr set=%v want omitted", addr, gotC)
			}
		} else if !okC || gotC != *cross {
			t.Fatalf("%s: cross=%v ok=%v want %v", addr, gotC, okC, *cross)
		}
		if cause != "" {
			wCause := el.Causes["resource_policy_world_principal"]
			cCause := el.Causes["resource_policy_cross_account"]
			if wCause != cause && cCause != cause {
				t.Fatalf("%s: causes world=%q cross=%q want %q on set axis", addr, wCause, cCause, cause)
			}
		}
	}

	falseVal := false
	trueVal := true

	t.Run("existing_buckets_and_secret_mitigated", func(t *testing.T) {
		for _, addr := range []string{
			"aws_s3_bucket.uploads",
			"aws_s3_bucket.worker",
			"aws_secretsmanager_secret.app",
		} {
			assertRP(t, addr, &falseVal, &falseVal, "")
		}
	})
	t.Run("S_K_world", func(t *testing.T) {
		assertRP(t, "aws_s3_bucket.s3_rp_world", &trueVal, &trueVal, "aws_s3_bucket_policy.s3_rp_world")
	})
	t.Run("S_L_foreign", func(t *testing.T) {
		assertRP(t, "aws_s3_bucket.s3_rp_foreign", &falseVal, nil, "aws_s3_bucket_policy.s3_rp_foreign")
	})
	t.Run("S_L2_same", func(t *testing.T) {
		assertRP(t, "aws_s3_bucket.s3_rp_same", &falseVal, &falseVal, "aws_s3_bucket_policy.s3_rp_same")
	})
	t.Run("S_M_org", func(t *testing.T) {
		assertRP(t, "aws_s3_bucket.s3_rp_org", &falseVal, &falseVal, "aws_s3_bucket_policy.s3_rp_org")
	})
	t.Run("S_N_deny_unverified", func(t *testing.T) {
		assertRP(t, "aws_s3_bucket.s3_rp_deny_cond", nil, nil, "")
	})
	t.Run("S_O_data_doc", func(t *testing.T) {
		assertRP(t, "aws_s3_bucket.s3_rp_doc", &falseVal, &falseVal, "data.aws_iam_policy_document.s3_rp_doc")
	})
	t.Run("S_BPA", func(t *testing.T) {
		assertRP(t, "aws_s3_bucket.s3_rp_bpa", &falseVal, &falseVal, "aws_s3_bucket_public_access_block.s3_rp_bpa")
	})
	t.Run("SM_K_world", func(t *testing.T) {
		assertRP(t, "aws_secretsmanager_secret.sm_rp_world", &trueVal, &trueVal, "aws_secretsmanager_secret_policy.sm_rp_world")
	})
	t.Run("SM_BPP_block", func(t *testing.T) {
		assertRP(t, "aws_secretsmanager_secret.sm_rp_block", &falseVal, &falseVal, "aws_secretsmanager_secret.sm_rp_block")
	})
	t.Run("SM_L2_same", func(t *testing.T) {
		assertRP(t, "aws_secretsmanager_secret.sm_rp_same", &falseVal, &falseVal, "aws_secretsmanager_secret_policy.sm_rp_same")
	})
	t.Run("SM_NONE", func(t *testing.T) {
		assertRP(t, "aws_secretsmanager_secret.sm_rp_none", &falseVal, &falseVal, "")
	})

	for _, w := range warnings {
		if w == "no mapping for aws_s3_bucket_policy.s3_rp_world; skipped" ||
			w == "no mapping for aws_secretsmanager_secret_policy.sm_rp_world; skipped" {
			t.Fatalf("unexpected no-mapping warning: %s", w)
		}
	}
}
