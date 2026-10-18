package client

import (
	"path/filepath"
	"testing"
)

func TestFr044HCLQueuePoliciesIndexed(t *testing.T) {
	modDir := filepath.Join("testdata", "fr044_hcl")
	idx, err := readRootIAMPolicyLiterals(modDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{
		"aws_sqs_queue_policy.sqs_rp_world",
		"aws_iam_role_policy.f45_res",
	} {
		if _, ok := idx[addr]; !ok {
			t.Fatalf("missing HCL policy literal for %s (keys=%d)", addr, len(idx))
		}
	}
}
