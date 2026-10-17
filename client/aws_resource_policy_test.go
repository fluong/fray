package client

import "testing"

func TestClassifyResourcePolicyWorldAndCross(t *testing.T) {
	ctx := awsResourcePolicyContext{owner: "999888777666", ownerOK: true}
	cases := []struct {
		name   string
		policy string
		cause  string
		world  triBool
		cross  triBool
	}{
		{
			name:   "world_open",
			policy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"dynamodb:GetItem","Resource":"*"}]}`,
			world:  triTrue, cross: triFalse,
		},
		{
			name:   "org_restricted",
			policy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"dynamodb:GetItem","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-exampleorgid"}}}]}`,
			world:  triFalse, cross: triFalse,
		},
		{
			name:   "foreign_literal_unknown_owner",
			policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"dynamodb:GetItem","Resource":"*"}]}`,
			world:  triFalse, cross: triOmit,
		},
		{
			name:   "foreign_literal_known_owner",
			policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"dynamodb:GetItem","Resource":"*"}]}`,
			world:  triFalse, cross: triTrue,
		},
		{
			name:   "deny_with_condition_omits",
			policy: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"dynamodb:*","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalOrgID":"o-x"}}}]}`,
			world:  triOmit, cross: triOmit,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useCtx := ctx
			if tc.name == "foreign_literal_unknown_owner" {
				useCtx = awsResourcePolicyContext{}
			}
			doc, ok := syntheticDocFromPolicyJSON("aws_dynamodb_resource_policy.test", tc.policy)
			if !ok {
				t.Fatal("bad policy json")
			}
			got := classifyResourcePolicyDoc(doc, useCtx)
			if got.world != tc.world || got.cross != tc.cross {
				t.Fatalf("world=%v cross=%v want world=%v cross=%v", got.world, got.cross, tc.world, tc.cross)
			}
		})
	}
}

func TestMergeResourcePolicyAnyTrueWins(t *testing.T) {
	merged := mergeResourcePolicyClassesSlice([]resourcePolicyClass{
		{world: triFalse, cross: triFalse},
		{world: triTrue, cross: triFalse},
	})
	if merged.world != triTrue || merged.cross != triFalse {
		t.Fatalf("merged world=%v cross=%v", merged.world, merged.cross)
	}
}

func TestConditionSourceArnWildcardNotRestricting(t *testing.T) {
	cond := map[string]any{
		"ArnLike": map[string]any{
			"aws:SourceArn": "arn:aws:s3:::bucket/prefix/*",
		},
	}
	if conditionFullyRestricts(cond) {
		t.Fatal("non-closed key must not restrict")
	}
	cond2 := map[string]any{
		"ArnLike": map[string]any{
			"aws:SourceArn": "arn:aws:s3:*:*:bucket/prefix/*",
		},
	}
	if conditionFullyRestricts(cond2) {
		t.Fatal("wildcard account in SourceArn must not restrict")
	}
}
