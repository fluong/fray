package client

import "testing"

func TestClassifyResourcePolicyWorldAndCross(t *testing.T) {
	ctx := awsResourcePolicyContext{owner: "111122223333", ownerOK: true}
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
			world:  triTrue, cross: triTrue,
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
		{world: triTrue, cross: triTrue},
	})
	if merged.world != triTrue || merged.cross != triTrue {
		t.Fatalf("merged world=%v cross=%v", merged.world, merged.cross)
	}
}

func TestS3BPANeutralizesAnyPrincipalNotForeign(t *testing.T) {
	ctx := awsResourcePolicyContext{owner: "111122223333", ownerOK: true}
	policy := `{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"},
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"s3:GetObject","Resource":"*"}
	]}`
	doc, ok := syntheticDocFromPolicyJSON("aws_s3_bucket_policy.test", policy)
	if !ok {
		t.Fatal("bad policy")
	}
	got := classifyResourcePolicyDocWithOptions(doc, ctx, resourcePolicyDocOptions{
		neutralizeAnyPrincipalAllow: true,
		neutralizeCause:             "aws_s3_bucket_public_access_block.test",
	})
	if got.world != triFalse || got.cross != triTrue {
		t.Fatalf("world=%v cross=%v want false/true (foreign principal still counts)", got.world, got.cross)
	}
}

func TestAccountBPASameProviderNeutralizesWorldPrincipal(t *testing.T) {
	plan := []byte(`{
	  "configuration": {"root_module": {"resources": [
	    {"address":"aws_s3_bucket.uploads","provider_config_key":"aws","expressions":{}},
	    {"address":"aws_s3_account_public_access_block.this","provider_config_key":"aws","expressions":{}}
	  ]}},
	  "resource_changes": [
	    {"address":"aws_s3_bucket.uploads","mode":"managed","type":"aws_s3_bucket","change":{"after":{"bucket":"b","region":"us-east-1"},"after_unknown":{"arn":true}}},
	    {"address":"aws_s3_account_public_access_block.this","mode":"managed","type":"aws_s3_account_public_access_block","change":{"after":{"restrict_public_buckets":true}}}
	  ]
	}`)
	keys := awsResourceProviderConfigKeys(plan)
	if keys["aws_s3_bucket.uploads"] != "aws" {
		t.Fatalf("provider key=%q", keys["aws_s3_bucket.uploads"])
	}
	resources, _ := loadResources(plan)
	ok, addr := accountBPARestrictsPublic(resources, keys, "aws")
	if !ok || addr != "aws_s3_account_public_access_block.this" {
		t.Fatalf("account BPA ok=%v addr=%q", ok, addr)
	}
	bucket := resources[0]
	neutral := s3BucketPolicyNeutralization(bucket, resources, configIndex{}, keys)
	if !neutral.blockAnyPrincipal || neutral.cause != addr {
		t.Fatalf("neutral=%+v", neutral)
	}
}

func TestAccountBPADifferentProviderIgnored(t *testing.T) {
	plan := []byte(`{
	  "configuration": {"root_module": {"resources": [
	    {"address":"aws_s3_bucket.uploads","provider_config_key":"aws"},
	    {"address":"aws_s3_account_public_access_block.other","provider_config_key":"aws.other"}
	  ]}},
	  "resource_changes": [
	    {"address":"aws_s3_bucket.uploads","mode":"managed","type":"aws_s3_bucket","change":{"after":{"bucket":"b"}}},
	    {"address":"aws_s3_account_public_access_block.other","mode":"managed","type":"aws_s3_account_public_access_block","change":{"after":{"restrict_public_buckets":true}}}
	  ]
	}`)
	keys := awsResourceProviderConfigKeys(plan)
	resources, _ := loadResources(plan)
	bucket := resources[0]
	neutral := s3BucketPolicyNeutralization(bucket, resources, configIndex{}, keys)
	if neutral.blockAnyPrincipal {
		t.Fatalf("expected no account BPA neutralization for provider alias mismatch")
	}
}

func TestBlockPublicPolicyNeutralizesWorldOnly(t *testing.T) {
	ctx := awsResourcePolicyContext{owner: "111122223333", ownerOK: true}
	policy := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`
	doc, ok := syntheticDocFromPolicyJSON("aws_secretsmanager_secret_policy.test", policy)
	if !ok {
		t.Fatal("bad policy")
	}
	got := classifyResourcePolicyDocWithOptions(doc, ctx, resourcePolicyDocOptions{
		neutralizeAnyPrincipalAllow: true,
		neutralizeCause:             "aws_secretsmanager_secret_policy.test",
	})
	if got.world != triFalse || got.cross != triFalse {
		t.Fatalf("world=%v cross=%v want false/false", got.world, got.cross)
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
