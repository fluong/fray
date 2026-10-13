package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const demoDFDSHA = "7a668e7b2563e40a9f025c1d1aecf62b59875499902b00536ea37ab401f0a0d3"

// Distinctive values for no-leak checks (must never appear on the wire DFD).
const (
	leakAccountID  = "111122223333"
	leakSecretARN  = "arn:aws:secretsmanager:eu-west-1:111122223333:secret:B35-LEAK-SECRET-AbCdEf"
	leakBucketARN  = "arn:aws:s3:::b35-leak-bucket-name"
	leakBucketName = "b35-leak-bucket-name"
	leakPolicyName = "b35-leak-policy-name-xyz"
	leakRolePolicy = "b35-leak-role-policy-xyz"
)

func TestSyntheticDocFromPolicyJSON(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantOK  bool
		wantLen int
		effect  string
	}{
		{
			name:    "allow_string_action_resource",
			raw:     `{"Version":"2012-10-17","Statement":{"Sid":"x","Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*","Principal":{"AWS":"*"}}}`,
			wantOK:  true,
			wantLen: 1,
			effect:  "Allow",
		},
		{
			name:    "list_forms",
			raw:     `{"Statement":[{"Effect":"Deny","Action":["s3:DeleteObject"],"Resource":["arn:aws:s3:::b/*"]}]}`,
			wantOK:  true,
			wantLen: 1,
			effect:  "Deny",
		},
		{
			name:   "malformed",
			raw:    `{not-json`,
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, ok := syntheticDocFromPolicyJSON("aws_iam_role_policy.x", tc.raw)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			stmts := asList(doc.values["statement"])
			if len(stmts) != tc.wantLen {
				t.Fatalf("stmts=%d want %d", len(stmts), tc.wantLen)
			}
			m := stmts[0].(map[string]any)
			if m["effect"] != tc.effect {
				t.Fatalf("effect=%v", m["effect"])
			}
			if _, ok := m["principal"]; ok {
				t.Fatal("principal must be ignored")
			}
			if _, ok := m["sid"]; ok {
				t.Fatal("sid must be ignored")
			}
		})
	}
}

func TestRoleDocumentsInlineSources(t *testing.T) {
	secretJSON := `{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`
	s3JSON := `{"Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:DeleteObject"],"Resource":"*"}]}`

	cases := []struct {
		name        string
		build       func() (module string, roleRefs []string, resources, data []planResource, idx configIndex)
		wantDocs    int
		wantUnknown bool
		wantCause   string // substring of a doc address when wantDocs>0
	}{
		{
			name: "a_role_policy_known_json",
			build: func() (string, []string, []planResource, []planResource, configIndex) {
				resources := []planResource{
					{address: "aws_iam_role.task", typ: "aws_iam_role"},
					{
						address: "aws_iam_role_policy.inline", typ: "aws_iam_role_policy",
						values: map[string]any{"policy": secretJSON, "name": leakRolePolicy},
					},
				}
				idx := configIndex{resources: map[string]exprSet{
					"aws_iam_role_policy.inline": {refs: map[string][]string{
						"role": {"aws_iam_role.task.name", "aws_iam_role.task"},
					}},
				}}
				return "", []string{"aws_iam_role.task"}, resources, nil, idx
			},
			wantDocs: 1, wantCause: "aws_iam_role_policy.inline",
		},
		{
			name: "a_role_policy_data_doc_ref",
			build: func() (string, []string, []planResource, []planResource, configIndex) {
				resources := []planResource{
					{address: "aws_iam_role.task", typ: "aws_iam_role"},
					{address: "aws_iam_role_policy.inline", typ: "aws_iam_role_policy", values: map[string]any{}},
				}
				data := []planResource{{
					address: "data.aws_iam_policy_document.sec", typ: "aws_iam_policy_document",
					values: map[string]any{"statement": []any{map[string]any{
						"effect": "Allow", "actions": []any{"secretsmanager:GetSecretValue"}, "resources": []any{"*"},
					}}},
				}}
				idx := configIndex{resources: map[string]exprSet{
					"aws_iam_role_policy.inline": {
						refs: map[string][]string{
							"role":   {"aws_iam_role.task.name", "aws_iam_role.task"},
							"policy": {"data.aws_iam_policy_document.sec.json", "data.aws_iam_policy_document.sec"},
						},
					},
				}}
				return "", []string{"aws_iam_role.task"}, resources, data, idx
			},
			wantDocs: 1, wantCause: "data.aws_iam_policy_document.sec",
		},
		{
			name: "a_role_policy_unknown",
			build: func() (string, []string, []planResource, []planResource, configIndex) {
				resources := []planResource{
					{address: "aws_iam_role.task", typ: "aws_iam_role"},
					{
						address: "aws_iam_role_policy.inline", typ: "aws_iam_role_policy",
						values: map[string]any{}, afterUnknown: map[string]any{"policy": true},
					},
				}
				idx := configIndex{resources: map[string]exprSet{
					"aws_iam_role_policy.inline": {
						refs: map[string][]string{
							"role":   {"aws_iam_role.task.name", "aws_iam_role.task"},
							"policy": {"aws_secretsmanager_secret.x.arn", "aws_secretsmanager_secret.x"},
						},
					},
				}}
				return "", []string{"aws_iam_role.task"}, resources, nil, idx
			},
			wantDocs: 0, wantUnknown: true,
		},
		{
			name: "b_inline_policy_known_json",
			build: func() (string, []string, []planResource, []planResource, configIndex) {
				resources := []planResource{{
					address: "aws_iam_role.task", typ: "aws_iam_role",
					values: map[string]any{
						"inline_policy": []any{map[string]any{"name": leakPolicyName, "policy": s3JSON}},
					},
				}}
				idx := configIndex{resources: map[string]exprSet{
					"aws_iam_role.task": {
						raw: map[string]any{"inline_policy": []any{map[string]any{
							"name":   map[string]any{"constant_value": leakPolicyName},
							"policy": map[string]any{"constant_value": s3JSON},
						}}},
					},
				}}
				return "", []string{"aws_iam_role.task"}, resources, nil, idx
			},
			wantDocs: 1, wantCause: "inline_policy." + leakPolicyName,
		},
		{
			name: "b_bare_after_unknown_inline_policy_ignored",
			build: func() (string, []string, []planResource, []planResource, configIndex) {
				resources := []planResource{{
					address: "aws_iam_role.task", typ: "aws_iam_role",
					values:       map[string]any{},
					afterUnknown: map[string]any{"inline_policy": true},
				}}
				idx := configIndex{resources: map[string]exprSet{
					"aws_iam_role.task": {},
				}}
				return "", []string{"aws_iam_role.task"}, resources, nil, idx
			},
			wantDocs: 0, wantUnknown: false,
		},
		{
			name: "c_managed_policy_arns_in_plan_policy_json",
			build: func() (string, []string, []planResource, []planResource, configIndex) {
				resources := []planResource{
					{
						address: "aws_iam_role.task", typ: "aws_iam_role",
						values: map[string]any{},
					},
					{
						address: "aws_iam_policy.extra", typ: "aws_iam_policy",
						values: map[string]any{"policy": secretJSON, "name": leakPolicyName},
					},
				}
				idx := configIndex{resources: map[string]exprSet{
					"aws_iam_role.task": {
						refs: map[string][]string{
							"managed_policy_arns": {"aws_iam_policy.extra.arn", "aws_iam_policy.extra"},
						},
						raw: map[string]any{"managed_policy_arns": map[string]any{
							"references": []any{"aws_iam_policy.extra.arn", "aws_iam_policy.extra"},
						}},
					},
					"aws_iam_policy.extra": {},
				}}
				return "", []string{"aws_iam_role.task"}, resources, nil, idx
			},
			wantDocs: 1, wantCause: "aws_iam_policy.extra",
		},
		{
			name: "c_bare_after_unknown_managed_policy_arns_ignored",
			build: func() (string, []string, []planResource, []planResource, configIndex) {
				resources := []planResource{{
					address: "aws_iam_role.task", typ: "aws_iam_role",
					values:       map[string]any{},
					afterUnknown: map[string]any{"managed_policy_arns": true},
				}}
				idx := configIndex{resources: map[string]exprSet{"aws_iam_role.task": {}}}
				return "", []string{"aws_iam_role.task"}, resources, nil, idx
			},
			wantDocs: 0, wantUnknown: false,
		},
		{
			name: "e_attachment_policy_json_string",
			build: func() (string, []string, []planResource, []planResource, configIndex) {
				resources := []planResource{
					{address: "aws_iam_role.task", typ: "aws_iam_role"},
					{address: "aws_iam_policy.jsonpol", typ: "aws_iam_policy", values: map[string]any{"policy": s3JSON}},
					{address: "aws_iam_role_policy_attachment.a", typ: "aws_iam_role_policy_attachment", values: map[string]any{}},
				}
				idx := configIndex{resources: map[string]exprSet{
					"aws_iam_role_policy_attachment.a": {refs: map[string][]string{
						"role":       {"aws_iam_role.task.name", "aws_iam_role.task"},
						"policy_arn": {"aws_iam_policy.jsonpol.arn", "aws_iam_policy.jsonpol"},
					}},
					"aws_iam_policy.jsonpol": {},
				}}
				return "", []string{"aws_iam_role.task"}, resources, nil, idx
			},
			wantDocs: 1, wantCause: "aws_iam_policy.jsonpol",
		},
		{
			name: "malformed_json_unknown",
			build: func() (string, []string, []planResource, []planResource, configIndex) {
				resources := []planResource{
					{address: "aws_iam_role.task", typ: "aws_iam_role"},
					{address: "aws_iam_role_policy.bad", typ: "aws_iam_role_policy", values: map[string]any{"policy": "{bad"}},
				}
				idx := configIndex{resources: map[string]exprSet{
					"aws_iam_role_policy.bad": {refs: map[string][]string{
						"role": {"aws_iam_role.task.name", "aws_iam_role.task"},
					}},
				}}
				return "", []string{"aws_iam_role.task"}, resources, nil, idx
			},
			wantDocs: 0, wantUnknown: true,
		},
		{
			name: "jsonencode_with_refs_unknown",
			build: func() (string, []string, []planResource, []planResource, configIndex) {
				resources := []planResource{
					{address: "aws_iam_role.task", typ: "aws_iam_role"},
					{
						address: "aws_iam_role_policy.enc", typ: "aws_iam_role_policy",
						values:       map[string]any{},
						afterUnknown: map[string]any{"policy": true},
					},
				}
				idx := configIndex{resources: map[string]exprSet{
					"aws_iam_role_policy.enc": {refs: map[string][]string{
						"role":   {"aws_iam_role.task.name", "aws_iam_role.task"},
						"policy": {leakSecretARN, "aws_secretsmanager_secret.db.arn", "aws_secretsmanager_secret.db"},
					}},
				}}
				return "", []string{"aws_iam_role.task"}, resources, nil, idx
			},
			wantDocs: 0, wantUnknown: true,
		},
		{
			name: "nested_module_role_policy",
			build: func() (string, []string, []planResource, []planResource, configIndex) {
				const mod = "module.ecs"
				role := mod + ".aws_iam_role.task"
				rp := mod + ".module.iam.aws_iam_role_policy.extra"
				resources := []planResource{
					{address: role, typ: "aws_iam_role"},
					{address: rp, typ: "aws_iam_role_policy", values: map[string]any{"policy": secretJSON}},
				}
				idx := configIndex{resources: map[string]exprSet{
					rp: {refs: map[string][]string{
						"role": {role + ".name", role},
					}},
				}}
				return mod, []string{role}, resources, nil, idx
			},
			wantDocs: 1, wantCause: "aws_iam_role_policy.extra",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mod, refs, resources, data, idx := tc.build()
			docs, unknown := roleDocuments(mod, refs, resources, data, idx)
			if unknown != tc.wantUnknown {
				t.Fatalf("unknown=%v want %v docs=%d", unknown, tc.wantUnknown, len(docs))
			}
			if len(docs) != tc.wantDocs {
				t.Fatalf("docs=%d want %d (%v)", len(docs), tc.wantDocs, docAddrs(docs))
			}
			if tc.wantCause != "" {
				found := false
				for _, d := range docs {
					if strings.Contains(d.address, tc.wantCause) {
						found = true
					}
				}
				if !found {
					t.Fatalf("no doc address contains %q: %v", tc.wantCause, docAddrs(docs))
				}
			}
		})
	}
}

func docAddrs(docs []planResource) []string {
	var out []string
	for _, d := range docs {
		out = append(out, d.address)
	}
	return out
}

func TestUnknownSourceOmitsConsumerScope(t *testing.T) {
	// Known narrow attachment doc + unknown role_policy → omit scopes.
	knownDoc := planResource{
		address: "data.aws_iam_policy_document.narrow",
		typ:     "aws_iam_policy_document",
		values: map[string]any{"statement": []any{map[string]any{
			"effect": "Allow", "actions": []any{"secretsmanager:GetSecretValue", "s3:PutObject", "bedrock:InvokeModel"},
			"resources": []any{nil},
		}}},
	}
	resources := []planResource{
		{address: "aws_iam_role.task", typ: "aws_iam_role"},
		{address: "aws_iam_policy.narrow", typ: "aws_iam_policy", values: map[string]any{}},
		{address: "aws_iam_role_policy_attachment.a", typ: "aws_iam_role_policy_attachment", values: map[string]any{}},
		{
			address: "aws_iam_role_policy.unknown", typ: "aws_iam_role_policy",
			values: map[string]any{}, afterUnknown: map[string]any{"policy": true},
		},
		{address: "aws_secretsmanager_secret.db", typ: "aws_secretsmanager_secret", values: map[string]any{"name": "db"}},
		{address: "aws_s3_bucket.uploads", typ: "aws_s3_bucket", values: map[string]any{"bucket": "uploads"}},
	}
	data := []planResource{knownDoc}
	idx := configIndex{
		resources: map[string]exprSet{
			"aws_iam_role_policy_attachment.a": {refs: map[string][]string{
				"role":       {"aws_iam_role.task.name", "aws_iam_role.task"},
				"policy_arn": {"aws_iam_policy.narrow.arn", "aws_iam_policy.narrow"},
			}},
			"aws_iam_policy.narrow": {refs: map[string][]string{
				"policy": {"data.aws_iam_policy_document.narrow.json", "data.aws_iam_policy_document.narrow"},
			}},
			"aws_iam_role_policy.unknown": {refs: map[string][]string{
				"role":   {"aws_iam_role.task.name", "aws_iam_role.task"},
				"policy": {"aws_secretsmanager_secret.db.arn"},
			}},
		},
		calls: map[string]exprSet{
			"": {refs: map[string][]string{
				"secret": {"module.db.aws_secretsmanager_secret.db"},
				"bucket": {"module.uploads.aws_s3_bucket.uploads"},
			}},
		},
	}
	// Fix call refs to match resource addresses used in elementsFromRefs
	idx.calls = map[string]exprSet{
		"module.db":      {refs: map[string][]string{"x": {"module.db.aws_secretsmanager_secret.db"}}},
		"module.uploads": {refs: map[string][]string{"x": {"module.uploads.aws_s3_bucket.uploads"}}},
	}
	// Use module-prefixed secrets/buckets for elementsFromRefs
	resources[4].address = "module.db.aws_secretsmanager_secret.db"
	resources[5].address = "module.uploads.aws_s3_bucket.uploads"

	docs, unknown := roleDocuments("", []string{"aws_iam_role.task"}, resources, data, idx)
	if !unknown {
		t.Fatal("expected unknown identity-policy source")
	}
	if len(docs) == 0 {
		t.Fatal("expected known docs still returned")
	}

	sec := &Element{
		Name: "db", Type: "datastore", Kind: "secret_store", Provider: "aws", Provenance: "iac",
		Evidence: Evidence{Addresses: []string{resources[4].address}},
	}
	bucket := &Element{
		Name: "uploads", Type: "datastore", Kind: "object_storage", Provider: "aws", Provenance: "iac",
		Evidence: Evidence{Addresses: []string{resources[5].address}},
	}
	elements := []*Element{sec, bucket}
	callRefs := []string{"module.db.aws_secretsmanager_secret.db", "module.uploads.aws_s3_bucket.uploads"}

	scope, _, _ := awsSecretScope(sec, docs, callRefs, resources, elements)
	if scope == "" {
		t.Fatal("known docs alone should still compute a scope (caller omits when unknown)")
	}
	// Simulate secretFlowsFrom omit rule:
	if unknown {
		scope = ""
	}
	if scope != "" {
		t.Fatal("secrets must omit authz_scope when unknown source present")
	}

	hits, grants, actions, _, amb, _ := bucketsFromDocs(docs, callRefs, resources, elements)
	if amb || len(hits) != 1 || len(grants) == 0 {
		t.Fatalf("S3 known grant hits=%d grants=%v amb=%v", len(hits), grants, amb)
	}
	if unknown {
		actions = nil
		grants = nil
	}
	if len(actions) != 0 || len(grants) != 0 {
		t.Fatalf("S3 must omit scope/actions when unknown; grants=%v actions=%v", grants, actions)
	}

	g, ok := bedrockGrantForRole("", []string{"aws_iam_role.task"}, resources, data, idx)
	if !ok {
		t.Fatal("Bedrock flow should exist when known Allow is present")
	}
	if g.scope != "" || g.region != "" || len(g.grants) != 0 {
		t.Fatalf("Bedrock must omit scope/region when unknown: %+v", g)
	}
}

func TestDenyInlineJSONBedrockOmitsSecretsS3NotGranted(t *testing.T) {
	denyJSON := `{"Statement":[{"Effect":"Deny","Action":"bedrock:InvokeModel","Resource":"*"},{"Effect":"Allow","Action":"logs:CreateLogStream","Resource":"*"}]}`
	resources := []planResource{
		{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{
			"inline_policy": []any{map[string]any{"name": "deny", "policy": denyJSON}},
		}},
	}
	data := []planResource{}
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_role.task": {
			raw: map[string]any{"inline_policy": []any{map[string]any{
				"name":   map[string]any{"constant_value": "deny"},
				"policy": map[string]any{"constant_value": denyJSON},
			}}},
		},
	}}
	// Also attach an Allow bedrock via separate role_policy so hasAllow is true with Deny.
	allowJSON := `{"Statement":[{"Effect":"Allow","Action":"bedrock:InvokeModel","Resource":"*"}]}`
	resources = append(resources, planResource{
		address: "aws_iam_role_policy.allow", typ: "aws_iam_role_policy",
		values: map[string]any{"policy": allowJSON},
	})
	idx.resources["aws_iam_role_policy.allow"] = exprSet{refs: map[string][]string{
		"role": {"aws_iam_role.task.name", "aws_iam_role.task"},
	}}

	g, ok := bedrockGrantForRole("", []string{"aws_iam_role.task"}, resources, data, idx)
	if !ok {
		t.Fatal("expected bedrock flow")
	}
	if g.scope != "" {
		t.Fatalf("Deny must omit bedrock scope, got %q", g.scope)
	}

	docs, unknown := roleDocuments("", []string{"aws_iam_role.task"}, resources, data, idx)
	if unknown {
		t.Fatal("unexpected unknown")
	}
	sec := &Element{Evidence: Evidence{Addresses: []string{"aws_secretsmanager_secret.x"}}}
	scope, _, _ := awsSecretScope(sec, docs, nil, resources, []*Element{sec})
	if scope != "" {
		t.Fatalf("secrets must not be granted by Deny/logs-only inline, got %q", scope)
	}
	hits, grants, _, _, _, _ := bucketsFromDocs(docs, nil, resources, []*Element{})
	if len(hits) != 0 || len(grants) != 0 {
		t.Fatalf("S3 must not be granted, hits=%d grants=%v", len(hits), grants)
	}
}

func TestKnownARNResourceClassification(t *testing.T) {
	secRes := planResource{
		address: "module.db.aws_secretsmanager_secret.db",
		typ:     "aws_secretsmanager_secret",
		values:  map[string]any{"name": "app/db", "arn": leakSecretARN},
	}
	otherSec := planResource{
		address: "module.db.aws_secretsmanager_secret.other",
		typ:     "aws_secretsmanager_secret",
		values:  map[string]any{"name": "other", "arn": "arn:aws:secretsmanager:eu-west-1:111122223333:secret:other-xxxx"},
	}
	bucketRes := planResource{
		address: "module.uploads.aws_s3_bucket.this",
		typ:     "aws_s3_bucket",
		values:  map[string]any{"bucket": leakBucketName, "arn": leakBucketARN},
	}
	secEl := &Element{
		Name: "db", Type: "datastore", Kind: "secret_store", Provider: "aws", Provenance: "iac",
		Evidence: Evidence{Addresses: []string{secRes.address}},
	}
	bucketEl := &Element{
		Name: "uploads", Type: "datastore", Kind: "object_storage", Provider: "aws", Provenance: "iac",
		Evidence: Evidence{Addresses: []string{bucketRes.address}},
	}
	resources := []planResource{secRes, otherSec, bucketRes}
	elements := []*Element{secEl, bucketEl}
	callRefs := []string{secRes.address, bucketRes.address}

	cases := []struct {
		name      string
		resources []any
		wantSec   string
		wantS3    string
		wantBed   string
	}{
		{
			name:      "matching_secret_arn_resource",
			resources: []any{leakSecretARN},
			wantSec:   "resource",
		},
		{
			name:      "non_matching_secret_arn_no_cover",
			resources: []any{"arn:aws:secretsmanager:eu-west-1:111122223333:secret:other-xxxx"},
			wantSec:   "",
		},
		{
			name:      "wildcard_secret_account",
			resources: []any{"arn:aws:secretsmanager:eu-west-1:111122223333:secret:*"},
			wantSec:   "account",
		},
		{
			name:      "matching_bucket_object_wildcard_resource",
			resources: []any{leakBucketARN + "/*"},
			wantS3:    "resource",
		},
		{
			name:      "matching_bucket_arn_exact",
			resources: []any{leakBucketARN},
			wantS3:    "resource",
		},
		{
			name:      "non_matching_bucket",
			resources: []any{"arn:aws:s3:::other-bucket"},
			wantS3:    "",
		},
		{
			name:      "bedrock_foundation_resource",
			resources: []any{"arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"},
			wantBed:   "resource",
		},
		{
			name:      "bedrock_star_account",
			resources: []any{"*"},
			wantBed:   "account",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := planResource{
				address: "data.aws_iam_policy_document.x",
				typ:     "aws_iam_policy_document",
				values: map[string]any{"statement": []any{map[string]any{
					"effect": "Allow",
					"actions": []any{
						"secretsmanager:GetSecretValue", "s3:PutObject", "s3:DeleteObject", "bedrock:InvokeModel",
					},
					"resources": tc.resources,
				}}},
			}
			docs := []planResource{doc}
			if tc.wantSec != "" || strings.Contains(tc.name, "secret") || strings.Contains(tc.name, "wildcard_secret") || strings.Contains(tc.name, "non_matching_secret") {
				scope, _, _ := awsSecretScope(secEl, docs, callRefs, resources, elements)
				if scope != tc.wantSec {
					t.Fatalf("secret scope=%q want %q", scope, tc.wantSec)
				}
			}
			if tc.wantS3 != "" || strings.Contains(tc.name, "bucket") {
				_, grants, _, _, _, _ := bucketsFromDocs(docs, callRefs, resources, elements)
				got := effectiveAuthzScope(grants)
				if got != tc.wantS3 {
					t.Fatalf("s3 scope=%q want %q grants=%v", got, tc.wantS3, grants)
				}
			}
			if tc.wantBed != "" {
				scope, _, ok := bedrockScopeFromAllows(docStatements(doc))
				if !ok && tc.wantBed != "" {
					t.Fatalf("bedrock scope not ok")
				}
				if scope != tc.wantBed {
					t.Fatalf("bedrock scope=%q want %q", scope, tc.wantBed)
				}
			}
		})
	}
}

func TestARNWildcardRefinement(t *testing.T) {
	secRes := planResource{
		address: "module.db.aws_secretsmanager_secret.db",
		typ:     "aws_secretsmanager_secret",
		values:  map[string]any{"name": "app/db", "arn": "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db-AbCdEf"},
	}
	bucketRes := planResource{
		address: "module.uploads.aws_s3_bucket.this",
		typ:     "aws_s3_bucket",
		values:  map[string]any{"bucket": "uploads-bucket", "arn": "arn:aws:s3:::uploads-bucket"},
	}
	secEl := &Element{
		Evidence: Evidence{Addresses: []string{secRes.address}},
		Name:     "db", Type: "datastore", Kind: "secret_store", Provider: "aws", Provenance: "iac",
	}
	bucketEl := &Element{
		Evidence: Evidence{Addresses: []string{bucketRes.address}},
		Name:     "uploads", Type: "datastore", Kind: "object_storage", Provider: "aws", Provenance: "iac",
	}
	resources := []planResource{secRes, bucketRes}
	elements := []*Element{secEl, bucketEl}
	callRefs := []string{secRes.address, bucketRes.address}

	cases := []struct {
		name    string
		arn     string
		wantSec string
		wantS3  string
	}{
		// S3 object-key wildcards → resource
		{name: "s3_bucket_slash_star", arn: "arn:aws:s3:::uploads-bucket/*", wantS3: "resource"},
		{name: "s3_bucket_prefix_star", arn: "arn:aws:s3:::uploads-bucket/inbox*", wantS3: "resource"},
		{name: "s3_exact_bucket", arn: "arn:aws:s3:::uploads-bucket", wantS3: "resource"},
		{name: "s3_non_matching_bucket", arn: "arn:aws:s3:::other-bucket/*", wantS3: ""},
		// S3 bucket-name wildcards → account
		{name: "s3_star_bucket", arn: "arn:aws:s3:::*", wantS3: "account"},
		{name: "s3_app_star_bucket", arn: "arn:aws:s3:::app-*", wantS3: "account"},
		{name: "s3_star_slash_star", arn: "arn:aws:s3:::*/*", wantS3: "account"},
		// Secrets suffix forms → resource when name matches
		{name: "secret_name_dash_star", arn: "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db-*", wantSec: "resource"},
		{name: "secret_name_dash_qqqqqq", arn: "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db-??????", wantSec: "resource"},
		{name: "secret_name_star_omit", arn: "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db*", wantSec: ""},
		{name: "secret_exact_arn", arn: "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db-AbCdEf", wantSec: "resource"},
		{name: "secret_non_matching_name", arn: "arn:aws:secretsmanager:eu-west-1:111122223333:secret:other-*", wantSec: ""},
		// Secrets account-wide wildcards
		{name: "secret_star", arn: "arn:aws:secretsmanager:eu-west-1:111122223333:secret:*", wantSec: "account"},
		{name: "secret_prod_slash_star", arn: "arn:aws:secretsmanager:eu-west-1:111122223333:secret:prod/*", wantSec: "account"},
		{name: "secret_region_star", arn: "arn:aws:secretsmanager:*:111122223333:secret:app/db", wantSec: "account"},
		{name: "secret_account_star", arn: "arn:aws:secretsmanager:eu-west-1:*:secret:app/db", wantSec: "account"},
		{name: "star_all", arn: "*", wantSec: "account", wantS3: "account"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := planResource{
				address: "data.aws_iam_policy_document.x",
				typ:     "aws_iam_policy_document",
				values: map[string]any{"statement": []any{map[string]any{
					"effect":    "Allow",
					"actions":   []any{"secretsmanager:GetSecretValue", "s3:PutObject", "s3:DeleteObject"},
					"resources": []any{tc.arn},
				}}},
			}
			docs := []planResource{doc}
			if tc.wantSec != "" || strings.HasPrefix(tc.name, "secret_") || tc.name == "star_all" {
				scope, _, _ := awsSecretScope(secEl, docs, callRefs, resources, elements)
				if scope != tc.wantSec {
					t.Fatalf("secret scope=%q want %q", scope, tc.wantSec)
				}
			}
			if tc.wantS3 != "" || strings.HasPrefix(tc.name, "s3_") || tc.name == "star_all" {
				_, grants, _, _, _, _ := bucketsFromDocs(docs, callRefs, resources, elements)
				got := effectiveAuthzScope(grants)
				if got != tc.wantS3 {
					t.Fatalf("s3 scope=%q want %q grants=%v", got, tc.wantS3, grants)
				}
			}
		})
	}
}

// TestFlatCoverageS3TaskRoleResourceScope mirrors fray-demo-coverage infra:
// one root task def, task_role with literal Put/Delete on bucket/* plus a
// data.aws_iam_policy_document in resource_changes (plan-unknown object ARN).
// Proves authz_scope=resource without running terraform locally.
func TestFlatCoverageS3TaskRoleResourceScope(t *testing.T) {
	plan := flatCoverageS3Plan(t, true)
	doc, _, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "t/coverage-s3", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var s3 *Flow
	for i := range doc.Flows {
		f := &doc.Flows[i]
		for _, el := range doc.Elements {
			if el.ID == f.To && el.Kind == "object_storage" {
				s3 = f
				break
			}
		}
		if s3 != nil {
			break
		}
	}
	if s3 == nil {
		t.Fatal("expected container → object_storage flow")
	}
	if s3.AuthzScope != "resource" {
		t.Fatalf("authz_scope=%q want resource (grants=%v)", s3.AuthzScope, s3.AuthzGrants)
	}
	wantActions := []string{"DeleteObject", "PutObject"}
	if strings.Join(s3.AuthzActions, ",") != strings.Join(wantActions, ",") {
		t.Fatalf("authz_actions=%v want %v", s3.AuthzActions, wantActions)
	}
}

// TestFlatCoverageS3DataDocPriorStateOnly: plan-time data.aws_iam_policy_document
// values live in prior_state when every argument is known at plan (no
// resource_changes entry). loadDataResources must read them so authz_scope is set.
func TestFlatCoverageS3DataDocPriorStateOnly(t *testing.T) {
	plan := flatCoverageS3Plan(t, false)
	doc, _, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "t/coverage-s3", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var s3 *Flow
	for i := range doc.Flows {
		f := &doc.Flows[i]
		for _, el := range doc.Elements {
			if el.ID == f.To && el.Kind == "object_storage" {
				s3 = f
				break
			}
		}
		if s3 != nil {
			break
		}
	}
	if s3 == nil {
		t.Fatal("expected container → object_storage flow")
	}
	if s3.AuthzScope != "resource" {
		t.Fatalf("authz_scope=%q want resource when data-doc is only in prior_state", s3.AuthzScope)
	}
}

func flatCoverageS3Plan(t *testing.T, dataInResourceChanges bool) string {
	t.Helper()
	bucket := "fray-coverage-uploads-fake"
	literal := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:DeleteObject"],"Resource":["arn:aws:s3:::` + bucket + `/*"]}]}`
	resources := []map[string]any{
		{
			"address": "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
		},
		{
			"address": "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"family":                "app",
				"container_definitions": `[{"name":"app","image":"public.ecr.aws/docker/library/nginx:1.27","essential":true}]`,
			}, "after_unknown": map[string]any{"task_role_arn": true, "execution_role_arn": true}},
		},
		{
			"address": "aws_iam_role.ecs_exec", "mode": "managed", "type": "aws_iam_role", "name": "ecs_exec",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "ecs-exec"}},
		},
		{
			"address": "aws_iam_role.ecs_task", "mode": "managed", "type": "aws_iam_role", "name": "ecs_task",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "ecs-task"},
				"after_unknown": map[string]any{"inline_policy": true, "managed_policy_arns": true}},
		},
		{
			"address": "aws_iam_role_policy.known", "mode": "managed", "type": "aws_iam_role_policy", "name": "known",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "known-literal-arns", "policy": literal}},
		},
		{
			"address": "aws_iam_role_policy.datadoc", "mode": "managed", "type": "aws_iam_role_policy", "name": "datadoc",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "datadoc-from-data"},
				"after_unknown": map[string]any{"policy": true}},
		},
		{
			"address": "aws_s3_bucket.uploads", "mode": "managed", "type": "aws_s3_bucket", "name": "uploads",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"bucket": bucket}},
		},
	}
	if dataInResourceChanges {
		resources = append(resources, map[string]any{
			"address": "data.aws_iam_policy_document.datadoc", "mode": "data", "type": "aws_iam_policy_document", "name": "datadoc",
			"change": map[string]any{"actions": []any{"read"}, "after": map[string]any{
				"statement": []any{map[string]any{
					"sid": "S3Write", "effect": "Allow",
					"actions":   []any{"s3:PutObject", "s3:DeleteObject"},
					"resources": []any{nil},
				}},
			}, "after_unknown": map[string]any{"json": true, "statement": []any{map[string]any{"resources": []any{true}}}}},
		})
	}
	cfg := []map[string]any{
		{
			"address": "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
			"expressions": map[string]any{
				"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.app.arn", "aws_ecs_task_definition.app"}},
			},
		},
		{
			"address": "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
			"expressions": map[string]any{
				"execution_role_arn": map[string]any{"references": []any{"aws_iam_role.ecs_exec.arn", "aws_iam_role.ecs_exec"}},
				"task_role_arn":      map[string]any{"references": []any{"aws_iam_role.ecs_task.arn", "aws_iam_role.ecs_task"}},
			},
		},
		{"address": "aws_iam_role.ecs_exec", "mode": "managed", "type": "aws_iam_role", "name": "ecs_exec", "expressions": map[string]any{}},
		{"address": "aws_iam_role.ecs_task", "mode": "managed", "type": "aws_iam_role", "name": "ecs_task", "expressions": map[string]any{}},
		{
			"address": "aws_iam_role_policy.known", "mode": "managed", "type": "aws_iam_role_policy", "name": "known",
			"expressions": map[string]any{
				"role":   map[string]any{"references": []any{"aws_iam_role.ecs_task.id", "aws_iam_role.ecs_task"}},
				"policy": map[string]any{"constant_value": literal},
			},
		},
		{
			"address": "aws_iam_role_policy.datadoc", "mode": "managed", "type": "aws_iam_role_policy", "name": "datadoc",
			"expressions": map[string]any{
				"role":   map[string]any{"references": []any{"aws_iam_role.ecs_task.id", "aws_iam_role.ecs_task"}},
				"policy": map[string]any{"references": []any{"data.aws_iam_policy_document.datadoc.json", "data.aws_iam_policy_document.datadoc"}},
			},
		},
		{"address": "aws_s3_bucket.uploads", "mode": "managed", "type": "aws_s3_bucket", "name": "uploads", "expressions": map[string]any{}},
		{
			"address": "data.aws_iam_policy_document.datadoc", "mode": "data", "type": "aws_iam_policy_document", "name": "datadoc",
			"expressions": map[string]any{},
		},
	}
	priorData := []map[string]any{
		{
			"address": "data.aws_iam_policy_document.datadoc", "mode": "data", "type": "aws_iam_policy_document", "name": "datadoc",
			"values": map[string]any{
				"statement": []any{map[string]any{
					"sid": "S3Write", "effect": "Allow",
					"actions":   []any{"s3:PutObject", "s3:DeleteObject"},
					"resources": []any{"arn:aws:s3:::" + bucket + "/*"},
				}},
			},
		},
	}
	plan := map[string]any{
		"format_version":   "1.2",
		"resource_changes": resources,
		"configuration":    map[string]any{"root_module": map[string]any{"resources": cfg}},
		"planned_values":   map[string]any{"root_module": map[string]any{"resources": []any{}}},
		"prior_state":      map[string]any{"values": map[string]any{"root_module": map[string]any{"resources": priorData}}},
	}
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMixedCaseSecretAndS3Actions(t *testing.T) {
	if !secretAction("SecretsManager:GetSecretValue") {
		t.Fatal("secretAction should be case-insensitive")
	}
	if !secretAction("SECRETSMANAGER:*") {
		t.Fatal("secretAction wildcard case")
	}
	if !s3Action("S3:PutObject") {
		t.Fatal("s3Action should be case-insensitive")
	}
	if !s3Action("s3:deleteobject") {
		t.Fatal("s3Action lower")
	}
}

func TestInlineIAMNoLeakOnWire(t *testing.T) {
	plan := inlineIAMNoLeakPlan(t)
	doc, _, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "t/b35", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, leak := range []string{leakAccountID, leakSecretARN, leakBucketARN, leakBucketName, leakPolicyName, leakRolePolicy} {
		if strings.Contains(s, leak) {
			t.Fatalf("wire DFD leaked %q", leak)
		}
	}
}

func inlineIAMNoLeakPlan(t *testing.T) string {
	t.Helper()
	policy := `{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"` + leakSecretARN + `"},{"Effect":"Allow","Action":["s3:PutObject","s3:DeleteObject"],"Resource":["` + leakBucketARN + `","` + leakBucketARN + `/*"]}]}`
	resources := []map[string]any{
		{
			"address": "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
			"change": map[string]any{"after": map[string]any{"name": "app"}},
		},
		{
			"address": "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
			"change": map[string]any{"after": map[string]any{
				"family": "app",
				"container_definitions": `[{"name":"app","image":"app:1","secrets":[{"name":"DB","valueFrom":"arn:aws:secretsmanager:eu-west-1:111122223333:secret:B35-LEAK-SECRET"}]}]`,
			}},
		},
		{
			"address": "aws_iam_role.exec", "mode": "managed", "type": "aws_iam_role", "name": "exec",
			"change": map[string]any{"after": map[string]any{"name": "exec"}},
		},
		{
			"address": "aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task",
			"change": map[string]any{"after": map[string]any{
				"name": "task",
				"inline_policy": []any{map[string]any{"name": leakPolicyName, "policy": policy}},
			}},
		},
		{
			"address": "aws_iam_role_policy.exec_secrets", "mode": "managed", "type": "aws_iam_role_policy", "name": "exec_secrets",
			"change": map[string]any{"after": map[string]any{"name": leakRolePolicy, "policy": policy}},
		},
		{
			"address": "module.db.aws_secretsmanager_secret.db", "mode": "managed", "type": "aws_secretsmanager_secret", "name": "db",
			"change": map[string]any{"after": map[string]any{"name": "app/db", "arn": leakSecretARN}},
		},
		{
			"address": "module.uploads.aws_s3_bucket.this", "mode": "managed", "type": "aws_s3_bucket", "name": "this",
			"change": map[string]any{"after": map[string]any{"bucket": leakBucketName, "arn": leakBucketARN}},
		},
	}
	cfg := []map[string]any{
		{
			"address": "aws_ecs_service.app", "type": "aws_ecs_service", "name": "app",
			"expressions": map[string]any{
				"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.app.arn", "aws_ecs_task_definition.app"}},
			},
		},
		{
			"address": "aws_ecs_task_definition.app", "type": "aws_ecs_task_definition", "name": "app",
			"expressions": map[string]any{
				"execution_role_arn": map[string]any{"references": []any{"aws_iam_role.exec.arn", "aws_iam_role.exec"}},
				"task_role_arn":      map[string]any{"references": []any{"aws_iam_role.task.arn", "aws_iam_role.task"}},
			},
		},
		{"address": "aws_iam_role.exec", "type": "aws_iam_role", "name": "exec", "expressions": map[string]any{}},
		{
			"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
			"expressions": map[string]any{
				"inline_policy": []any{map[string]any{
					"name":   map[string]any{"constant_value": leakPolicyName},
					"policy": map[string]any{"constant_value": policy},
				}},
			},
		},
		{
			"address": "aws_iam_role_policy.exec_secrets", "type": "aws_iam_role_policy", "name": "exec_secrets",
			"expressions": map[string]any{
				"role":   map[string]any{"references": []any{"aws_iam_role.exec.name", "aws_iam_role.exec"}},
				"policy": map[string]any{"constant_value": policy},
			},
		},
		{"address": "module.db.aws_secretsmanager_secret.db", "type": "aws_secretsmanager_secret", "name": "db", "expressions": map[string]any{}},
		{"address": "module.uploads.aws_s3_bucket.this", "type": "aws_s3_bucket", "name": "this", "expressions": map[string]any{}},
	}
	// module_calls so callRefs resolve secrets/buckets
	root := map[string]any{
		"resources": cfg,
		"module_calls": map[string]any{
			"db": map[string]any{
				"source": "./db",
				"module": map[string]any{
					"resources": []any{
						map[string]any{"address": "aws_secretsmanager_secret.db", "type": "aws_secretsmanager_secret", "name": "db", "expressions": map[string]any{}},
					},
				},
				"expressions": map[string]any{},
			},
			"uploads": map[string]any{
				"source": "./uploads",
				"module": map[string]any{
					"resources": []any{
						map[string]any{"address": "aws_s3_bucket.this", "type": "aws_s3_bucket", "name": "this", "expressions": map[string]any{}},
					},
				},
				"expressions": map[string]any{},
			},
		},
	}
	plan := map[string]any{
		"format_version":    "1.2",
		"resource_changes":  resources,
		"configuration":     map[string]any{"root_module": root},
		"planned_values":    map[string]any{"root_module": map[string]any{"resources": []any{}}},
	}
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDemoFixtureDFDHashUnchanged(t *testing.T) {
	plan, err := os.ReadFile("testdata/aws-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, _, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "", Source{
		Repo: "example/aws-web-app", Commit: "4530a865f29ba14931379f361b177a992edeab51",
		Tool: "terraform", Fidelity: "plan",
	}, filepath.Join("..", "testdata", "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != demoDFDSHA {
		t.Fatalf("demo DFD sha256=%s want %s", hex.EncodeToString(sum[:]), demoDFDSHA)
	}
	want, err := os.ReadFile(filepath.Join("..", "testdata", "golden", "aws-web-app-fixture.dfd.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("demo DFD not byte-identical to golden (%d vs %d bytes)", len(got), len(want))
	}
}

func TestAttachmentUnknownPolicyOmitsScope(t *testing.T) {
	// Behaviour change vs pre-B-35: attachment → aws_iam_policy with unknown
	// JSON and no data-doc ref used to be silently skipped; now marks unknown.
	resources := []planResource{
		{address: "aws_iam_role.task", typ: "aws_iam_role"},
		{
			address: "aws_iam_policy.unk", typ: "aws_iam_policy",
			values: map[string]any{}, afterUnknown: map[string]any{"policy": true},
		},
		{address: "aws_iam_role_policy_attachment.a", typ: "aws_iam_role_policy_attachment", values: map[string]any{}},
		{
			address: "aws_iam_policy.known", typ: "aws_iam_policy",
			values: map[string]any{},
		},
		{address: "aws_iam_role_policy_attachment.b", typ: "aws_iam_role_policy_attachment", values: map[string]any{}},
	}
	data := []planResource{{
		address: "data.aws_iam_policy_document.known", typ: "aws_iam_policy_document",
		values: map[string]any{"statement": []any{map[string]any{
			"effect": "Allow", "actions": []any{"secretsmanager:GetSecretValue"}, "resources": []any{"*"},
		}}},
	}}
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_role_policy_attachment.a": {refs: map[string][]string{
			"role": {"aws_iam_role.task.name", "aws_iam_role.task"}, "policy_arn": {"aws_iam_policy.unk.arn", "aws_iam_policy.unk"},
		}},
		"aws_iam_policy.unk": {refs: map[string][]string{
			"policy": {"aws_secretsmanager_secret.x.arn"},
		}},
		"aws_iam_role_policy_attachment.b": {refs: map[string][]string{
			"role": {"aws_iam_role.task.name", "aws_iam_role.task"}, "policy_arn": {"aws_iam_policy.known.arn", "aws_iam_policy.known"},
		}},
		"aws_iam_policy.known": {refs: map[string][]string{
			"policy": {"data.aws_iam_policy_document.known.json", "data.aws_iam_policy_document.known"},
		}},
	}}
	docs, unknown := roleDocuments("", []string{"aws_iam_role.task"}, resources, data, idx)
	if !unknown {
		t.Fatal("attachment-backed unknown policy must set unknown")
	}
	if len(docs) != 1 {
		t.Fatalf("docs=%d want 1 known", len(docs))
	}
}
