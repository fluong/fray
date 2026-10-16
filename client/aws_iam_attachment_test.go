package client

import (
	"strings"
	"testing"
)

const s3PutJSON = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::b35-leak-bucket-name/*"]}]}`

func attachmentS3BucketFixture() (resources []planResource, elements []*Element) {
	bucket := planResource{
		address: "aws_s3_bucket.uploads", typ: "aws_s3_bucket",
		values: map[string]any{"bucket": leakBucketName, "arn": leakBucketARN},
	}
	el := &Element{
		Evidence: Evidence{Addresses: []string{bucket.address}},
		Name:     "uploads", Type: "datastore", Kind: "object_storage", Provider: "aws", Provenance: "iac",
	}
	return []planResource{bucket}, []*Element{el}
}

func TestPolicyAttachmentRolesGrantBoth(t *testing.T) {
	bucketRes, elements := attachmentS3BucketFixture()
	resources := []planResource{
		{address: "aws_iam_role.a", typ: "aws_iam_role"},
		{address: "aws_iam_role.b", typ: "aws_iam_role"},
		{address: "aws_iam_policy.s3", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
		{address: "aws_iam_policy_attachment.both", typ: "aws_iam_policy_attachment", values: map[string]any{}},
	}
	resources = append(resources, bucketRes...)
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_policy_attachment.both": {refs: map[string][]string{
			"roles":      {"aws_iam_role.a.name", "aws_iam_role.a", "aws_iam_role.b.name", "aws_iam_role.b"},
			"policy_arn": {"aws_iam_policy.s3.arn", "aws_iam_policy.s3"},
		}},
		"aws_iam_policy.s3": {},
	}}
	for _, role := range []string{"aws_iam_role.a", "aws_iam_role.b"} {
		docs, unknown, _ := roleDocuments("", []string{role}, resources, nil, idx)
		if unknown {
			t.Fatalf("%s: unexpected unknown", role)
		}
		if len(docs) != 1 {
			t.Fatalf("%s: docs=%d want 1", role, len(docs))
		}
		_, grants, _, _, _, _ := bucketsFromDocs(docs, nil, resources, elements)
		if effectiveAuthzScope(grants) != "resource" {
			t.Fatalf("%s: scope=%q want resource grants=%v", role, effectiveAuthzScope(grants), grants)
		}
	}
}

func TestPolicyAttachmentRolesUnknownOmitsScope(t *testing.T) {
	// roles after_unknown with config refs → unknown for those roles (scope omitted).
	resources := []planResource{
		{address: "aws_iam_role.task", typ: "aws_iam_role"},
		{address: "aws_iam_policy.s3", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
		{
			address: "aws_iam_policy_attachment.dyn", typ: "aws_iam_policy_attachment",
			values:       map[string]any{},
			afterUnknown: map[string]any{"roles": true},
		},
	}
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_policy_attachment.dyn": {refs: map[string][]string{
			"roles":      {"aws_iam_role.task.name", "aws_iam_role.task"},
			"policy_arn": {"aws_iam_policy.s3.arn", "aws_iam_policy.s3"},
		}},
		"aws_iam_policy.s3": {},
	}}
	docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
	if !unknown {
		t.Fatal("unknown roles on policy_attachment must set unknown")
	}
	// Policy content is not applied while roles are unknown.
	if len(docs) != 0 {
		t.Fatalf("docs=%d want 0 while roles unknown", len(docs))
	}
}

func TestPolicyAttachmentRolesUnknownNoRefsMarksEveryRole(t *testing.T) {
	// roles after_unknown and no aws_iam_role refs → unknown for every queried role.
	resources := []planResource{
		{address: "aws_iam_role.task", typ: "aws_iam_role"},
		{address: "aws_iam_policy.s3", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
		{
			address: "aws_iam_policy_attachment.opaque", typ: "aws_iam_policy_attachment",
			values:       map[string]any{},
			afterUnknown: map[string]any{"roles": true},
		},
	}
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_policy_attachment.opaque": {refs: map[string][]string{
			"policy_arn": {"aws_iam_policy.s3.arn", "aws_iam_policy.s3"},
			// roles refs absent (e.g. var.role_names)
		}},
		"aws_iam_policy.s3": {},
	}}
	_, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
	if !unknown {
		t.Fatal("policy_attachment with unknown roles and no role refs must mark unknown")
	}
}

func TestRolePolicyAttachmentsExclusiveInPlanScope(t *testing.T) {
	bucketRes, elements := attachmentS3BucketFixture()
	resources := []planResource{
		{address: "aws_iam_role.task", typ: "aws_iam_role"},
		{address: "aws_iam_policy.narrow", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
		{address: "aws_iam_role_policy_attachments_exclusive.task", typ: "aws_iam_role_policy_attachments_exclusive", values: map[string]any{}},
	}
	resources = append(resources, bucketRes...)
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_role_policy_attachments_exclusive.task": {refs: map[string][]string{
			"role_name":   {"aws_iam_role.task.name", "aws_iam_role.task"},
			"policy_arns": {"aws_iam_policy.narrow.arn", "aws_iam_policy.narrow"},
		}},
		"aws_iam_policy.narrow": {},
	}}
	docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
	if unknown {
		t.Fatal("unexpected unknown")
	}
	if len(docs) != 1 {
		t.Fatalf("docs=%d want 1", len(docs))
	}
	_, grants, _, _, _, _ := bucketsFromDocs(docs, nil, resources, elements)
	if effectiveAuthzScope(grants) != "resource" {
		t.Fatalf("scope=%q want resource", effectiveAuthzScope(grants))
	}
}

func TestRolePolicyAttachmentsExclusiveUnknownExternalARNOmits(t *testing.T) {
	resources := []planResource{
		{address: "aws_iam_role.task", typ: "aws_iam_role"},
		{address: "aws_iam_role_policy_attachments_exclusive.task", typ: "aws_iam_role_policy_attachments_exclusive", values: map[string]any{}},
	}
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_role_policy_attachments_exclusive.task": {refs: map[string][]string{
			"role_name":   {"aws_iam_role.task.name", "aws_iam_role.task"},
			"policy_arns": {"aws_iam_policy.missing.arn", "aws_iam_policy.missing"},
		}},
	}}
	docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
	if !unknown {
		t.Fatal("missing in-plan policy ARN must set unknown")
	}
	if len(docs) != 0 {
		t.Fatalf("docs=%d want 0", len(docs))
	}
}

func TestRolePolicyAttachmentsExclusiveAfterUnknownARNOmits(t *testing.T) {
	resources := []planResource{
		{address: "aws_iam_role.task", typ: "aws_iam_role"},
		{
			address: "aws_iam_role_policy_attachments_exclusive.task", typ: "aws_iam_role_policy_attachments_exclusive",
			values:       map[string]any{},
			afterUnknown: map[string]any{"policy_arns": true},
		},
	}
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_role_policy_attachments_exclusive.task": {refs: map[string][]string{
			"role_name": {"aws_iam_role.task.name", "aws_iam_role.task"},
		}},
	}}
	_, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
	if !unknown {
		t.Fatal("after_unknown policy_arns with no constant must set unknown")
	}
}

func TestRolePoliciesExclusiveMissingInlineOmits(t *testing.T) {
	resources := []planResource{
		{address: "aws_iam_role.task", typ: "aws_iam_role"},
		{
			address: "aws_iam_role_policies_exclusive.task", typ: "aws_iam_role_policies_exclusive",
			values: map[string]any{"policy_names": []any{"missing-inline"}},
		},
	}
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_role_policies_exclusive.task": {refs: map[string][]string{
			"role_name": {"aws_iam_role.task.name", "aws_iam_role.task"},
		}, constants: map[string]any{
			"policy_names": []any{"missing-inline"},
		}},
	}}
	docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
	if !unknown {
		t.Fatal("exclusive name with no matching inline policy must set unknown")
	}
	if len(docs) != 0 {
		t.Fatalf("docs=%d want 0", len(docs))
	}
}

func TestRolePoliciesExclusiveMatchingInlineCounts(t *testing.T) {
	resources := []planResource{
		{address: "aws_iam_role.task", typ: "aws_iam_role"},
		{
			address: "aws_iam_role_policy.extra", typ: "aws_iam_role_policy",
			values: map[string]any{"name": "extra", "policy": s3PutJSON},
		},
		{
			address: "aws_iam_role_policies_exclusive.task", typ: "aws_iam_role_policies_exclusive",
			values: map[string]any{"policy_names": []any{"extra"}},
		},
	}
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_role_policy.extra": {refs: map[string][]string{
			"role": {"aws_iam_role.task.name", "aws_iam_role.task"},
		}},
		"aws_iam_role_policies_exclusive.task": {refs: map[string][]string{
			"role_name": {"aws_iam_role.task.name", "aws_iam_role.task"},
		}, constants: map[string]any{
			"policy_names": []any{"extra"},
		}},
	}}
	docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
	if unknown {
		t.Fatal("unexpected unknown")
	}
	// aws_iam_role_policy.extra is also collected by the role_policy loop; uniqueResources.
	found := false
	for _, d := range docs {
		if strings.Contains(d.address, "aws_iam_role_policy.extra") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected inline policy doc, got %v", docAddrs(docs))
	}
}

func TestPolicyAttachmentIgnoresUsersAndGroups(t *testing.T) {
	// users/groups on the attachment must not affect role document collection.
	resources := []planResource{
		{address: "aws_iam_role.task", typ: "aws_iam_role"},
		{address: "aws_iam_policy.s3", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
		{address: "aws_iam_policy_attachment.ug", typ: "aws_iam_policy_attachment", values: map[string]any{
			"users":  []any{"alice"},
			"groups": []any{"devs"},
		}},
	}
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_policy_attachment.ug": {refs: map[string][]string{
			// no roles=
			"policy_arn": {"aws_iam_policy.s3.arn", "aws_iam_policy.s3"},
			"users":      {"aws_iam_user.alice"},
			"groups":     {"aws_iam_group.devs"},
		}},
		"aws_iam_policy.s3": {},
	}}
	docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
	if unknown {
		t.Fatal("users/groups-only attachment must not mark role unknown")
	}
	if len(docs) != 0 {
		t.Fatalf("docs=%d want 0 (no roles=)", len(docs))
	}
}

// Literal IAM role name matching (string constants, not aws_iam_role refs).
//
// Cases per attachment-like resource:
//   match   — literal equals a queried role's known plan name → policy attaches
//   nomatch — literal matches no role in the plan → ignored (external)
//   unkname — queried role name unknown + literal present → unknown (scope omitted)

func TestLiteralRoleName_RolePolicyAttachment(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		bucketRes, elements := attachmentS3BucketFixture()
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "app-task"}},
			{address: "aws_iam_policy.s3", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
			{
				address: "aws_iam_role_policy_attachment.lit", typ: "aws_iam_role_policy_attachment",
				values: map[string]any{"role": "app-task"},
			},
		}
		resources = append(resources, bucketRes...)
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task": {},
			"aws_iam_role_policy_attachment.lit": {constants: map[string]any{"role": "app-task"}, refs: map[string][]string{
				"policy_arn": {"aws_iam_policy.s3.arn", "aws_iam_policy.s3"},
			}},
			"aws_iam_policy.s3": {},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if unknown {
			t.Fatal("unexpected unknown")
		}
		if len(docs) != 1 {
			t.Fatalf("docs=%d want 1", len(docs))
		}
		_, grants, _, _, _, _ := bucketsFromDocs(docs, nil, resources, elements)
		if effectiveAuthzScope(grants) != "resource" {
			t.Fatalf("scope=%q want resource", effectiveAuthzScope(grants))
		}
	})
	t.Run("nomatch", func(t *testing.T) {
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "app-task"}},
			{address: "aws_iam_policy.s3", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
			{
				address: "aws_iam_role_policy_attachment.ext", typ: "aws_iam_role_policy_attachment",
				values: map[string]any{"role": "someone-else"},
			},
		}
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task": {},
			"aws_iam_role_policy_attachment.ext": {constants: map[string]any{"role": "someone-else"}, refs: map[string][]string{
				"policy_arn": {"aws_iam_policy.s3.arn", "aws_iam_policy.s3"},
			}},
			"aws_iam_policy.s3": {},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if unknown {
			t.Fatal("external literal must not mark unknown")
		}
		if len(docs) != 0 {
			t.Fatalf("docs=%d want 0 (external role)", len(docs))
		}
	})
	t.Run("unkname", func(t *testing.T) {
		resources := []planResource{
			{
				address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{},
				afterUnknown: map[string]any{"name": true},
			},
			{address: "aws_iam_policy.s3", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
			{
				address: "aws_iam_role_policy_attachment.lit", typ: "aws_iam_role_policy_attachment",
				values: map[string]any{"role": "maybe-task"},
			},
		}
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task": {raw: map[string]any{"name_prefix": map[string]any{"constant_value": "task-"}}},
			"aws_iam_role_policy_attachment.lit": {constants: map[string]any{"role": "maybe-task"}, refs: map[string][]string{
				"policy_arn": {"aws_iam_policy.s3.arn", "aws_iam_policy.s3"},
			}},
			"aws_iam_policy.s3": {},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if !unknown {
			t.Fatal("literal with unknown role name must set unknown")
		}
		if len(docs) != 0 {
			t.Fatalf("docs=%d want 0 (scope omitted)", len(docs))
		}
	})
}

func TestLiteralRoleName_PolicyAttachment(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		bucketRes, elements := attachmentS3BucketFixture()
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "app-task"}},
			{address: "aws_iam_policy.s3", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
			{
				address: "aws_iam_policy_attachment.lit", typ: "aws_iam_policy_attachment",
				values: map[string]any{"roles": []any{"app-task"}},
			},
		}
		resources = append(resources, bucketRes...)
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task": {},
			"aws_iam_policy_attachment.lit": {constants: map[string]any{"roles": []any{"app-task"}}, refs: map[string][]string{
				"policy_arn": {"aws_iam_policy.s3.arn", "aws_iam_policy.s3"},
			}},
			"aws_iam_policy.s3": {},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if unknown || len(docs) != 1 {
			t.Fatalf("unknown=%v docs=%d", unknown, len(docs))
		}
		_, grants, _, _, _, _ := bucketsFromDocs(docs, nil, resources, elements)
		if effectiveAuthzScope(grants) != "resource" {
			t.Fatalf("scope=%q", effectiveAuthzScope(grants))
		}
	})
	t.Run("nomatch", func(t *testing.T) {
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "app-task"}},
			{address: "aws_iam_policy.s3", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
			{
				address: "aws_iam_policy_attachment.ext", typ: "aws_iam_policy_attachment",
				values: map[string]any{"roles": []any{"external-role"}},
			},
		}
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task": {},
			"aws_iam_policy_attachment.ext": {constants: map[string]any{"roles": []any{"external-role"}}, refs: map[string][]string{
				"policy_arn": {"aws_iam_policy.s3.arn", "aws_iam_policy.s3"},
			}},
			"aws_iam_policy.s3": {},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if unknown || len(docs) != 0 {
			t.Fatalf("unknown=%v docs=%d want ignore", unknown, len(docs))
		}
	})
	t.Run("unkname", func(t *testing.T) {
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{}},
			{address: "aws_iam_policy.s3", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
			{
				address: "aws_iam_policy_attachment.lit", typ: "aws_iam_policy_attachment",
				values: map[string]any{"roles": []any{"maybe-task"}},
			},
		}
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task": {raw: map[string]any{"name_prefix": map[string]any{"constant_value": "task-"}}},
			"aws_iam_policy_attachment.lit": {constants: map[string]any{"roles": []any{"maybe-task"}}, refs: map[string][]string{
				"policy_arn": {"aws_iam_policy.s3.arn", "aws_iam_policy.s3"},
			}},
			"aws_iam_policy.s3": {},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if !unknown || len(docs) != 0 {
			t.Fatalf("unknown=%v docs=%d want unknown omit", unknown, len(docs))
		}
	})
}

func TestLiteralRoleName_RolePolicy(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		bucketRes, elements := attachmentS3BucketFixture()
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "app-task"}},
			{
				address: "aws_iam_role_policy.lit", typ: "aws_iam_role_policy",
				values: map[string]any{"role": "app-task", "policy": s3PutJSON},
			},
		}
		resources = append(resources, bucketRes...)
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task":       {},
			"aws_iam_role_policy.lit": {constants: map[string]any{"role": "app-task"}},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if unknown || len(docs) != 1 {
			t.Fatalf("unknown=%v docs=%d", unknown, len(docs))
		}
		_, grants, _, _, _, _ := bucketsFromDocs(docs, nil, resources, elements)
		if effectiveAuthzScope(grants) != "resource" {
			t.Fatalf("scope=%q", effectiveAuthzScope(grants))
		}
	})
	t.Run("nomatch", func(t *testing.T) {
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "app-task"}},
			{
				address: "aws_iam_role_policy.ext", typ: "aws_iam_role_policy",
				values: map[string]any{"role": "other-role", "policy": s3PutJSON},
			},
		}
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task":       {},
			"aws_iam_role_policy.ext": {constants: map[string]any{"role": "other-role"}},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if unknown || len(docs) != 0 {
			t.Fatalf("unknown=%v docs=%d", unknown, len(docs))
		}
	})
	t.Run("unkname", func(t *testing.T) {
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{}},
			{
				address: "aws_iam_role_policy.lit", typ: "aws_iam_role_policy",
				values: map[string]any{"role": "maybe-task", "policy": s3PutJSON},
			},
		}
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task":       {raw: map[string]any{"name_prefix": map[string]any{"constant_value": "task-"}}},
			"aws_iam_role_policy.lit": {constants: map[string]any{"role": "maybe-task"}},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if !unknown || len(docs) != 0 {
			t.Fatalf("unknown=%v docs=%d", unknown, len(docs))
		}
	})
}

func TestLiteralRoleName_AttachmentsExclusive(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		bucketRes, elements := attachmentS3BucketFixture()
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "app-task"}},
			{address: "aws_iam_policy.s3", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
			{
				address: "aws_iam_role_policy_attachments_exclusive.lit", typ: "aws_iam_role_policy_attachments_exclusive",
				values: map[string]any{"role_name": "app-task"},
			},
		}
		resources = append(resources, bucketRes...)
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task": {},
			"aws_iam_role_policy_attachments_exclusive.lit": {
				constants: map[string]any{"role_name": "app-task"},
				refs:      map[string][]string{"policy_arns": {"aws_iam_policy.s3.arn", "aws_iam_policy.s3"}},
			},
			"aws_iam_policy.s3": {},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if unknown || len(docs) != 1 {
			t.Fatalf("unknown=%v docs=%d", unknown, len(docs))
		}
		_, grants, _, _, _, _ := bucketsFromDocs(docs, nil, resources, elements)
		if effectiveAuthzScope(grants) != "resource" {
			t.Fatalf("scope=%q", effectiveAuthzScope(grants))
		}
	})
	t.Run("nomatch", func(t *testing.T) {
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "app-task"}},
			{address: "aws_iam_policy.s3", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
			{
				address: "aws_iam_role_policy_attachments_exclusive.ext", typ: "aws_iam_role_policy_attachments_exclusive",
				values: map[string]any{"role_name": "external"},
			},
		}
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task": {},
			"aws_iam_role_policy_attachments_exclusive.ext": {
				constants: map[string]any{"role_name": "external"},
				refs:      map[string][]string{"policy_arns": {"aws_iam_policy.s3.arn", "aws_iam_policy.s3"}},
			},
			"aws_iam_policy.s3": {},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if unknown || len(docs) != 0 {
			t.Fatalf("unknown=%v docs=%d", unknown, len(docs))
		}
	})
	t.Run("unkname", func(t *testing.T) {
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{}},
			{address: "aws_iam_policy.s3", typ: "aws_iam_policy", values: map[string]any{"policy": s3PutJSON}},
			{
				address: "aws_iam_role_policy_attachments_exclusive.lit", typ: "aws_iam_role_policy_attachments_exclusive",
				values: map[string]any{"role_name": "maybe"},
			},
		}
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task": {raw: map[string]any{"name_prefix": map[string]any{"constant_value": "t-"}}},
			"aws_iam_role_policy_attachments_exclusive.lit": {
				constants: map[string]any{"role_name": "maybe"},
				refs:      map[string][]string{"policy_arns": {"aws_iam_policy.s3.arn", "aws_iam_policy.s3"}},
			},
			"aws_iam_policy.s3": {},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if !unknown || len(docs) != 0 {
			t.Fatalf("unknown=%v docs=%d", unknown, len(docs))
		}
	})
}

func TestLiteralRoleName_PoliciesExclusive(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		bucketRes, elements := attachmentS3BucketFixture()
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "app-task"}},
			{
				address: "aws_iam_role_policy.extra", typ: "aws_iam_role_policy",
				values: map[string]any{"name": "extra", "role": "app-task", "policy": s3PutJSON},
			},
			{
				address: "aws_iam_role_policies_exclusive.lit", typ: "aws_iam_role_policies_exclusive",
				values: map[string]any{"role_name": "app-task", "policy_names": []any{"extra"}},
			},
		}
		resources = append(resources, bucketRes...)
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task":         {},
			"aws_iam_role_policy.extra": {constants: map[string]any{"role": "app-task", "name": "extra"}},
			"aws_iam_role_policies_exclusive.lit": {constants: map[string]any{
				"role_name": "app-task", "policy_names": []any{"extra"},
			}},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if unknown || len(docs) == 0 {
			t.Fatalf("unknown=%v docs=%d", unknown, len(docs))
		}
		_, grants, _, _, _, _ := bucketsFromDocs(docs, nil, resources, elements)
		if effectiveAuthzScope(grants) != "resource" {
			t.Fatalf("scope=%q", effectiveAuthzScope(grants))
		}
	})
	t.Run("nomatch", func(t *testing.T) {
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "app-task"}},
			{
				address: "aws_iam_role_policies_exclusive.ext", typ: "aws_iam_role_policies_exclusive",
				values: map[string]any{"role_name": "external", "policy_names": []any{"extra"}},
			},
		}
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task": {},
			"aws_iam_role_policies_exclusive.ext": {constants: map[string]any{
				"role_name": "external", "policy_names": []any{"extra"},
			}},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if unknown || len(docs) != 0 {
			t.Fatalf("unknown=%v docs=%d want ignore external", unknown, len(docs))
		}
	})
	t.Run("unkname", func(t *testing.T) {
		resources := []planResource{
			{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{}},
			{
				address: "aws_iam_role_policies_exclusive.lit", typ: "aws_iam_role_policies_exclusive",
				values: map[string]any{"role_name": "maybe", "policy_names": []any{"extra"}},
			},
		}
		idx := configIndex{resources: map[string]exprSet{
			"aws_iam_role.task": {raw: map[string]any{"name_prefix": map[string]any{"constant_value": "t-"}}},
			"aws_iam_role_policies_exclusive.lit": {constants: map[string]any{
				"role_name": "maybe", "policy_names": []any{"extra"},
			}},
		}}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, idx)
		if !unknown || len(docs) != 0 {
			t.Fatalf("unknown=%v docs=%d", unknown, len(docs))
		}
	})
}
