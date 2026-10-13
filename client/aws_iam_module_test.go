package client

import (
	"testing"
)

func TestSameModuleRoot(t *testing.T) {
	cases := []struct {
		addr, module string
		want         bool
	}{
		{"aws_iam_role_policy_attachment.x", "", true},
		{"data.aws_iam_policy_document.x", "", true},
		{"aws_iam_policy.x", "", true},
		{"module.app.aws_iam_role_policy_attachment.x", "", false},
		{"module.app.aws_iam_role_policy_attachment.x", "module.app", true},
		{"module.app.data.aws_iam_policy_document.x", "module.app", true},
		// Named modules keep prefix match so nested module.x.module.y.… is included.
		{"module.ecs.module.iam.aws_iam_policy.x", "module.ecs", true},
		{"module.ecs.module.iam.data.aws_iam_policy_document.x", "module.ecs", true},
		{"module.other.aws_iam_policy.x", "module.ecs", false},
	}
	for _, tc := range cases {
		if got := sameModule(tc.addr, tc.module); got != tc.want {
			t.Fatalf("sameModule(%q, %q)=%v want %v", tc.addr, tc.module, got, tc.want)
		}
	}
}

// TestRootModuleRoleDocuments pins the sameModule fix in roleDocuments.
//
// Before: HasPrefix(address, module+".") with module=="" required a leading ".",
// so root addresses like aws_iam_role_policy_attachment.x never matched and
// roleDocuments returned no docs. Secrets/S3 authz_scope was omitted on any
// root-module layout (module-scoped layouts such as aws-web-app were fine).
//
// After: sameModule("", rootAddr) is true, so root IAM attachments are visible.
// Inputs that change: any root-module plan where roleDocuments is consulted
// (ECS secrets via execution role, S3 via task role, Bedrock via task/Lambda
// role). Module-prefixed layouts are unchanged.
func TestRootModuleRoleDocuments(t *testing.T) {
	resources := []planResource{
		{address: "aws_iam_role.task", typ: "aws_iam_role"},
		{address: "aws_iam_role_policy_attachment.bedrock", typ: "aws_iam_role_policy_attachment"},
		{address: "aws_iam_policy.bedrock", typ: "aws_iam_policy"},
	}
	data := []planResource{
		{
			address: "data.aws_iam_policy_document.bedrock",
			typ:     "aws_iam_policy_document",
			values: map[string]any{
				"statement": []any{map[string]any{
					"effect":    "Allow",
					"actions":   []any{"bedrock:InvokeModel"},
					"resources": []any{"*"},
				}},
			},
		},
	}
	idx := configIndex{resources: map[string]exprSet{
		"aws_iam_role_policy_attachment.bedrock": {
			refs: map[string][]string{
				"role":       {"aws_iam_role.task.name", "aws_iam_role.task"},
				"policy_arn": {"aws_iam_policy.bedrock.arn", "aws_iam_policy.bedrock"},
			},
		},
		"aws_iam_policy.bedrock": {
			refs: map[string][]string{
				"policy": {"data.aws_iam_policy_document.bedrock.json", "data.aws_iam_policy_document.bedrock"},
			},
		},
	}}
	docs := roleDocuments("", []string{"aws_iam_role.task.arn", "aws_iam_role.task"}, resources, data, idx)
	if len(docs) != 1 {
		t.Fatalf("roleDocuments root docs=%d want 1 (sameModule must match root addresses)", len(docs))
	}
	if docs[0].address != "data.aws_iam_policy_document.bedrock" {
		t.Fatalf("doc=%q", docs[0].address)
	}
}

// TestRoleDocumentsNestedModule pins prefix match for named modules: role and
// attachment in module.ecs, policy + document in module.ecs.module.iam.
func TestRoleDocumentsNestedModule(t *testing.T) {
	const mod = "module.ecs"
	role := mod + ".aws_iam_role.task"
	att := mod + ".aws_iam_role_policy_attachment.bedrock"
	pol := mod + ".module.iam.aws_iam_policy.bedrock"
	doc := mod + ".module.iam.data.aws_iam_policy_document.bedrock"

	resources := []planResource{
		{address: role, typ: "aws_iam_role"},
		{address: att, typ: "aws_iam_role_policy_attachment"},
		{address: pol, typ: "aws_iam_policy"},
	}
	data := []planResource{
		{
			address: doc,
			typ:     "aws_iam_policy_document",
			values: map[string]any{
				"statement": []any{map[string]any{
					"effect":    "Allow",
					"actions":   []any{"bedrock:InvokeModel"},
					"resources": []any{"*"},
				}},
			},
		},
	}
	idx := configIndex{resources: map[string]exprSet{
		att: {
			refs: map[string][]string{
				"role":       {role + ".name", role},
				"policy_arn": {pol + ".arn", pol},
			},
		},
		pol: {
			refs: map[string][]string{
				"policy": {doc + ".json", doc},
			},
		},
	}}
	docs := roleDocuments(mod, []string{role + ".arn", role}, resources, data, idx)
	if len(docs) != 1 {
		t.Fatalf("roleDocuments nested docs=%d want 1", len(docs))
	}
	if docs[0].address != doc {
		t.Fatalf("doc=%q want %q", docs[0].address, doc)
	}
}
