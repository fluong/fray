package client

import (
	"encoding/json"
	"strings"
	"testing"
)

const unmanagedCustomerPolicyARN = "arn:aws:iam::123456789012:policy/app-db"

// iamRoleChange is an aws_iam_role whose name is known but name_prefix is
// after_unknown, matching the AWS provider plan shape (optional name_prefix
// stays unknown when name is set).
func iamRoleChange(local, name string) map[string]any {
	return map[string]any{
		"address": "aws_iam_role." + local, "mode": "managed", "type": "aws_iam_role", "name": local,
		"change": map[string]any{
			"actions": []any{"create"},
			"after":   map[string]any{"name": name},
			"after_unknown": map[string]any{
				"name_prefix": true, "inline_policy": true, "managed_policy_arns": true,
			},
		},
	}
}

func s3InlinePolicy(bucket string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::` + bucket + `/*"]},{"Effect":"Allow","Action":["bedrock:InvokeModel"],"Resource":["arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"]}]}`
}

// twoServiceIAMPlan is service A (inline resource-scoped S3 + Bedrock) and
// service B (only a customer-managed policy ARN attachment, policy not in the plan).
// withBothOnB adds A's inline policy onto B as well as the unresolvable attachment.
func twoServiceIAMPlan(t *testing.T, withBothOnB bool) string {
	t.Helper()
	return twoServiceIAMPlanManaged(t, withBothOnB, "")
}

func twoServiceIAMPlanManaged(t *testing.T, withBothOnB bool, roleAManagedARN string) string {
	t.Helper()
	polA := s3InlinePolicy("bucket-a")
	resources := []map[string]any{
		iamRoleChange("a", "role-a"),
		iamRoleChange("b", "role-b"),
		{
			"address": "aws_s3_bucket.bucket_a", "mode": "managed", "type": "aws_s3_bucket", "name": "bucket_a",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"bucket": "bucket-a", "arn": "arn:aws:s3:::bucket-a",
			}},
		},
		{
			"address": "aws_iam_role_policy.a_s3", "mode": "managed", "type": "aws_iam_role_policy", "name": "a_s3",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"name": "a-s3", "policy": polA, "role": "role-a",
			}},
		},
		{
			"address": "aws_iam_role_policy_attachment.b_managed", "mode": "managed", "type": "aws_iam_role_policy_attachment", "name": "b_managed",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"role": "role-b", "policy_arn": unmanagedCustomerPolicyARN,
			}},
		},
		ecsTask("a", "a"),
		ecsTask("b", "b"),
		ecsService("a"),
		ecsService("b"),
		{
			"address": "aws_lambda_function.pinned", "mode": "managed", "type": "aws_lambda_function", "name": "pinned",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"function_name": "pinned", "handler": "index.handler", "runtime": "nodejs20.x",
			}},
		},
	}
	cfg := []map[string]any{
		{"address": "aws_iam_role.a", "type": "aws_iam_role", "name": "a", "expressions": map[string]any{}},
		{"address": "aws_iam_role.b", "type": "aws_iam_role", "name": "b", "expressions": map[string]any{}},
		{"address": "aws_s3_bucket.bucket_a", "type": "aws_s3_bucket", "name": "bucket_a", "expressions": map[string]any{}},
		{"address": "aws_iam_role_policy.a_s3", "type": "aws_iam_role_policy", "name": "a_s3", "expressions": map[string]any{
			"role":   map[string]any{"references": []any{"aws_iam_role.a.name", "aws_iam_role.a"}},
			"policy": map[string]any{"constant_value": polA},
		}},
		{"address": "aws_iam_role_policy_attachment.b_managed", "type": "aws_iam_role_policy_attachment", "name": "b_managed", "expressions": map[string]any{
			"role":       map[string]any{"references": []any{"aws_iam_role.b.name", "aws_iam_role.b"}},
			"policy_arn": map[string]any{"constant_value": unmanagedCustomerPolicyARN},
		}},
	}
	if roleAManagedARN != "" {
		resources = append(resources, map[string]any{
			"address": "aws_iam_role_policy_attachment.a_managed", "mode": "managed", "type": "aws_iam_role_policy_attachment", "name": "a_managed",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"role": "role-a", "policy_arn": roleAManagedARN,
			}},
		})
		cfg = append(cfg, map[string]any{
			"address": "aws_iam_role_policy_attachment.a_managed", "type": "aws_iam_role_policy_attachment", "name": "a_managed",
			"expressions": map[string]any{
				"role":       map[string]any{"references": []any{"aws_iam_role.a.name", "aws_iam_role.a"}},
				"policy_arn": map[string]any{"constant_value": roleAManagedARN},
			},
		})
	}
	cfg = append(cfg,
		ecsTaskCfg("a", "a"),
		ecsTaskCfg("b", "b"),
		ecsServiceCfg("a"),
		ecsServiceCfg("b"),
		map[string]any{"address": "aws_lambda_function.pinned", "type": "aws_lambda_function", "name": "pinned", "expressions": map[string]any{
			"role": map[string]any{"references": []any{"aws_iam_role.a.arn", "aws_iam_role.a"}},
		}},
	)
	if withBothOnB {
		polB := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::bucket-a/*"]}]}`
		resources = append(resources, map[string]any{
			"address": "aws_iam_role_policy.b_s3", "mode": "managed", "type": "aws_iam_role_policy", "name": "b_s3",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"name": "b-s3", "policy": polB, "role": "role-b",
			}},
		})
		cfg = append(cfg, map[string]any{
			"address": "aws_iam_role_policy.b_s3", "type": "aws_iam_role_policy", "name": "b_s3", "expressions": map[string]any{
				"role":   map[string]any{"references": []any{"aws_iam_role.b.name", "aws_iam_role.b"}},
				"policy": map[string]any{"constant_value": polB},
			},
		})
	}
	raw, err := json.Marshal(map[string]any{
		"format_version":   "1.2",
		"resource_changes": resources,
		"configuration":    map[string]any{"root_module": map[string]any{"resources": cfg}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func ecsTask(local, role string) map[string]any {
	return map[string]any{
		"address": "aws_ecs_task_definition." + local, "mode": "managed", "type": "aws_ecs_task_definition", "name": local,
		"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
			"family": local, "container_definitions": `[{"name":"app","image":"app:1"}]`,
		}, "after_unknown": map[string]any{"task_role_arn": true}},
	}
}

func ecsService(local string) map[string]any {
	return map[string]any{
		"address": "aws_ecs_service." + local, "mode": "managed", "type": "aws_ecs_service", "name": local,
		"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": local}},
	}
}

func ecsTaskCfg(local, role string) map[string]any {
	return map[string]any{
		"address": "aws_ecs_task_definition." + local, "type": "aws_ecs_task_definition", "name": local,
		"expressions": map[string]any{
			"task_role_arn": map[string]any{"references": []any{
				"aws_iam_role." + role + ".arn", "aws_iam_role." + role,
			}},
		},
	}
}

func ecsServiceCfg(local string) map[string]any {
	return map[string]any{
		"address": "aws_ecs_service." + local, "type": "aws_ecs_service", "name": local,
		"expressions": map[string]any{
			"task_definition": map[string]any{"references": []any{
				"aws_ecs_task_definition." + local + ".arn",
				"aws_ecs_task_definition." + local,
			}},
		},
	}
}

func parseIAMPlan(t *testing.T, plan string) (DFD, []string) {
	t.Helper()
	doc, warnings, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "t/iam", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return doc, warnings
}

func flowScopeByService(t *testing.T, doc DFD, svcAddr string) (scope string, ok bool) {
	t.Helper()
	var svcID string
	for _, el := range doc.Elements {
		if len(el.Evidence.Addresses) == 1 && el.Evidence.Addresses[0] == svcAddr {
			svcID = el.ID
		}
	}
	if svcID == "" {
		t.Fatalf("missing element %s", svcAddr)
	}
	for _, f := range doc.Flows {
		if f.From == svcID {
			return f.AuthzScope, true
		}
	}
	return "", false
}

func hasBedrockSignal(doc DFD) bool {
	for _, el := range doc.Elements {
		if el.Kind != "llm_api" {
			continue
		}
		for _, s := range el.Evidence.Signals {
			if s.Type == "iam_service" && s.Name == "bedrock" {
				return true
			}
		}
	}
	return false
}

func TestUnresolvedManagedPolicyDoesNotDropOtherRoles(t *testing.T) {
	doc, _ := parseIAMPlan(t, twoServiceIAMPlan(t, false))
	scopeA, okA := flowScopeByService(t, doc, "aws_ecs_service.a")
	if !okA || scopeA != "resource" {
		t.Fatalf("service A scope=%q present=%v; want resource (plan-wide drop)", scopeA, okA)
	}
	if !hasBedrockSignal(doc) {
		t.Fatal("signal:iam_service:bedrock missing")
	}
	scopeB, okB := flowScopeByService(t, doc, "aws_ecs_service.b")
	if okB && scopeB != "" {
		t.Fatalf("service B scope=%q; unresolvable managed policy must not set authz_scope", scopeB)
	}
}

func TestInlinePlusUnresolvedManagedOmitsScope(t *testing.T) {
	doc, warnings := parseIAMPlan(t, twoServiceIAMPlan(t, true))
	scopeB, okB := flowScopeByService(t, doc, "aws_ecs_service.b")
	if !okB {
		t.Fatal("service B flow missing; known inline grant should still emit the flow")
	}
	if scopeB != "" {
		t.Fatalf("service B scope=%q; unknown managed policy must not claim resource", scopeB)
	}
	joined := strings.Join(warnings, "\n")
	const want = "authz_scope omitted for aws_iam_role.b: aws_iam_role_policy_attachment.b_managed policy_arn is not an in-plan policy"
	if !strings.Contains(joined, want) {
		t.Fatalf("warnings missing %q:\n%s", want, joined)
	}
	// Role A is unchanged.
	scopeA, okA := flowScopeByService(t, doc, "aws_ecs_service.a")
	if !okA || scopeA != "resource" {
		t.Fatalf("service A scope=%q present=%v", scopeA, okA)
	}
}

func TestCoverageShapeKeepsBedrockAndS3Scopes(t *testing.T) {
	// Same trigger as coverage: a third role's .name is a known string on a
	// customer-managed attachment, while every role has after_unknown name_prefix.
	doc, _ := parseIAMPlan(t, twoServiceIAMPlan(t, false))
	scopeA, okA := flowScopeByService(t, doc, "aws_ecs_service.a")
	if !okA || scopeA != "resource" {
		t.Fatalf("S3 authz_scope=%q present=%v; want resource", scopeA, okA)
	}
	if !hasBedrockSignal(doc) {
		t.Fatal("signal:iam_service:bedrock dropped")
	}
	for _, f := range doc.Flows {
		for _, el := range doc.Elements {
			if el.ID == f.To && el.Kind == "llm_api" && f.AuthzScope != "resource" {
				t.Fatalf("bedrock flow scope=%q want resource", f.AuthzScope)
			}
		}
	}
}

func TestFillAuthzScopeOnUnresolvedManagedPolicy(t *testing.T) {
	cfg := []byte(`schema_version: fray-config/v1
annotations:
  flows:
    - from: aws_ecs_service.b
      to: aws_s3_bucket.bucket_a
      authz_scope: account
      reason: "managed policy grants s3 on the bucket (reviewed)"
`)
	doc, warnings, err := Parse([]byte(twoServiceIAMPlan(t, true)), cfg, "fray.yaml",
		Source{Repo: "t/iam", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	scopeA, okA := flowScopeByService(t, doc, "aws_ecs_service.a")
	if !okA || scopeA != "resource" {
		t.Fatalf("service A scope=%q present=%v; fill must not change derived scope", scopeA, okA)
	}
	scopeB, okB := flowScopeByService(t, doc, "aws_ecs_service.b")
	if !okB || scopeB != "account" {
		t.Fatalf("service B scope=%q present=%v; want declared account", scopeB, okB)
	}
	for _, w := range warnings {
		if strings.Contains(w, "aws_ecs_service.a") {
			t.Fatalf("unexpected warning for A: %s", w)
		}
		if strings.Contains(w, "authz_scope omitted for aws_iam_role.b") {
			t.Fatalf("filled role must drop the omit warning: %s", w)
		}
	}
}

func TestAWSManagedPolicyAllowlist(t *testing.T) {
	const s3Full = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
	const exec = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"

	doc, warnings := parseIAMPlan(t, twoServiceIAMPlanManaged(t, false, s3Full))
	scopeA, okA := flowScopeByService(t, doc, "aws_ecs_service.a")
	if !okA || scopeA != "account" {
		t.Fatalf("AmazonS3FullAccess scope=%q present=%v; want account", scopeA, okA)
	}
	for _, w := range warnings {
		if strings.Contains(w, "aws_iam_role_policy_attachment.a_managed") {
			t.Fatalf("known-wide S3 policy must not warn: %s", w)
		}
	}

	doc, warnings = parseIAMPlan(t, twoServiceIAMPlanManaged(t, false, exec))
	scopeA, okA = flowScopeByService(t, doc, "aws_ecs_service.a")
	if !okA || scopeA != "resource" {
		t.Fatalf("ECS execution policy scope=%q present=%v; want resource", scopeA, okA)
	}
	for _, w := range warnings {
		if strings.Contains(w, "authz_scope omitted for aws_iam_role.a") {
			t.Fatalf("allowlisted execution policy must not warn: %s", w)
		}
	}
}

func TestOmittedScopeWarningDroppedOnlyWhenAllFlowsFilled(t *testing.T) {
	const hint = "; declare it with fray.yaml annotations.flows authz_scope"
	plan := sharedRoleWidePlan(t)
	one := []byte(`schema_version: fray-config/v1
annotations:
  flows:
    - from: aws_ecs_service.a
      to: aws_s3_bucket.bucket_a
      authz_scope: account
      reason: "managed policy reviewed for this service"
`)
	doc, warnings, err := Parse([]byte(plan), one, "fray.yaml",
		Source{Repo: "t/iam", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if scope, ok := flowScopeByService(t, doc, "aws_ecs_service.a"); !ok || scope != "account" {
		t.Fatalf("filled service scope=%q present=%v", scope, ok)
	}
	if scope, ok := flowScopeByService(t, doc, "aws_ecs_service.c"); !ok || scope != "" {
		t.Fatalf("unfilled service scope=%q present=%v", scope, ok)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "authz_scope omitted for aws_iam_role.a:") || !strings.Contains(joined, hint) {
		t.Fatalf("partial fill must keep the omit warning with the declare hint:\n%s", joined)
	}

	both := []byte(`schema_version: fray-config/v1
annotations:
  flows:
    - from: aws_ecs_service.a
      to: aws_s3_bucket.bucket_a
      authz_scope: account
      reason: "managed policy reviewed for this service"
    - from: aws_ecs_service.c
      to: aws_s3_bucket.bucket_a
      authz_scope: account
      reason: "managed policy reviewed for the other service"
`)
	_, warnings, err = Parse([]byte(plan), both, "fray.yaml",
		Source{Repo: "t/iam", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "authz_scope omitted for aws_iam_role.a") {
			t.Fatalf("all flows filled; warning must be dropped: %s", w)
		}
	}
}

func TestRoleKnownIAMNameWithUnknownNamePrefix(t *testing.T) {
	role := planResource{
		address:      "aws_iam_role.task",
		typ:          "aws_iam_role",
		values:       map[string]any{"name": "fray-coverage-ecs-task"},
		afterUnknown: map[string]any{"name_prefix": true},
	}
	got, ok := roleKnownIAMName(role, configIndex{})
	if !ok || got != "fray-coverage-ecs-task" {
		t.Fatalf("name=%q ok=%v", got, ok)
	}
}

func TestKnownWideBedrockPlusUnreadCustomer(t *testing.T) {
	const bedrockFull = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
	plan := roleABedrockFullPlusCustomerPlan(t, bedrockFull)
	doc, warnings := parseIAMPlan(t, plan)
	scopeA, okA := flowScopeByService(t, doc, "aws_ecs_service.a")
	if !okA || scopeA != "" {
		t.Fatalf("S3 scope=%q present=%v; unread customer must omit S3 authz_scope", scopeA, okA)
	}
	if !hasBedrockSignal(doc) {
		t.Fatal("bedrock signal missing")
	}
	for _, f := range doc.Flows {
		for _, el := range doc.Elements {
			if el.ID == f.To && el.Kind == "llm_api" && f.AuthzScope != "account" {
				t.Fatalf("bedrock flow scope=%q want account", f.AuthzScope)
			}
		}
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "authz_scope omitted for aws_iam_role.a:") {
		t.Fatalf("missing omit warning for S3:\n%s", joined)
	}
	if strings.Contains(joined, bedrockFull) {
		t.Fatalf("known-wide bedrock attachment must not warn:\n%s", joined)
	}
}

func roleABedrockFullPlusCustomerPlan(t *testing.T, bedrockFullARN string) string {
	t.Helper()
	pol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::bucket-a/*"]}]}`
	resources := []map[string]any{
		iamRoleChange("a", "role-a"),
		{
			"address": "aws_s3_bucket.bucket_a", "mode": "managed", "type": "aws_s3_bucket", "name": "bucket_a",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"bucket": "bucket-a", "arn": "arn:aws:s3:::bucket-a",
			}},
		},
		{
			"address": "aws_iam_role_policy.a_s3", "mode": "managed", "type": "aws_iam_role_policy", "name": "a_s3",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"name": "a-s3", "policy": pol, "role": "role-a",
			}},
		},
		{
			"address": "aws_iam_role_policy_attachment.a_bedrock", "mode": "managed", "type": "aws_iam_role_policy_attachment", "name": "a_bedrock",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"role": "role-a", "policy_arn": bedrockFullARN,
			}},
		},
		{
			"address": "aws_iam_role_policy_attachment.a_customer", "mode": "managed", "type": "aws_iam_role_policy_attachment", "name": "a_customer",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"role": "role-a", "policy_arn": unmanagedCustomerPolicyARN,
			}},
		},
		ecsTask("a", "a"),
		ecsService("a"),
		{
			"address": "aws_lambda_function.pinned", "mode": "managed", "type": "aws_lambda_function", "name": "pinned",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"function_name": "pinned", "handler": "index.handler", "runtime": "nodejs20.x",
			}},
		},
	}
	cfg := []map[string]any{
		{"address": "aws_iam_role.a", "type": "aws_iam_role", "name": "a", "expressions": map[string]any{}},
		{"address": "aws_s3_bucket.bucket_a", "type": "aws_s3_bucket", "name": "bucket_a", "expressions": map[string]any{}},
		{"address": "aws_iam_role_policy.a_s3", "type": "aws_iam_role_policy", "name": "a_s3", "expressions": map[string]any{
			"role":   map[string]any{"references": []any{"aws_iam_role.a.name", "aws_iam_role.a"}},
			"policy": map[string]any{"constant_value": pol},
		}},
		{"address": "aws_iam_role_policy_attachment.a_bedrock", "type": "aws_iam_role_policy_attachment", "name": "a_bedrock", "expressions": map[string]any{
			"role":       map[string]any{"references": []any{"aws_iam_role.a.name", "aws_iam_role.a"}},
			"policy_arn": map[string]any{"constant_value": bedrockFullARN},
		}},
		{"address": "aws_iam_role_policy_attachment.a_customer", "type": "aws_iam_role_policy_attachment", "name": "a_customer", "expressions": map[string]any{
			"role":       map[string]any{"references": []any{"aws_iam_role.a.name", "aws_iam_role.a"}},
			"policy_arn": map[string]any{"constant_value": unmanagedCustomerPolicyARN},
		}},
		ecsTaskCfg("a", "a"),
		ecsServiceCfg("a"),
		{"address": "aws_lambda_function.pinned", "type": "aws_lambda_function", "name": "pinned", "expressions": map[string]any{
			"role": map[string]any{"references": []any{"aws_iam_role.a.arn", "aws_iam_role.a"}},
		}},
	}
	raw, err := json.Marshal(map[string]any{
		"format_version":   "1.2",
		"resource_changes": resources,
		"configuration":    map[string]any{"root_module": map[string]any{"resources": cfg}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func sharedRoleWidePlan(t *testing.T) string {
	t.Helper()
	pol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::bucket-a/*"]}]}`
	resources := []map[string]any{
		iamRoleChange("a", "role-a"),
		{
			"address": "aws_s3_bucket.bucket_a", "mode": "managed", "type": "aws_s3_bucket", "name": "bucket_a",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"bucket": "bucket-a", "arn": "arn:aws:s3:::bucket-a",
			}},
		},
		{
			"address": "aws_iam_role_policy.a_s3", "mode": "managed", "type": "aws_iam_role_policy", "name": "a_s3",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"name": "a-s3", "policy": pol, "role": "role-a",
			}},
		},
		{
			"address": "aws_iam_role_policy_attachment.a_managed", "mode": "managed", "type": "aws_iam_role_policy_attachment", "name": "a_managed",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"role": "role-a", "policy_arn": unmanagedCustomerPolicyARN,
			}},
		},
		ecsTask("a", "a"),
		ecsTask("c", "a"),
		ecsService("a"),
		ecsService("c"),
	}
	cfg := []map[string]any{
		{"address": "aws_iam_role.a", "type": "aws_iam_role", "name": "a", "expressions": map[string]any{}},
		{"address": "aws_s3_bucket.bucket_a", "type": "aws_s3_bucket", "name": "bucket_a", "expressions": map[string]any{}},
		{"address": "aws_iam_role_policy.a_s3", "type": "aws_iam_role_policy", "name": "a_s3", "expressions": map[string]any{
			"role":   map[string]any{"references": []any{"aws_iam_role.a.name", "aws_iam_role.a"}},
			"policy": map[string]any{"constant_value": pol},
		}},
		{"address": "aws_iam_role_policy_attachment.a_managed", "type": "aws_iam_role_policy_attachment", "name": "a_managed", "expressions": map[string]any{
			"role":       map[string]any{"references": []any{"aws_iam_role.a.name", "aws_iam_role.a"}},
			"policy_arn": map[string]any{"constant_value": unmanagedCustomerPolicyARN},
		}},
		ecsTaskCfg("a", "a"),
		ecsTaskCfg("c", "a"),
		ecsServiceCfg("a"),
		ecsServiceCfg("c"),
	}
	raw, err := json.Marshal(map[string]any{
		"format_version":   "1.2",
		"resource_changes": resources,
		"configuration":    map[string]any{"root_module": map[string]any{"resources": cfg}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
