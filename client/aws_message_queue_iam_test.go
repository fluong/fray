package client

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestAmazonSQSFullAccessAccountScope(t *testing.T) {
	const sqsFull = "arn:aws:iam::aws:policy/AmazonSQSFullAccess"
	doc, warnings := parseIAMPlan(t, sqsManagedWidePlan(t, sqsFull))
	scopeA, okA := flowScopeToMessageQueueService(t, doc, "aws_ecs_service.app", "sqs")
	if !okA || scopeA != "account" {
		t.Fatalf("AmazonSQSFullAccess scope=%q present=%v; want account", scopeA, okA)
	}
	for _, w := range warnings {
		if strings.Contains(w, "aws_iam_role_policy_attachment.app_sqs") {
			t.Fatalf("known-wide SQS policy must not warn: %s", w)
		}
	}
}

func TestSQSStarOnQueueARNResourceScope(t *testing.T) {
	plan := minimalSQSQueueIAMPlan(t, []string{"sqs:*"}, []string{"arn:aws:sqs:us-east-1:111122223333:jobs-queue"})
	doc, _ := parseIAMPlan(t, string(plan))
	f := flowLambdaToMessageQueue(doc, "aws_lambda_function.fn", "aws_sqs_queue.jobs")
	if f == nil || f.AuthzScope != "resource" {
		t.Fatalf("flow=%v want resource", f)
	}
}

func TestSQSMixedNamedAndStarAccountScope(t *testing.T) {
	plan := minimalSQSQueueIAMPlan(t, []string{"sqs:SendMessage"}, []string{"arn:aws:sqs:us-east-1:111122223333:a-queue", "*"})
	doc, _ := parseIAMPlan(t, string(plan))
	for _, q := range []string{"aws_sqs_queue.a", "aws_sqs_queue.b"} {
		f := flowLambdaToMessageQueue(doc, "aws_lambda_function.fn", q)
		if f == nil || f.AuthzScope != "account" {
			t.Fatalf("%s scope=%v want account", q, f)
		}
	}
}

func TestF45ResHCLFallbackResolvesQueueTopicRefs(t *testing.T) {
	modDir := filepath.Join("testdata", "fr044_hcl")
	doc, warnings := parseCoveragePlanModule(t, "coverage-fr044-plan.json", modDir)
	for _, w := range warnings {
		if strings.Contains(w, "authz_scope omitted for aws_iam_role.f45_res") {
			t.Fatalf("HCL fallback must resolve f45_res policy: %s", w)
		}
	}
	f := flowLambdaToMessageQueue(doc, "aws_lambda_function.f45_res", "aws_sqs_queue.sqs_rp_none")
	if f == nil || f.AuthzScope != "resource" {
		t.Fatalf("flow=%v", f)
	}
}

func sqsManagedWidePlan(t *testing.T, managedARN string) string {
	t.Helper()
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			iamRoleChange("app", "app-role"),
			map[string]any{
				"address": "aws_sqs_queue.jobs", "mode": "managed", "type": "aws_sqs_queue", "name": "jobs",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"name": "jobs-queue", "arn": "arn:aws:sqs:us-east-1:111122223333:jobs-queue",
				}},
			},
			map[string]any{
				"address": "aws_iam_role_policy_attachment.app_sqs", "mode": "managed", "type": "aws_iam_role_policy_attachment", "name": "app_sqs",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"role": "app-role", "policy_arn": managedARN,
				}},
			},
			ecsTask("app"),
			ecsService("app"),
		},
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					ecsTaskCfg("app", "app"),
					ecsServiceCfg("app"),
					map[string]any{
						"address": "aws_iam_role_policy_attachment.app_sqs", "mode": "managed", "type": "aws_iam_role_policy_attachment", "name": "app_sqs",
						"provider_config_key": "aws",
						"expressions": map[string]any{
							"role":       map[string]any{"references": []any{"aws_iam_role.app.name", "aws_iam_role.app"}},
							"policy_arn": map[string]any{"constant_value": managedARN},
						},
					},
				},
			},
		},
	}
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func flowScopeToMessageQueueService(t *testing.T, doc DFD, fromAddr, service string) (string, bool) {
	t.Helper()
	byID := map[string]Element{}
	for _, el := range doc.Elements {
		byID[el.ID] = el
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		from, ok1 := byID[f.From]
		to, ok2 := byID[f.To]
		if !ok1 || !ok2 || to.Kind != "message_queue" {
			continue
		}
		if len(from.Evidence.Addresses) == 0 || from.Evidence.Addresses[0] != fromAddr {
			continue
		}
		addr := to.Evidence.Addresses[0]
		switch service {
		case "sqs":
			if !stringsHasPrefix(addr, "aws_sqs_queue.") {
				continue
			}
		case "sns":
			if !stringsHasPrefix(addr, "aws_sns_topic.") {
				continue
			}
		default:
			continue
		}
		return f.AuthzScope, f.AuthzScope != ""
	}
	return "", false
}

func stringsHasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

func minimalSQSQueueIAMPlan(t *testing.T, actions, resourceRefs []string) []byte {
	t.Helper()
	resAny := any(resourceRefs[0])
	if len(resourceRefs) > 1 {
		resAny = resourceRefs
	}
	actAny := any(actions[0])
	if len(actions) > 1 {
		actAny = actions
	}
	polDoc, err := json.Marshal(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{map[string]any{
			"Effect": "Allow", "Action": actAny, "Resource": resAny,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{"address": "aws_sqs_queue.a", "mode": "managed", "type": "aws_sqs_queue", "name": "a", "change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "a-queue", "arn": "arn:aws:sqs:us-east-1:111122223333:a-queue"}, "after_unknown": map[string]any{"id": true}}},
			map[string]any{"address": "aws_sqs_queue.b", "mode": "managed", "type": "aws_sqs_queue", "name": "b", "change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "b-queue"}, "after_unknown": map[string]any{"arn": true, "id": true}}},
			map[string]any{"address": "aws_sqs_queue.jobs", "mode": "managed", "type": "aws_sqs_queue", "name": "jobs", "change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "jobs-queue", "arn": "arn:aws:sqs:us-east-1:111122223333:jobs-queue"}, "after_unknown": map[string]any{"id": true}}},
			map[string]any{"address": "aws_iam_role.fn", "mode": "managed", "type": "aws_iam_role", "name": "fn", "change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "fn-role"}}},
			map[string]any{"address": "aws_iam_role_policy.fn", "mode": "managed", "type": "aws_iam_role_policy", "name": "fn", "change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "fn-pol", "role": "fn-role", "policy": string(polDoc)}}},
			map[string]any{"address": "aws_lambda_function.fn", "mode": "managed", "type": "aws_lambda_function", "name": "fn", "change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"function_name": "fn", "role": "arn:aws:iam::111122223333:role/fn-role"}}},
		},
		"configuration": map[string]any{"root_module": map[string]any{"resources": []any{
			map[string]any{
				"address": "aws_iam_role_policy.fn", "mode": "managed", "type": "aws_iam_role_policy", "name": "fn", "provider_config_key": "aws",
				"expressions": map[string]any{
					"role":   map[string]any{"references": []any{"aws_iam_role.fn.id", "aws_iam_role.fn"}},
					"policy": map[string]any{"constant_value": string(polDoc)},
				},
			},
			map[string]any{
				"address": "aws_lambda_function.fn", "mode": "managed", "type": "aws_lambda_function", "name": "fn", "provider_config_key": "aws",
				"expressions": map[string]any{
					"role":          map[string]any{"references": []any{"aws_iam_role.fn.arn", "aws_iam_role.fn"}},
					"function_name": map[string]any{"constant_value": "fn"},
				},
			},
		}}},
	}
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
