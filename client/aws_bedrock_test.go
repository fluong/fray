package client

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
)

func TestBedrockIAMMapping(t *testing.T) {
	cfg := []byte("schema_version: fray-config/v1\n")
	src := Source{Repo: "t/bedrock", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}

	cases := []struct {
		name       string
		plan       string
		wantScope  string // "" = omitted
		wantRegion string // "" = omitted
		wantCaller string // address of compute element
		wantFlows  int
	}{
		{
			name:       "ecs_task_role_star",
			plan:       bedrockECSPlan(t, bedrockIAMOpts{resources: []string{"*"}, onTaskRole: true}),
			wantScope:  "account",
			wantRegion: "",
			wantCaller: "aws_ecs_service.app",
			wantFlows:  1,
		},
		{
			name: "lambda_foundation_eu_west_1",
			plan: bedrockLambdaPlan(t, bedrockIAMOpts{
				resources: []string{"arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"},
			}),
			wantScope:  "resource",
			wantRegion: "eu-west-1",
			wantCaller: "aws_lambda_function.fn",
			wantFlows:  1,
		},
		{
			name: "global_inference_profile",
			plan: bedrockLambdaPlan(t, bedrockIAMOpts{
				resources: []string{"arn:aws:bedrock:us-east-1:123456789012:inference-profile/global.anthropic.claude-sonnet-4"},
			}),
			wantScope:  "resource",
			wantRegion: "global",
			wantCaller: "aws_lambda_function.fn",
			wantFlows:  1,
		},
		{
			name: "geographic_profile_plus_multi_region_models",
			plan: bedrockLambdaPlan(t, bedrockIAMOpts{
				resources: []string{
					"arn:aws:bedrock:us-east-1:123456789012:inference-profile/eu.anthropic.claude-sonnet-4",
					"arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",
					"arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",
					"arn:aws:bedrock:ap-southeast-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",
				},
			}),
			wantScope:  "resource",
			wantRegion: "",
			wantCaller: "aws_lambda_function.fn",
			wantFlows:  1,
		},
		{
			name:       "condition_omits_scope",
			plan:       bedrockLambdaPlan(t, bedrockIAMOpts{resources: []string{"*"}, condition: true}),
			wantScope:  "",
			wantRegion: "",
			wantCaller: "aws_lambda_function.fn",
			wantFlows:  1,
		},
		{
			name:       "not_action_omits_scope",
			plan:       bedrockLambdaPlan(t, bedrockIAMOpts{resources: []string{"*"}, notAction: true}),
			wantScope:  "",
			wantRegion: "",
			wantCaller: "aws_lambda_function.fn",
			wantFlows:  1,
		},
		{
			name:       "deny_bedrock_omits_scope",
			plan:       bedrockLambdaPlan(t, bedrockIAMOpts{resources: []string{"*"}, denyBedrock: true}),
			wantScope:  "",
			wantRegion: "",
			wantCaller: "aws_lambda_function.fn",
			wantFlows:  1,
		},
		{
			name:       "computed_resources_omits_scope",
			plan:       bedrockLambdaPlan(t, bedrockIAMOpts{computedResources: true}),
			wantScope:  "",
			wantRegion: "",
			wantCaller: "aws_lambda_function.fn",
			wantFlows:  1,
		},
		{
			name:       "amazon_bedrock_full_access",
			plan:       bedrockLambdaPlan(t, bedrockIAMOpts{managedFullAccess: true}),
			wantScope:  "account",
			wantRegion: "",
			wantCaller: "aws_lambda_function.fn",
			wantFlows:  1,
		},
		{
			name:      "execution_role_not_task_role",
			plan:      bedrockECSPlan(t, bedrockIAMOpts{resources: []string{"*"}, onTaskRole: false, onExecRole: true}),
			wantFlows: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, err := Parse([]byte(tc.plan), cfg, "fray.yaml", src, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			bedrock := findBedrock(doc)
			if tc.wantFlows == 0 {
				if bedrock != nil {
					t.Fatal("expected no Bedrock element")
				}
				if n := countBedrockFlows(doc); n != 0 {
					t.Fatalf("flows=%d want 0", n)
				}
				return
			}
			if bedrock == nil {
				t.Fatal("missing Bedrock llm_api")
			}
			if bedrock.Name != "Bedrock" || bedrock.Provider != "aws" || bedrock.Provenance != "inferred" {
				t.Fatalf("element=%+v", bedrock)
			}
			if len(bedrock.Evidence.Signals) != 1 ||
				bedrock.Evidence.Signals[0].Type != "iam_service" ||
				bedrock.Evidence.Signals[0].Name != "bedrock" {
				t.Fatalf("signals=%+v", bedrock.Evidence.Signals)
			}
			gotRegion, _ := bedrock.Attributes["region"].(string)
			if gotRegion != tc.wantRegion {
				t.Fatalf("region=%q want %q", gotRegion, tc.wantRegion)
			}
			flow := bedrockFlowFrom(doc, tc.wantCaller)
			if flow == nil {
				t.Fatalf("no flow from %s", tc.wantCaller)
			}
			if flow.DataClass != "unknown" || flow.Transport != "tls" {
				t.Fatalf("flow meta data_class=%q transport=%q", flow.DataClass, flow.Transport)
			}
			if flow.AuthzScope != tc.wantScope {
				t.Fatalf("authz_scope=%q want %q", flow.AuthzScope, tc.wantScope)
			}
			if tc.wantScope == "" {
				if len(flow.AuthzGrants) != 0 {
					t.Fatalf("grants=%v want omitted", flow.AuthzGrants)
				}
			} else if len(flow.AuthzGrants) == 0 || flow.AuthzGrants[0] != tc.wantScope {
				t.Fatalf("grants=%v", flow.AuthzGrants)
			}
		})
	}
}

func TestBedrockLambdaDedupesAPIGatewayElement(t *testing.T) {
	plan := bedrockLambdaWithURLAndGrant(t)
	doc, _, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "t/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, el := range doc.Elements {
		if el.Kind == "serverless_function" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("serverless_function count=%d want 1", n)
	}
	if findBedrock(doc) == nil {
		t.Fatal("missing Bedrock")
	}
}

func TestBedrockTwoCallersRegionCombine(t *testing.T) {
	cfg := []byte("schema_version: fray-config/v1\n")
	src := Source{Repo: "t/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}

	t.Run("different_concrete_regions", func(t *testing.T) {
		plan := bedrockTwoLambdasPlan(t,
			[]string{"arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"},
			[]string{"arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"},
		)
		doc, _, err := Parse([]byte(plan), cfg, "fray.yaml", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		b := findBedrock(doc)
		if b == nil {
			t.Fatal("missing Bedrock")
		}
		if _, ok := b.Attributes["region"]; ok {
			t.Fatalf("region must be omitted, got %v", b.Attributes["region"])
		}
		if countBedrockFlows(doc) != 2 {
			t.Fatalf("flows=%d", countBedrockFlows(doc))
		}
	})

	t.Run("one_global", func(t *testing.T) {
		plan := bedrockTwoLambdasPlan(t,
			[]string{"arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"},
			[]string{"arn:aws:bedrock:us-east-1:123456789012:inference-profile/global.anthropic.claude-sonnet-4"},
		)
		doc, _, err := Parse([]byte(plan), cfg, "fray.yaml", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		b := findBedrock(doc)
		if b == nil {
			t.Fatal("missing Bedrock")
		}
		if b.Attributes["region"] != "global" {
			t.Fatalf("region=%v want global", b.Attributes["region"])
		}
	})
}

func TestBedrockNoLeakInDFDAndScanRequest(t *testing.T) {
	plan := bedrockLambdaPlan(t, bedrockIAMOpts{
		resources: []string{
			"arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",
			"arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet-4",
		},
	})
	cfg := []byte("schema_version: fray-config/v1\n")
	src := Source{Repo: "probe/bedrock", Commit: "abcdef1234567", Tool: "terraform", Fidelity: "plan"}
	doc, _, err := Parse([]byte(plan), cfg, "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	assertBedrockNoLeak(t, raw)

	key := mustBedrockKey(t)
	for _, redact := range []bool{true, false} {
		t.Run(map[bool]string{true: "redaction_on", false: "redaction_off"}[redact], func(t *testing.T) {
			body := bedrockScanRequestBody(t, doc, key, redact)
			assertBedrockNoLeak(t, body)
		})
	}
}

func mustBedrockKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func bedrockScanRequestBody(t *testing.T, doc DFD, key []byte, redact bool) []byte {
	t.Helper()
	wire := doc
	var idMap IDMap
	repo := doc.Source.Repo
	if redact {
		var err error
		wire, idMap, err = Redact(doc, key)
		if err != nil {
			t.Fatal(err)
		}
		repo = wire.Source.Repo
	}
	rawDFD, err := Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(apiv1.ScanRequest{
		DFD:             rawDFD,
		Repo:            repo,
		Commit:          "abcdef1234567",
		IsDefaultBranch: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if redact {
		if err := AssertNoPlaintext(body, idMap.Plaintext); err != nil {
			t.Fatalf("AssertNoPlaintext: %v", err)
		}
	}
	return body
}

var (
	bedrockLeakARN       = regexp.MustCompile(`arn:aws`)
	bedrockLeakAccount   = regexp.MustCompile(`\b\d{12}\b`)
	bedrockLeakModelPath = regexp.MustCompile(`foundation-model|inference-profile`)
	bedrockLeakPrefixes  = []string{"anthropic.", "amazon.", "meta.", "mistral.", "cohere.", "ai21."}
)

func assertBedrockNoLeak(t *testing.T, body []byte) {
	t.Helper()
	if bedrockLeakARN.Match(body) {
		t.Error("FAIL: arn:aws PRESENT")
	}
	if bedrockLeakAccount.Match(body) {
		t.Error("FAIL: 12-digit account id PRESENT")
	}
	if bedrockLeakModelPath.Match(body) {
		t.Error("FAIL: foundation-model/inference-profile PRESENT")
	}
	for _, p := range bedrockLeakPrefixes {
		if bytes.Contains(body, []byte(p)) {
			t.Errorf("FAIL: model id prefix %q PRESENT", p)
		}
	}
}

// --- plan builders ---

type bedrockIAMOpts struct {
	resources         []string
	onTaskRole        bool
	onExecRole        bool
	condition         bool
	notAction         bool
	denyBedrock       bool
	computedResources bool
	managedFullAccess bool
}

func bedrockLambdaPlan(t *testing.T, o bedrockIAMOpts) string {
	t.Helper()
	resources, cfg := bedrockLambdaSkeleton("fn", "role")
	resources, cfg = appendBedrockIAM(resources, cfg, "role", o)
	return marshalPlan(t, resources, cfg)
}

func bedrockECSPlan(t *testing.T, o bedrockIAMOpts) string {
	t.Helper()
	resources := []map[string]any{
		{
			"address": "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service",
			"name": "app", "change": map[string]any{"after": map[string]any{"name": "app"}},
		},
		{
			"address": "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition",
			"name": "app", "change": map[string]any{"after": map[string]any{
				"family": "app",
				"container_definitions": `[{"name":"app","image":"example:1"}]`,
			}},
		},
		{
			"address": "aws_iam_role.task", "mode": "managed", "type": "aws_iam_role",
			"name": "task", "change": map[string]any{"after": map[string]any{"name": "task"}},
		},
		{
			"address": "aws_iam_role.exec", "mode": "managed", "type": "aws_iam_role",
			"name": "exec", "change": map[string]any{"after": map[string]any{"name": "exec"}},
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
				"task_role_arn":      map[string]any{"references": []any{"aws_iam_role.task.arn", "aws_iam_role.task"}},
				"execution_role_arn": map[string]any{"references": []any{"aws_iam_role.exec.arn", "aws_iam_role.exec"}},
			},
		},
		{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task", "expressions": map[string]any{}},
		{"address": "aws_iam_role.exec", "type": "aws_iam_role", "name": "exec", "expressions": map[string]any{}},
	}
	role := "task"
	if o.onExecRole && !o.onTaskRole {
		role = "exec"
	}
	resources, cfg = appendBedrockIAM(resources, cfg, role, o)
	return marshalPlan(t, resources, cfg)
}

func bedrockLambdaWithURLAndGrant(t *testing.T) string {
	t.Helper()
	resources, cfg := bedrockLambdaSkeleton("fn", "role")
	resources = append(resources, map[string]any{
		"address": "aws_lambda_function_url.fn", "mode": "managed", "type": "aws_lambda_function_url",
		"name": "fn", "change": map[string]any{"after": map[string]any{"authorization_type": "AWS_IAM"}},
	})
	cfg = append(cfg, map[string]any{
		"address": "aws_lambda_function_url.fn", "type": "aws_lambda_function_url", "name": "fn",
		"expressions": map[string]any{
			"function_name": map[string]any{"references": []any{"aws_lambda_function.fn.arn", "aws_lambda_function.fn"}},
		},
	})
	resources, cfg = appendBedrockIAM(resources, cfg, "role", bedrockIAMOpts{
		resources: []string{"arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"},
	})
	return marshalPlan(t, resources, cfg)
}

func bedrockTwoLambdasPlan(t *testing.T, resA, resB []string) string {
	t.Helper()
	resources := []map[string]any{
		{
			"address": "aws_lambda_function.a", "mode": "managed", "type": "aws_lambda_function",
			"name": "a", "change": map[string]any{"after": map[string]any{"function_name": "a"}},
		},
		{
			"address": "aws_lambda_function.b", "mode": "managed", "type": "aws_lambda_function",
			"name": "b", "change": map[string]any{"after": map[string]any{"function_name": "b"}},
		},
		{
			"address": "aws_iam_role.role_a", "mode": "managed", "type": "aws_iam_role",
			"name": "role_a", "change": map[string]any{"after": map[string]any{"name": "role_a"}},
		},
		{
			"address": "aws_iam_role.role_b", "mode": "managed", "type": "aws_iam_role",
			"name": "role_b", "change": map[string]any{"after": map[string]any{"name": "role_b"}},
		},
	}
	cfg := []map[string]any{
		{
			"address": "aws_lambda_function.a", "type": "aws_lambda_function", "name": "a",
			"expressions": map[string]any{
				"role": map[string]any{"references": []any{"aws_iam_role.role_a.arn", "aws_iam_role.role_a"}},
			},
		},
		{
			"address": "aws_lambda_function.b", "type": "aws_lambda_function", "name": "b",
			"expressions": map[string]any{
				"role": map[string]any{"references": []any{"aws_iam_role.role_b.arn", "aws_iam_role.role_b"}},
			},
		},
		{"address": "aws_iam_role.role_a", "type": "aws_iam_role", "name": "role_a", "expressions": map[string]any{}},
		{"address": "aws_iam_role.role_b", "type": "aws_iam_role", "name": "role_b", "expressions": map[string]any{}},
	}
	resources, cfg = appendBedrockIAM(resources, cfg, "role_a", bedrockIAMOpts{resources: resA})
	resources, cfg = appendBedrockIAMNamed(resources, cfg, "role_b", "b", bedrockIAMOpts{resources: resB})
	return marshalPlan(t, resources, cfg)
}

func bedrockLambdaSkeleton(fnName, roleName string) ([]map[string]any, []map[string]any) {
	resources := []map[string]any{
		{
			"address": "aws_lambda_function." + fnName, "mode": "managed", "type": "aws_lambda_function",
			"name": fnName, "change": map[string]any{"after": map[string]any{"function_name": fnName}},
		},
		{
			"address": "aws_iam_role." + roleName, "mode": "managed", "type": "aws_iam_role",
			"name": roleName, "change": map[string]any{"after": map[string]any{"name": roleName}},
		},
	}
	cfg := []map[string]any{
		{
			"address": "aws_lambda_function." + fnName, "type": "aws_lambda_function", "name": fnName,
			"expressions": map[string]any{
				"role": map[string]any{"references": []any{"aws_iam_role." + roleName + ".arn", "aws_iam_role." + roleName}},
			},
		},
		{"address": "aws_iam_role." + roleName, "type": "aws_iam_role", "name": roleName, "expressions": map[string]any{}},
	}
	return resources, cfg
}

func appendBedrockIAM(resources, cfg []map[string]any, roleName string, o bedrockIAMOpts) ([]map[string]any, []map[string]any) {
	return appendBedrockIAMNamed(resources, cfg, roleName, roleName, o)
}

func appendBedrockIAMNamed(resources, cfg []map[string]any, roleName, suffix string, o bedrockIAMOpts) ([]map[string]any, []map[string]any) {
	att := "aws_iam_role_policy_attachment.bedrock_" + suffix
	if o.managedFullAccess {
		resources = append(resources, map[string]any{
			"address": att, "mode": "managed", "type": "aws_iam_role_policy_attachment",
			"name": "bedrock_" + suffix,
			"change": map[string]any{"after": map[string]any{
				"policy_arn": "arn:aws:iam::aws:policy/AmazonBedrockFullAccess",
			}},
		})
		cfg = append(cfg, map[string]any{
			"address": att, "type": "aws_iam_role_policy_attachment", "name": "bedrock_" + suffix,
			"expressions": map[string]any{
				"role":       map[string]any{"references": []any{"aws_iam_role." + roleName + ".name", "aws_iam_role." + roleName}},
				"policy_arn": map[string]any{"constant_value": "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"},
			},
		})
		return resources, cfg
	}

	pol := "aws_iam_policy.bedrock_" + suffix
	doc := "data.aws_iam_policy_document.bedrock_" + suffix
	resources = append(resources,
		map[string]any{
			"address": pol, "mode": "managed", "type": "aws_iam_policy",
			"name": "bedrock_" + suffix, "change": map[string]any{"after": map[string]any{"name": "bedrock-" + suffix}},
		},
		map[string]any{
			"address": att, "mode": "managed", "type": "aws_iam_role_policy_attachment",
			"name": "bedrock_" + suffix, "change": map[string]any{"after": map[string]any{}},
		},
	)
	cfg = append(cfg,
		map[string]any{
			"address": pol, "type": "aws_iam_policy", "name": "bedrock_" + suffix,
			"expressions": map[string]any{
				"policy": map[string]any{"references": []any{doc + ".json", doc}},
			},
		},
		map[string]any{
			"address": att, "type": "aws_iam_role_policy_attachment", "name": "bedrock_" + suffix,
			"expressions": map[string]any{
				"role":       map[string]any{"references": []any{"aws_iam_role." + roleName + ".name", "aws_iam_role." + roleName}},
				"policy_arn": map[string]any{"references": []any{pol + ".arn", pol}},
			},
		},
	)

	stmts := []any{}
	allow := map[string]any{
		"effect":  "Allow",
		"actions": []any{"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"},
	}
	if o.notAction {
		allow["not_actions"] = []any{"bedrock:InvokeModelWithResponseStream"}
		allow["actions"] = []any{"bedrock:InvokeModel"}
	}
	if o.condition {
		allow["condition"] = []any{map[string]any{"test": "StringEquals", "variable": "aws:RequestedRegion", "values": []any{"eu-west-1"}}}
	}
	if o.computedResources {
		allow["resources"] = []any{nil}
	} else {
		res := make([]any, len(o.resources))
		for i, r := range o.resources {
			res[i] = r
		}
		if len(res) == 0 {
			res = []any{"*"}
		}
		allow["resources"] = res
	}
	stmts = append(stmts, allow)
	if o.denyBedrock {
		stmts = append(stmts, map[string]any{
			"effect":    "Deny",
			"actions":   []any{"bedrock:InvokeModel"},
			"resources": []any{"*"},
		})
	}

	// data source appears in resource_changes with mode=data
	resources = append(resources, map[string]any{
		"address": doc, "mode": "data", "type": "aws_iam_policy_document",
		"name": "bedrock_" + suffix,
		"change": map[string]any{"after": map[string]any{
			"statement": stmts,
		}},
	})
	cfg = append(cfg, map[string]any{
		"address": doc, "type": "aws_iam_policy_document", "name": "bedrock_" + suffix, "mode": "data",
		"expressions": map[string]any{},
	})
	return resources, cfg
}

func findBedrock(doc DFD) *Element {
	for i := range doc.Elements {
		el := &doc.Elements[i]
		if el.Kind == "llm_api" && el.Provider == "aws" && el.Name == "Bedrock" {
			return el
		}
	}
	return nil
}

func countBedrockFlows(doc DFD) int {
	b := findBedrock(doc)
	if b == nil {
		return 0
	}
	n := 0
	for _, f := range doc.Flows {
		if f.To == b.ID {
			n++
		}
	}
	return n
}

func bedrockFlowFrom(doc DFD, callerAddr string) *Flow {
	var callerID, bedrockID string
	for _, el := range doc.Elements {
		if el.Kind == "llm_api" && el.Provider == "aws" {
			bedrockID = el.ID
		}
		if len(el.Evidence.Addresses) == 1 && el.Evidence.Addresses[0] == callerAddr {
			callerID = el.ID
		}
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		if f.From == callerID && f.To == bedrockID {
			return f
		}
	}
	return nil
}

func TestBedrockExistingGoldensUnchanged(t *testing.T) {
	// Sanity: aws-web-app DFD golden must stay byte-identical after Bedrock work.
	plan, err := os.ReadFile("testdata/aws-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "", Source{
		Repo: "example/aws-web-app", Commit: "4530a865f29ba14931379f361b177a992edeab51",
		Tool: "terraform", Fidelity: "plan",
	}, filepath.Join("..", "testdata", "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) > 0 {
		t.Fatalf("warnings: %s", strings.Join(warnings, "\n"))
	}
	got, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "testdata", "golden", "aws-web-app-fixture.dfd.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("aws-web-app DFD golden changed (%d vs %d bytes) — stop, do not regenerate", len(got), len(want))
	}
}

func TestBedrockInvokeActionMatcher(t *testing.T) {
	plan := bedrockLambdaPlan(t, bedrockIAMOpts{resources: []string{"*"}})
	plan = strings.Replace(plan, `"bedrock:InvokeModel"`, `"Bedrock:InvokeModel"`, 1)
	doc, _, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "t/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if findBedrock(doc) == nil {
		t.Fatal("case-insensitive action match failed")
	}
}

func TestBedrockJSONRoundTripHelpers(t *testing.T) {
	// Ensure appendBedrockIAM produces valid JSON for the deny/condition variants.
	for _, o := range []bedrockIAMOpts{
		{resources: []string{"*"}, condition: true},
		{resources: []string{"*"}, denyBedrock: true},
		{managedFullAccess: true},
	} {
		raw := bedrockLambdaPlan(t, o)
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			t.Fatal(err)
		}
	}
}
