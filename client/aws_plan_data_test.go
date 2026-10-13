package client

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLoadDataResourcesPriorStateAndCollision(t *testing.T) {
	// RC entry for data.a; prior_state has data.a (different values) and data.b;
	// child module holds data.c. RC wins for data.a.
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "data.aws_iam_policy_document.a", "mode": "data", "type": "aws_iam_policy_document",
				"change": map[string]any{"actions": []any{"read"}, "after": map[string]any{
					"statement": []any{map[string]any{"actions": []any{"s3:*"}, "resources": []any{"*"}}},
				}},
			},
		},
		"prior_state": map[string]any{
			"values": map[string]any{
				"root_module": map[string]any{
					"resources": []any{
						map[string]any{
							"address": "data.aws_iam_policy_document.a", "mode": "data", "type": "aws_iam_policy_document",
							"values": map[string]any{
								"statement": []any{map[string]any{
									"actions": []any{"s3:GetObject"}, "resources": []any{"arn:aws:s3:::only-prior/*"},
								}},
							},
						},
						map[string]any{
							"address": "data.aws_iam_policy_document.b", "mode": "data", "type": "aws_iam_policy_document",
							"values": map[string]any{"statement": []any{}},
						},
					},
					"child_modules": []any{
						map[string]any{
							"address": "module.iam",
							"resources": []any{
								map[string]any{
									"address": "module.iam.data.aws_iam_policy_document.c",
									"mode":    "data", "type": "aws_iam_policy_document",
									"values": map[string]any{"statement": []any{}},
								},
							},
						},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := loadDataResources(raw)
	if err != nil {
		t.Fatal(err)
	}
	byAddr := map[string]planResource{}
	for _, d := range docs {
		byAddr[d.address] = d
	}
	if len(byAddr) != 3 {
		t.Fatalf("got %d data docs want 3: %v", len(byAddr), keysOf(byAddr))
	}
	a := byAddr["data.aws_iam_policy_document.a"]
	stmts := asList(a.values["statement"])
	if len(stmts) != 1 {
		t.Fatalf("collision: want RC statement, got %#v", a.values["statement"])
	}
	m := stmts[0].(map[string]any)
	if res := asList(m["resources"]); len(res) != 1 || res[0] != "*" {
		t.Fatalf("resource_changes must win collision, resources=%v", res)
	}
	if _, ok := byAddr["data.aws_iam_policy_document.b"]; !ok {
		t.Fatal("missing prior_state root data.b")
	}
	if _, ok := byAddr["module.iam.data.aws_iam_policy_document.c"]; !ok {
		t.Fatal("missing prior_state child_modules data.c")
	}
}

func keysOf(m map[string]planResource) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestPriorStateDataDocScopesSecretsS3Bedrock: one plan-time data document
// (prior_state only) grants secret, S3, and Bedrock — all scopes resource.
func TestPriorStateDataDocScopesSecretsS3Bedrock(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db-AbCdEf"
	bucket := "prior-state-bucket"
	bucketARN := "arn:aws:s3:::" + bucket
	bedrockARN := "arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
	docJSON := map[string]any{
		"statement": []any{
			map[string]any{
				"effect": "Allow", "actions": []any{"secretsmanager:GetSecretValue"},
				"resources": []any{secretARN},
			},
			map[string]any{
				"effect": "Allow", "actions": []any{"s3:PutObject", "s3:DeleteObject"},
				"resources": []any{bucketARN + "/*"},
			},
			map[string]any{
				"effect": "Allow", "actions": []any{"bedrock:InvokeModel"},
				"resources": []any{bedrockARN},
			},
		},
	}
	resources := []map[string]any{
		{
			"address": "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
			"change": map[string]any{"after": map[string]any{"name": "app"}},
		},
		{
			"address": "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
			"change": map[string]any{"after": map[string]any{
				"family": "app",
				// valueFrom uses a module address so elementsFromRefs can resolve it.
				"container_definitions": `[{"name":"app","image":"app:1","secrets":[{"name":"DB","valueFrom":"module.db.aws_secretsmanager_secret.db.arn"}]}]`,
			}},
		},
		{
			"address": "aws_iam_role.exec", "mode": "managed", "type": "aws_iam_role", "name": "exec",
			"change": map[string]any{"after": map[string]any{"name": "exec"}},
		},
		{
			"address": "aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task",
			"change": map[string]any{"after": map[string]any{"name": "task"}},
		},
		{
			"address": "aws_iam_role_policy.from_data", "mode": "managed", "type": "aws_iam_role_policy", "name": "from_data",
			"change": map[string]any{"after": map[string]any{"name": "from-data"}, "after_unknown": map[string]any{"policy": true}},
		},
		{
			"address": "aws_lambda_function.fn", "mode": "managed", "type": "aws_lambda_function", "name": "fn",
			"change": map[string]any{"after": map[string]any{"function_name": "fn"}},
		},
		{
			"address": "aws_iam_role.lambda", "mode": "managed", "type": "aws_iam_role", "name": "lambda",
			"change": map[string]any{"after": map[string]any{"name": "lambda"}},
		},
		{
			"address": "aws_iam_role_policy.lambda_data", "mode": "managed", "type": "aws_iam_role_policy", "name": "lambda_data",
			"change": map[string]any{"after": map[string]any{"name": "lambda-data"}, "after_unknown": map[string]any{"policy": true}},
		},
		{
			"address": "module.db.aws_secretsmanager_secret.db", "mode": "managed", "type": "aws_secretsmanager_secret", "name": "db",
			"change": map[string]any{"after": map[string]any{"name": "app/db", "arn": secretARN}},
		},
		{
			"address": "module.uploads.aws_s3_bucket.this", "mode": "managed", "type": "aws_s3_bucket", "name": "this",
			"change": map[string]any{"after": map[string]any{"bucket": bucket, "arn": bucketARN}},
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
		{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task", "expressions": map[string]any{}},
		{
			"address": "aws_iam_role_policy.from_data", "type": "aws_iam_role_policy", "name": "from_data",
			"expressions": map[string]any{
				// Attach the same prior_state doc to both exec (secrets) and task (S3)
				// via two policies — here one policy on task; exec gets a sibling below.
				"role":   map[string]any{"references": []any{"aws_iam_role.task.name", "aws_iam_role.task"}},
				"policy": map[string]any{"references": []any{"data.aws_iam_policy_document.all.json", "data.aws_iam_policy_document.all"}},
			},
		},
		{
			"address": "aws_iam_role_policy.exec_data", "type": "aws_iam_role_policy", "name": "exec_data", "mode": "managed",
			"expressions": map[string]any{
				"role":   map[string]any{"references": []any{"aws_iam_role.exec.name", "aws_iam_role.exec"}},
				"policy": map[string]any{"references": []any{"data.aws_iam_policy_document.all.json", "data.aws_iam_policy_document.all"}},
			},
		},
		{
			"address": "aws_lambda_function.fn", "type": "aws_lambda_function", "name": "fn",
			"expressions": map[string]any{
				"role": map[string]any{"references": []any{"aws_iam_role.lambda.arn", "aws_iam_role.lambda"}},
			},
		},
		{"address": "aws_iam_role.lambda", "type": "aws_iam_role", "name": "lambda", "expressions": map[string]any{}},
		{
			"address": "aws_iam_role_policy.lambda_data", "type": "aws_iam_role_policy", "name": "lambda_data",
			"expressions": map[string]any{
				"role":   map[string]any{"references": []any{"aws_iam_role.lambda.name", "aws_iam_role.lambda"}},
				"policy": map[string]any{"references": []any{"data.aws_iam_policy_document.all.json", "data.aws_iam_policy_document.all"}},
			},
		},
		{"address": "data.aws_iam_policy_document.all", "mode": "data", "type": "aws_iam_policy_document", "name": "all", "expressions": map[string]any{}},
		{"address": "module.db.aws_secretsmanager_secret.db", "type": "aws_secretsmanager_secret", "name": "db", "expressions": map[string]any{}},
		{"address": "module.uploads.aws_s3_bucket.this", "type": "aws_s3_bucket", "name": "this", "expressions": map[string]any{}},
	}
	// exec_data must also be in resource_changes
	resources = append(resources, map[string]any{
		"address": "aws_iam_role_policy.exec_data", "mode": "managed", "type": "aws_iam_role_policy", "name": "exec_data",
		"change": map[string]any{"after": map[string]any{"name": "exec-data"}, "after_unknown": map[string]any{"policy": true}},
	})
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
		"format_version":   "1.2",
		"resource_changes": resources,
		"configuration":    map[string]any{"root_module": root},
		"planned_values":   map[string]any{"root_module": map[string]any{"resources": []any{}}},
		"prior_state": map[string]any{
			"values": map[string]any{
				"root_module": map[string]any{
					"resources": []any{
						map[string]any{
							"address": "data.aws_iam_policy_document.all", "mode": "data",
							"type": "aws_iam_policy_document", "values": docJSON,
						},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	doc, _, err := Parse(raw, []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "t/prior", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	kind := map[string]string{}
	for _, el := range doc.Elements {
		kind[el.ID] = el.Kind
	}
	var gotSecret, gotS3, gotBedrock string
	for i := range doc.Flows {
		f := &doc.Flows[i]
		switch {
		case kind[f.From] == "secret_store" || kind[f.To] == "secret_store":
			gotSecret = f.AuthzScope
		case kind[f.To] == "object_storage":
			gotS3 = f.AuthzScope
		case kind[f.To] == "llm_api":
			gotBedrock = f.AuthzScope
		}
	}
	if gotSecret != "resource" {
		t.Fatalf("secret authz_scope=%q want resource", gotSecret)
	}
	if gotS3 != "resource" {
		t.Fatalf("s3 authz_scope=%q want resource", gotS3)
	}
	if gotBedrock != "resource" {
		t.Fatalf("bedrock authz_scope=%q want resource", gotBedrock)
	}
}

func TestPriorStateChildModuleDataDocS3Scope(t *testing.T) {
	// ECS + IAM + bucket live in module.app; data doc only in prior_state.child_modules.
	const mod = "module.app"
	bucket := "child-mod-bucket"
	literalBucket := "arn:aws:s3:::" + bucket + "/*"
	resources := []map[string]any{
		{
			"address": mod + ".aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
			"change": map[string]any{"after": map[string]any{"name": "app"}},
		},
		{
			"address": mod + ".aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
			"change": map[string]any{"after": map[string]any{
				"family":                "app",
				"container_definitions": `[{"name":"app","image":"app:1"}]`,
			}},
		},
		{
			"address": mod + ".aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task",
			"change": map[string]any{"after": map[string]any{"name": "task"}},
		},
		{
			"address": mod + ".aws_iam_role_policy.datadoc", "mode": "managed", "type": "aws_iam_role_policy", "name": "datadoc",
			"change": map[string]any{"after": map[string]any{"name": "d"}, "after_unknown": map[string]any{"policy": true}},
		},
		{
			"address": mod + ".aws_s3_bucket.uploads", "mode": "managed", "type": "aws_s3_bucket", "name": "uploads",
			"change": map[string]any{"after": map[string]any{"bucket": bucket}},
		},
	}
	modResources := []any{
		map[string]any{
			"address": "aws_ecs_service.app", "type": "aws_ecs_service", "name": "app",
			"expressions": map[string]any{
				"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.app.arn", "aws_ecs_task_definition.app"}},
			},
		},
		map[string]any{
			"address": "aws_ecs_task_definition.app", "type": "aws_ecs_task_definition", "name": "app",
			"expressions": map[string]any{
				"execution_role_arn": map[string]any{"references": []any{"aws_iam_role.task.arn", "aws_iam_role.task"}},
				"task_role_arn":      map[string]any{"references": []any{"aws_iam_role.task.arn", "aws_iam_role.task"}},
			},
		},
		map[string]any{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task", "expressions": map[string]any{}},
		map[string]any{
			"address": "aws_iam_role_policy.datadoc", "type": "aws_iam_role_policy", "name": "datadoc",
			"expressions": map[string]any{
				"role": map[string]any{"references": []any{"aws_iam_role.task.id", "aws_iam_role.task"}},
				"policy": map[string]any{"references": []any{
					"data.aws_iam_policy_document.s3.json",
					"data.aws_iam_policy_document.s3",
				}},
			},
		},
		map[string]any{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": map[string]any{}},
		map[string]any{"address": "data.aws_iam_policy_document.s3", "mode": "data", "type": "aws_iam_policy_document", "name": "s3", "expressions": map[string]any{}},
	}
	plan := map[string]any{
		"format_version":   "1.2",
		"resource_changes": resources,
		"configuration": map[string]any{"root_module": map[string]any{
			"resources": []any{},
			"module_calls": map[string]any{
				"app": map[string]any{
					"source": "./app", "expressions": map[string]any{},
					"module": map[string]any{"resources": modResources},
				},
			},
		}},
		"planned_values": map[string]any{"root_module": map[string]any{"resources": []any{}}},
		"prior_state": map[string]any{
			"values": map[string]any{
				"root_module": map[string]any{
					"resources": []any{},
					"child_modules": []any{
						map[string]any{
							"address": mod,
							"resources": []any{
								map[string]any{
									"address": mod + ".data.aws_iam_policy_document.s3",
									"mode":    "data", "type": "aws_iam_policy_document",
									"values": map[string]any{
										"statement": []any{map[string]any{
											"effect": "Allow", "actions": []any{"s3:PutObject"},
											"resources": []any{literalBucket},
										}},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	doc, _, err := Parse(raw, []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "t/child", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		for _, el := range doc.Elements {
			if el.ID == f.To && el.Kind == "object_storage" {
				if f.AuthzScope != "resource" {
					t.Fatalf("child_modules prior_state data-doc: scope=%q want resource", f.AuthzScope)
				}
				return
			}
		}
	}
	t.Fatal("no object_storage flow")
}

func TestMixedResourceChangesWinsCollisionAccountScope(t *testing.T) {
	// Same data-doc address in RC (account *) and prior_state (resource ARN).
	// RC wins → account. A sibling literal grant matches the bucket so a flow exists.
	bucket := "collision-bucket"
	literal := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::` + bucket + `/*"]}]}`
	resources := []map[string]any{
		{
			"address": "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
			"change": map[string]any{"after": map[string]any{"name": "app"}},
		},
		{
			"address": "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
			"change": map[string]any{"after": map[string]any{
				"family":                "app",
				"container_definitions": `[{"name":"app","image":"app:1"}]`,
			}},
		},
		{
			"address": "aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task",
			"change": map[string]any{"after": map[string]any{"name": "task"}},
		},
		{
			"address": "aws_iam_role_policy.known", "mode": "managed", "type": "aws_iam_role_policy", "name": "known",
			"change": map[string]any{"after": map[string]any{"name": "known", "policy": literal}},
		},
		{
			"address": "aws_iam_role_policy.datadoc", "mode": "managed", "type": "aws_iam_role_policy", "name": "datadoc",
			"change": map[string]any{"after": map[string]any{"name": "d"}, "after_unknown": map[string]any{"policy": true}},
		},
		{
			"address": "aws_s3_bucket.uploads", "mode": "managed", "type": "aws_s3_bucket", "name": "uploads",
			"change": map[string]any{"after": map[string]any{"bucket": bucket}},
		},
		{
			"address": "data.aws_iam_policy_document.datadoc", "mode": "data", "type": "aws_iam_policy_document", "name": "datadoc",
			"change": map[string]any{"actions": []any{"read"}, "after": map[string]any{
				"statement": []any{map[string]any{
					"effect": "Allow", "actions": []any{"s3:PutObject"}, "resources": []any{"*"},
				}},
			}},
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
				"execution_role_arn": map[string]any{"references": []any{"aws_iam_role.task.arn", "aws_iam_role.task"}},
			},
		},
		{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task", "expressions": map[string]any{}},
		{
			"address": "aws_iam_role_policy.known", "type": "aws_iam_role_policy", "name": "known",
			"expressions": map[string]any{
				"role":   map[string]any{"references": []any{"aws_iam_role.task.id", "aws_iam_role.task"}},
				"policy": map[string]any{"constant_value": literal},
			},
		},
		{
			"address": "aws_iam_role_policy.datadoc", "type": "aws_iam_role_policy", "name": "datadoc",
			"expressions": map[string]any{
				"role":   map[string]any{"references": []any{"aws_iam_role.task.id", "aws_iam_role.task"}},
				"policy": map[string]any{"references": []any{"data.aws_iam_policy_document.datadoc.json", "data.aws_iam_policy_document.datadoc"}},
			},
		},
		{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": map[string]any{}},
		{"address": "data.aws_iam_policy_document.datadoc", "mode": "data", "type": "aws_iam_policy_document", "name": "datadoc", "expressions": map[string]any{}},
	}
	plan := map[string]any{
		"format_version":   "1.2",
		"resource_changes": resources,
		"configuration":    map[string]any{"root_module": map[string]any{"resources": cfg}},
		"planned_values":   map[string]any{"root_module": map[string]any{"resources": []any{}}},
		"prior_state": map[string]any{
			"values": map[string]any{
				"root_module": map[string]any{
					"resources": []any{
						map[string]any{
							"address": "data.aws_iam_policy_document.datadoc", "mode": "data",
							"type": "aws_iam_policy_document",
							"values": map[string]any{
								"statement": []any{map[string]any{
									"effect": "Allow", "actions": []any{"s3:PutObject"},
									"resources": []any{"arn:aws:s3:::" + bucket + "/*"},
								}},
							},
						},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	doc, _, err := Parse(raw, []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "t/collision", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		for _, el := range doc.Elements {
			if el.ID == f.To && el.Kind == "object_storage" {
				if f.AuthzScope != "account" {
					t.Fatalf("RC collision win: scope=%q want account (grants=%v)", f.AuthzScope, f.AuthzGrants)
				}
				if strings.Contains(strings.Join(f.AuthzGrants, ","), "resource") && f.AuthzScope != "account" {
					t.Fatalf("unexpected grants %v", f.AuthzGrants)
				}
				return
			}
		}
	}
	t.Fatal("no object_storage flow")
}
