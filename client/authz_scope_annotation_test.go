package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fluong/fray/schema/validate"
	"gopkg.in/yaml.v3"
)

func TestAuthzScopeAnnotationFill(t *testing.T) {
	src := Source{Repo: "t/b61", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}
	reason := "rds-db:connect scoped via managed policy arn:aws:iam::123:policy/app-db"

	t.Run("secret resource mitigated", func(t *testing.T) {
		f := fillScope(t, secretUnknownDocsPlan(t), "fray.yaml", src, `
  flows:
    - from: aws_secretsmanager_secret.db
      to: aws_ecs_service.app
      authz_scope: resource
      reason: "`+reason+`"
`, "credentials")
		if f.AuthzScope != "resource" || !slices.Equal(f.AuthzGrants, []string{"resource"}) {
			t.Fatalf("scope=%q grants=%v; resource is the mitigated verdict", f.AuthzScope, f.AuthzGrants)
		}
		if f.AuthzScopeSource != authzScopeSourceDeclared {
			t.Fatalf("authz_scope_source=%q want declared", f.AuthzScopeSource)
		}
	})

	t.Run("secret account open", func(t *testing.T) {
		f := fillScope(t, secretUnknownDocsPlan(t), "fray.yaml", src, `
  flows:
    - from: aws_secretsmanager_secret.db
      to: aws_ecs_service.app
      authz_scope: account
      reason: "`+reason+`"
`, "credentials")
		if f.AuthzScope != "account" || !slices.Equal(f.AuthzGrants, []string{"account"}) {
			t.Fatalf("scope=%q grants=%v", f.AuthzScope, f.AuthzGrants)
		}
		want := "fray.yaml#aws_secretsmanager_secret.db -> aws_ecs_service.app credentials"
		if f.Causes["authz_scope"] != want {
			t.Fatalf("cause %q", f.Causes["authz_scope"])
		}
		if f.Causes["secret_delivery"] == "" {
			t.Fatal("secret_delivery cause cleared")
		}
	})

	t.Run("bucket resource mitigated", func(t *testing.T) {
		f := fillScope(t, bucketUnknownDocsPlan(t), "infra/fray.yaml", src, `
  flows:
    - from: aws_ecs_service.app
      to: aws_s3_bucket.uploads
      authz_scope: resource
      reason: "`+reason+`"
`, "unknown")
		if f.AuthzScope != "resource" {
			t.Fatalf("scope=%q", f.AuthzScope)
		}
		want := "infra/fray.yaml#aws_ecs_service.app -> aws_s3_bucket.uploads unknown"
		if f.Causes["authz_scope"] != want {
			t.Fatalf("cause %q", f.Causes["authz_scope"])
		}
	})

	t.Run("bucket account open", func(t *testing.T) {
		f := fillScope(t, bucketUnknownDocsPlan(t), "fray.yaml", src, `
  flows:
    - from: aws_ecs_service.app
      to: aws_s3_bucket.uploads
      authz_scope: account
      reason: "`+reason+`"
`, "unknown")
		if f.AuthzScope != "account" {
			t.Fatalf("scope=%q want account (open)", f.AuthzScope)
		}
	})

	t.Run("db resource mitigated", func(t *testing.T) {
		f := fillScope(t, dbAuthzECSPlan(t, "", true), "fray.yaml", src, `
  flows:
    - from: module.ecs.aws_ecs_service.this
      to: module.db.aws_db_instance.this
      authz_scope: resource
      reason: "`+reason+`"
`, "unknown")
		if f.AuthzScope != "resource" || !slices.Equal(f.AuthzGrants, []string{"resource"}) {
			t.Fatalf("scope=%q grants=%v", f.AuthzScope, f.AuthzGrants)
		}
	})

	t.Run("db account open fingerprint", func(t *testing.T) {
		f := fillScope(t, dbAuthzECSPlan(t, "", true), "fray.yaml", src, `
  flows:
    - from: module.ecs.aws_ecs_service.this
      to: module.db.aws_db_instance.this
      data_class: unknown
      authz_scope: account
      reason: "`+reason+`"
`, "unknown")
		if f.AuthzScope != "account" {
			t.Fatalf("scope=%q want account (open)", f.AuthzScope)
		}
		cause := "fray.yaml#module.ecs.aws_ecs_service.this -> module.db.aws_db_instance.this unknown"
		if f.Causes["authz_scope"] != cause {
			t.Fatalf("cause %q", f.Causes["authz_scope"])
		}
		// partialFingerprints["fray/v1"] is sha256("FR-028|" + cause).
		sum := sha256.Sum256([]byte("FR-028|" + cause))
		const wantFP = "ffd2bfe4d245ccaf71bf391b63da35aed40ef6927ef7395037433dcf335cd839"
		if got := hex.EncodeToString(sum[:]); got != wantFP {
			t.Fatalf("fingerprint %s", got)
		}
	})
}

func TestAuthzScopeAnnotationIgnored(t *testing.T) {
	src := Source{Repo: "t/b61", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}
	plan := dbAuthzECSPlan(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["rds-db:connect"],"Resource":["arn:aws:rds-db:us-east-1:111122223333:dbuser:db-ABCDEF/app"]}]}`, false)
	plain := []byte("schema_version: fray-config/v1\n")
	base, _, err := Parse([]byte(plan), plain, "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings, err := Parse([]byte(plan), []byte(`schema_version: fray-config/v1
annotations:
  flows:
    - from: module.ecs.aws_ecs_service.this
      to: module.db.aws_db_instance.this
      authz_scope: resource
      reason: "parser already derived resource from the task role"
`), "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	wantWarn := "fray.yaml annotation ignored: module.ecs.aws_ecs_service.this -> module.db.aws_db_instance.this already has derived authz_scope resource; remove the annotation, or use .fray/waivers.yml to accept a wider grant"
	if !slices.Contains(warnings, wantWarn) {
		t.Fatalf("warnings: %s", strings.Join(warnings, "\n"))
	}
	baseJSON, err := Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	gotJSON, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(baseJSON, gotJSON) {
		t.Fatal("derived scope annotation changed the DFD")
	}

	app := &Element{Provenance: "iac", Evidence: Evidence{Addresses: []string{"aws_ecs_service.app"}}}
	db := &Element{Provenance: "iac", Evidence: Evidence{Addresses: []string{"aws_db_instance.main"}}}
	elements := []*Element{app, db}
	flows := []*Flow{
		{From: app.canonicalKey(), To: db.canonicalKey(), DataClass: "unknown"},
		{From: app.canonicalKey(), To: db.canonicalKey(), DataClass: "credentials"},
	}
	before := []Flow{*flows[0], *flows[1]}
	var noted []string
	cfg := frayConfig{SchemaVersion: "fray-config/v1", Annotations: frayAnnotations{Flows: []frayFlowAnnotation{{
		From: "aws_ecs_service.app", To: "aws_db_instance.main", AuthzScope: "account",
		Reason: "two parser flows share these endpoints",
	}}}}
	if err := applyFlowAnnotations(flows, elements, cfg, "fray.yaml", &noted); err != nil {
		t.Fatalf("two matches failed the scan: %v", err)
	}
	if !slices.Contains(noted, "fray.yaml annotation ignored: aws_ecs_service.app -> aws_db_instance.main matched 2 flows; set data_class to disambiguate, or declare a new flow under flows") {
		t.Fatalf("warnings: %s", strings.Join(noted, "\n"))
	}
	if flows[0].AuthzScope != before[0].AuthzScope || flows[1].AuthzScope != before[1].AuthzScope || flows[0].DataClass != before[0].DataClass || flows[1].DataClass != before[1].DataClass {
		t.Fatalf("flows changed: %#v %#v", flows[0], flows[1])
	}

	noted = nil
	if err := applyFlowAnnotations(nil, elements, frayConfig{Annotations: frayAnnotations{Flows: []frayFlowAnnotation{{
		From: "aws_ecs_service.app", To: "aws_db_instance.main", DataClass: "unknown", AuthzScope: "account",
		Reason: "no parser flow between these resources",
	}}}}, "fray.yaml", &noted); err != nil {
		t.Fatalf("zero matches failed the scan: %v", err)
	}
	if !slices.Contains(noted, "fray.yaml annotation ignored: aws_ecs_service.app -> aws_db_instance.main unknown matched no parser flow; set data_class to disambiguate, or declare a new flow under flows") {
		t.Fatalf("warnings: %s", strings.Join(noted, "\n"))
	}

	one := []*Flow{
		{From: app.canonicalKey(), To: db.canonicalKey(), DataClass: "unknown"},
		{From: app.canonicalKey(), To: db.canonicalKey(), DataClass: "credentials"},
	}
	noted = nil
	if err := applyFlowAnnotations(one, elements, frayConfig{Annotations: frayAnnotations{Flows: []frayFlowAnnotation{{
		From: "aws_ecs_service.app", To: "aws_db_instance.main", DataClass: "credentials",
		AuthzScope: "resource", Reason: "only the credentials flow is declared",
	}}}}, "fray.yaml", &noted); err != nil {
		t.Fatal(err)
	}
	if len(noted) != 0 {
		t.Fatalf("disambiguation warnings: %s", strings.Join(noted, "\n"))
	}
	if one[0].AuthzScope != "" || one[1].AuthzScope != "resource" {
		t.Fatalf("disambiguation scopes %q %q", one[0].AuthzScope, one[1].AuthzScope)
	}
	if one[1].Causes["authz_scope"] != "fray.yaml#aws_ecs_service.app -> aws_db_instance.main credentials" {
		t.Fatalf("cause %q", one[1].Causes["authz_scope"])
	}
	if one[1].AuthzScopeSource != authzScopeSourceDeclared {
		t.Fatalf("authz_scope_source=%q want declared", one[1].AuthzScopeSource)
	}

	// data_class-only annotations still rewrite the class and need no reason.
	only := []*Flow{{From: app.canonicalKey(), To: db.canonicalKey(), DataClass: "unknown"}}
	if err := applyFlowAnnotations(only, elements, frayConfig{Annotations: frayAnnotations{Flows: []frayFlowAnnotation{{
		From: "aws_ecs_service.app", To: "aws_db_instance.main", DataClass: "customer_data",
	}}}}, "fray.yaml", &noted); err != nil {
		t.Fatal(err)
	}
	if only[0].DataClass != "customer_data" || only[0].AuthzScope != "" {
		t.Fatalf("data_class-only: class=%q scope=%q", only[0].DataClass, only[0].AuthzScope)
	}
}

func TestAuthzScopeAnnotationSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "schema", "fray-config.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := validate.CompileBytes("fray-config.schema.json", raw)
	if err != nil {
		t.Fatal(err)
	}
	reason := "rds-db:connect scoped via managed policy app-db"
	valid := map[string]any{
		"schema_version": "fray-config/v1",
		"annotations": map[string]any{"flows": []any{map[string]any{
			"from": "aws_ecs_service.app", "to": "aws_db_instance.main",
			"authz_scope": "resource", "reason": reason,
		}}},
	}
	if err := validate.Schema(schema, mustJSON(t, valid)); err != nil {
		t.Fatal(err)
	}
	// data_class-only stays valid without reason.
	classOnly := map[string]any{
		"schema_version": "fray-config/v1",
		"annotations": map[string]any{"flows": []any{map[string]any{
			"from": "aws_ecs_service.app", "to": "aws_s3_bucket.uploads",
			"data_class": "customer_data",
		}}},
	}
	if err := validate.Schema(schema, mustJSON(t, classOnly)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "short"} {
		t.Run(name, func(t *testing.T) {
			ann := map[string]any{
				"from": "aws_ecs_service.app", "to": "aws_db_instance.main",
				"authz_scope": "resource",
			}
			if name == "short" {
				ann["reason"] = "too short"
			}
			doc := map[string]any{
				"schema_version": "fray-config/v1",
				"annotations":    map[string]any{"flows": []any{ann}},
			}
			err := validate.Schema(schema, mustJSON(t, doc))
			if err == nil {
				t.Fatal("want schema error")
			}
		})
	}
	// YAML documents the Action would load must fail the same schema.
	shortYAML := []byte("schema_version: fray-config/v1\nannotations:\n  flows:\n    - from: aws_ecs_service.app\n      to: aws_db_instance.main\n      authz_scope: account\n      reason: short\n")
	var node any
	if err := yaml.Unmarshal(shortYAML, &node); err != nil {
		t.Fatal(err)
	}
	if err := validate.Schema(schema, mustJSON(t, node)); err == nil {
		t.Fatal("short reason yaml: want schema error")
	}
}

func fillScope(t *testing.T, plan, path string, src Source, flowsYAML, class string) Flow {
	t.Helper()
	cfg := "schema_version: fray-config/v1\nannotations:\n" + flowsYAML
	doc, _, err := Parse([]byte(plan), []byte(cfg), path, src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var hits []Flow
	for _, f := range doc.Flows {
		if f.DataClass == class && f.AuthzScope != "" {
			hits = append(hits, f)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("filled flows: %d", len(hits))
	}
	return hits[0]
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func secretUnknownDocsPlan(t *testing.T) string {
	t.Helper()
	defs := `[{"name":"app","image":"app:1","secrets":[{"name":"DB","valueFrom":"aws_secretsmanager_secret.db.arn"}]}]`
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
			},
			map[string]any{
				"address": "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"family": "app", "container_definitions": defs,
				}, "after_unknown": map[string]any{"execution_role_arn": true}},
			},
			map[string]any{
				"address": "aws_iam_role.exec", "mode": "managed", "type": "aws_iam_role", "name": "exec",
				"change": map[string]any{
					"actions": []any{"create"}, "after": map[string]any{"name": "exec"},
					"after_unknown": map[string]any{"managed_policy_arns": true},
				},
			},
			map[string]any{
				"address": "aws_secretsmanager_secret.db", "mode": "managed", "type": "aws_secretsmanager_secret", "name": "db",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "db"}},
			},
		},
		"configuration": map[string]any{"root_module": map[string]any{"resources": []any{
			map[string]any{"address": "aws_ecs_service.app", "type": "aws_ecs_service", "name": "app", "expressions": map[string]any{
				"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.app.arn"}},
			}},
			map[string]any{"address": "aws_ecs_task_definition.app", "type": "aws_ecs_task_definition", "name": "app", "expressions": map[string]any{
				"execution_role_arn": map[string]any{"references": []any{"aws_iam_role.exec.arn", "aws_iam_role.exec"}},
			}},
			map[string]any{"address": "aws_iam_role.exec", "type": "aws_iam_role", "name": "exec", "expressions": map[string]any{
				"managed_policy_arns": map[string]any{"references": []any{"aws_iam_policy.unread.arn", "aws_iam_policy.unread"}},
			}},
			map[string]any{"address": "aws_secretsmanager_secret.db", "type": "aws_secretsmanager_secret", "name": "db", "expressions": map[string]any{}},
		}}},
	}
	return mustPlan(t, plan)
}

func bucketUnknownDocsPlan(t *testing.T) string {
	t.Helper()
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::uploads/*"]}]}`
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
			},
			map[string]any{
				"address": "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"family": "app", "container_definitions": `[{"name":"app","image":"app:1"}]`,
				}, "after_unknown": map[string]any{"task_role_arn": true}},
			},
			map[string]any{
				"address": "aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task",
				"change": map[string]any{
					"actions": []any{"create"}, "after": map[string]any{"name": "task"},
					"after_unknown": map[string]any{"managed_policy_arns": true},
				},
			},
			map[string]any{
				"address": "aws_iam_role_policy.s3", "mode": "managed", "type": "aws_iam_role_policy", "name": "s3",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "s3", "policy": policy}},
			},
			map[string]any{
				"address": "aws_s3_bucket.uploads", "mode": "managed", "type": "aws_s3_bucket", "name": "uploads",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"bucket": "uploads"}},
			},
		},
		"configuration": map[string]any{"root_module": map[string]any{"resources": []any{
			map[string]any{"address": "aws_ecs_service.app", "type": "aws_ecs_service", "name": "app", "expressions": map[string]any{
				"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.app.arn"}},
			}},
			map[string]any{"address": "aws_ecs_task_definition.app", "type": "aws_ecs_task_definition", "name": "app", "expressions": map[string]any{
				"task_role_arn": map[string]any{"references": []any{"aws_iam_role.task.arn", "aws_iam_role.task"}},
			}},
			map[string]any{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task", "expressions": map[string]any{
				"managed_policy_arns": map[string]any{"references": []any{"aws_iam_policy.unread.arn"}},
			}},
			map[string]any{"address": "aws_iam_role_policy.s3", "type": "aws_iam_role_policy", "name": "s3", "expressions": map[string]any{
				"role":   map[string]any{"references": []any{"aws_iam_role.task.id", "aws_iam_role.task"}},
				"policy": map[string]any{"constant_value": policy},
			}},
			map[string]any{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": map[string]any{}},
		}}},
	}
	return mustPlan(t, plan)
}

func mustPlan(t *testing.T, plan map[string]any) string {
	t.Helper()
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
