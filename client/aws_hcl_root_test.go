package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// B-49: root-module aws_ecs_task_definition HCL fallback when
// container_definitions is unknown at plan.

func TestB49RootHCLSecretManagerJSONEncode(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, `resource "aws_ecs_task_definition" "app" {
  family = "app"
  container_definitions = jsonencode([{
    name  = "app"
    image = "app:1"
    secrets = [{
      name      = "DB"
      valueFrom = aws_secretsmanager_secret.app.arn
    }]
  }])
}
`)
	known := parseECSPlanDir(t, rootAppSecretPlan(t, `[{"name":"app","image":"app:1","secrets":[{"name":"DB","valueFrom":"aws_secretsmanager_secret.app.arn"}]}]`, false), t.TempDir())
	unknown := parseECSPlanDir(t, rootAppSecretPlan(t, "", true), dir)
	knownFlows := secretDeliveryFlows(known)
	unknownFlows := secretDeliveryFlows(unknown)
	if len(knownFlows) != 1 {
		t.Fatalf("known-JSON flows=%d want 1", len(knownFlows))
	}
	if len(unknownFlows) != 1 {
		t.Fatalf("unknown+HCL flows=%d want 1", len(unknownFlows))
	}
	assertSecretFragmentEqual(t, knownFlows[0], unknownFlows[0])
	if addr := secretFlowFromAddr(unknown, unknownFlows[0]); addr != "aws_secretsmanager_secret.app" {
		t.Fatalf("matched %q want aws_secretsmanager_secret.app", addr)
	}
}

func TestB49RootHCLSSMParameterOmits(t *testing.T) {
	// aws_ssm_parameter is not modeled as a secret_store element today;
	// HCL valueFrom must omit (no invented element).
	dir := t.TempDir()
	writeTF(t, dir, `resource "aws_ecs_task_definition" "app" {
  family = "app"
  container_definitions = jsonencode([{
    name  = "app"
    image = "app:1"
    secrets = [{
      name      = "P"
      valueFrom = aws_ssm_parameter.p.arn
    }]
  }])
}
`)
	baseline := parseECSPlanDir(t, rootAppSecretPlan(t, `[{"name":"app","image":"app:1"}]`, false), t.TempDir())
	doc := parseECSPlanDir(t, rootAppSecretPlan(t, "", true), dir)
	if len(doc.Elements) != len(baseline.Elements) {
		t.Fatalf("elements=%d want %d", len(doc.Elements), len(baseline.Elements))
	}
	if flows := secretDeliveryFlows(doc); len(flows) != 0 {
		t.Fatalf("SSM valueFrom flows=%d want 0", len(flows))
	}
}

func TestB49PlanKnownWinsOverDifferingHCL(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, `resource "aws_ecs_task_definition" "app" {
  family = "app"
  container_definitions = jsonencode([{
    name  = "app"
    image = "app:1"
    secrets = [{
      name      = "DB"
      valueFrom = aws_secretsmanager_secret.app.arn
    }]
  }])
}
`)
	// Plan known JSON has no secrets; HCL has a secret — plan wins → omit.
	doc := parseECSPlanDir(t, rootAppSecretPlan(t, `[{"name":"app","image":"app:1"}]`, false), dir)
	if flows := secretDeliveryFlows(doc); len(flows) != 0 {
		t.Fatalf("plan-known wins: flows=%d want 0", len(flows))
	}
}

func TestB49RootHCLCountOmits(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, `resource "aws_ecs_task_definition" "app" {
  count  = 2
  family = "app"
  container_definitions = jsonencode([{
    name  = "app"
    image = "app:1"
    secrets = [{
      name      = "DB"
      valueFrom = aws_secretsmanager_secret.app.arn
    }]
  }])
}
`)
	doc := parseECSPlanDir(t, rootAppSecretPlan(t, "", true), dir)
	if flows := secretDeliveryFlows(doc); len(flows) != 0 {
		t.Fatalf("count block: flows=%d want 0", len(flows))
	}
}

func TestB49RootHCLLocalFileTemplatefileOmit(t *testing.T) {
	for _, expr := range []string{
		`local.defs`,
		`file("x.json")`,
		`templatefile("x.tftpl", {})`,
	} {
		t.Run(expr, func(t *testing.T) {
			dir := t.TempDir()
			writeTF(t, dir, `resource "aws_ecs_task_definition" "app" {
  family                = "app"
  container_definitions = `+expr+`
}
`)
			doc := parseECSPlanDir(t, rootAppSecretPlan(t, "", true), dir)
			if flows := secretDeliveryFlows(doc); len(flows) != 0 {
				t.Fatalf("%s: flows=%d want 0", expr, len(flows))
			}
		})
	}
}

func TestB49RootHCLDataSecretOmits(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, `resource "aws_ecs_task_definition" "app" {
  family = "app"
  container_definitions = jsonencode([{
    name  = "app"
    image = "app:1"
    secrets = [{
      name      = "DB"
      valueFrom = data.aws_secretsmanager_secret.x.arn
    }]
  }])
}
`)
	baseline := parseECSPlanDir(t, rootAppSecretPlan(t, `[{"name":"app","image":"app:1"}]`, false), t.TempDir())
	doc := parseECSPlanDir(t, rootAppSecretPlan(t, "", true), dir)
	if len(doc.Elements) != len(baseline.Elements) {
		t.Fatalf("elements=%d want %d", len(doc.Elements), len(baseline.Elements))
	}
	if flows := secretDeliveryFlows(doc); len(flows) != 0 {
		t.Fatalf("data.* valueFrom flows=%d want 0", len(flows))
	}
}

func TestB49ModuleContainersObjectFormByteIdentical(t *testing.T) {
	// Module path keeps object/map form: readRootContainers and
	// parseContainersObject agree byte-for-byte on the same expression.
	dir := t.TempDir()
	writeTF(t, dir, `module "ecs" {
  source = "./ecs"
  container_definitions = {
    app = {
      essential = true
      image     = "app:1"
      secrets = [{
        name      = "DB"
        valueFrom = aws_secretsmanager_secret.app.arn
      }]
      environment = [{
        name  = "HOST"
        value = "db.example"
      }]
    }
  }
}
`)
	fromRoot, err := readRootContainers(dir)
	if err != nil {
		t.Fatal(err)
	}
	fromExpr := map[string][]containerSpec{}
	src, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	file, diags := hclsyntax.ParseConfig(src, filepath.Join(dir, "main.tf"), hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		t.Fatal("expected hclsyntax.Body")
	}
	for _, block := range body.Blocks {
		if block.Type != "module" || len(block.Labels) != 1 {
			continue
		}
		attr, ok := block.Body.Attributes["container_definitions"]
		if !ok {
			t.Fatal("missing container_definitions")
		}
		specs, ok := parseContainersObject(attr.Expr)
		if !ok {
			t.Fatal("parseContainersObject failed on module object form")
		}
		fromExpr["module."+block.Labels[0]] = specs
	}
	a, err := json.Marshal(encodeContainerMap(fromRoot))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(encodeContainerMap(fromExpr))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("readRootContainers=%s parseContainersObject=%s", a, b)
	}
	want := `{"module.ecs":[{"image":"app:1","image_ok":true,"secrets":["aws_secretsmanager_secret.app.arn"]}]}`
	if string(a) != want {
		t.Fatalf("module HCL specs=%s want %s", a, want)
	}
}

func TestB49ModuleJSONEncodeOmits(t *testing.T) {
	// Module-call path must not accept jsonencode([...]) (pre-B-49 behavior).
	dir := t.TempDir()
	writeTF(t, dir, `module "ecs" {
  source = "./ecs"
  container_definitions = jsonencode([{
    name  = "app"
    image = "app:1"
    secrets = [{
      name      = "DB"
      valueFrom = aws_secretsmanager_secret.app.arn
    }]
  }])
}
`)
	got, err := readRootContainers(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("module jsonencode: got %v want omit", got)
	}
}

func TestB49RootDuplicateTaskDefOmits(t *testing.T) {
	// Two .tf files declaring the same resource name → omit (never pick one).
	// Asserted on readRootTaskDefinitionContainers; full Parse also rejects
	// duplicate resources via the lifecycle index.
	dir := t.TempDir()
	src := `resource "aws_ecs_task_definition" "app" {
  family = "app"
  container_definitions = jsonencode([{
    name  = "app"
    image = "app:1"
    secrets = [{
      name      = "DB"
      valueFrom = aws_secretsmanager_secret.app.arn
    }]
  }])
}
`
	if err := os.WriteFile(filepath.Join(dir, "a.tf"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.tf"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readRootTaskDefinitionContainers(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("duplicate root blocks: got %v want omit", got)
	}
}

type containerSpecJSON struct {
	Image   string   `json:"image"`
	ImageOK bool     `json:"image_ok"`
	Secrets []string `json:"secrets"`
}

func encodeContainerMap(in map[string][]containerSpec) map[string][]containerSpecJSON {
	out := map[string][]containerSpecJSON{}
	for k, specs := range in {
		for _, s := range specs {
			out[k] = append(out[k], containerSpecJSON{Image: s.image, ImageOK: s.imageOK, Secrets: s.secrets})
		}
	}
	return out
}

func parseECSPlanDir(t *testing.T, plan, moduleDir string) DFD {
	t.Helper()
	doc, _, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "t/ecs", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func writeTF(t *testing.T, dir, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertSecretFragmentEqual(t *testing.T, a, b Flow) {
	t.Helper()
	if a.SecretDelivery != b.SecretDelivery || a.DataClass != b.DataClass ||
		a.Transport != b.Transport || a.AuthzScope != b.AuthzScope {
		t.Fatalf("fragment a delivery=%q class=%q transport=%q scope=%q; b delivery=%q class=%q transport=%q scope=%q",
			a.SecretDelivery, a.DataClass, a.Transport, a.AuthzScope,
			b.SecretDelivery, b.DataClass, b.Transport, b.AuthzScope)
	}
}

// rootAppSecretPlan is like rootModuleSecretPlan but with a root-module secret
// aws_secretsmanager_secret.app (for unqualified HCL traversals).
func rootAppSecretPlan(t *testing.T, containerDefs string, unknown bool) string {
	t.Helper()
	secretARN := "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db-AbCdEf"
	after := map[string]any{"family": "app"}
	afterUnknown := map[string]any{"task_role_arn": true, "execution_role_arn": true}
	if unknown {
		afterUnknown["container_definitions"] = true
	} else {
		after["container_definitions"] = containerDefs
	}
	execPol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["secretsmanager:GetSecretValue"],"Resource":["` + secretARN + `"]}]}`
	resources := []map[string]any{
		{
			"address": "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
		},
		{
			"address": "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": after, "after_unknown": afterUnknown},
		},
		{
			"address": "aws_iam_role.exec", "mode": "managed", "type": "aws_iam_role", "name": "exec",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "exec"}},
		},
		{
			"address": "aws_iam_role_policy.exec_secrets", "mode": "managed", "type": "aws_iam_role_policy", "name": "exec_secrets",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "exec-secrets", "policy": execPol}},
		},
		{
			"address": "aws_secretsmanager_secret.app", "mode": "managed", "type": "aws_secretsmanager_secret", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app/db", "arn": secretARN}},
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
			},
		},
		{"address": "aws_iam_role.exec", "type": "aws_iam_role", "name": "exec", "expressions": map[string]any{}},
		{
			"address": "aws_iam_role_policy.exec_secrets", "type": "aws_iam_role_policy", "name": "exec_secrets",
			"expressions": map[string]any{
				"role":   map[string]any{"references": []any{"aws_iam_role.exec.name", "aws_iam_role.exec"}},
				"policy": map[string]any{"constant_value": execPol},
			},
		},
		{"address": "aws_secretsmanager_secret.app", "type": "aws_secretsmanager_secret", "name": "app", "expressions": map[string]any{}},
	}
	root := map[string]any{
		"format_version":   "1.2",
		"resource_changes": resources,
		"configuration":    map[string]any{"root_module": map[string]any{"resources": cfg}},
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
