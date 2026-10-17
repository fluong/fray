package client

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func parseCoveragePlan(t *testing.T, name string) (DFD, []string) {
	t.Helper()
	plan, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "fluong/fray", Commit: "coverage", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return doc, warnings
}

func elementByAddress(doc DFD, addr string) (Element, bool) {
	for _, el := range doc.Elements {
		if len(el.Evidence.Addresses) > 0 && el.Evidence.Addresses[0] == addr {
			return el, true
		}
	}
	return Element{}, false
}

func flowComputeToDB(doc DFD, fromAddr, toAddr string) *Flow {
	byID := map[string]Element{}
	for _, el := range doc.Elements {
		byID[el.ID] = el
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		from, ok1 := byID[f.From]
		to, ok2 := byID[f.To]
		if !ok1 || !ok2 {
			continue
		}
		if to.Kind != "relational_db" {
			continue
		}
		if len(from.Evidence.Addresses) == 0 || from.Evidence.Addresses[0] != fromAddr {
			continue
		}
		if len(to.Evidence.Addresses) == 0 || to.Evidence.Addresses[0] != toAddr {
			continue
		}
		return f
	}
	return nil
}

func flowLambdaToBucket(doc DFD, lambdaAddr, bucketAddr string) *Flow {
	byID := map[string]Element{}
	for _, el := range doc.Elements {
		byID[el.ID] = el
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		from, ok1 := byID[f.From]
		to, ok2 := byID[f.To]
		if !ok1 || !ok2 {
			continue
		}
		if len(from.Evidence.Addresses) == 0 || from.Evidence.Addresses[0] != lambdaAddr {
			continue
		}
		if len(to.Evidence.Addresses) == 0 || to.Evidence.Addresses[0] != bucketAddr {
			continue
		}
		return f
	}
	return nil
}

func hasClasses(classes []string, want ...string) bool {
	for _, w := range want {
		if !slices.Contains(classes, w) {
			return false
		}
	}
	return true
}

func TestCoverageDBControlDEFGH(t *testing.T) {
	doc, warnings := parseCoveragePlan(t, "coverage-db-control-plan.json")
	for _, w := range warnings {
		if strings.Contains(w, "db control-plane grant with unreadable Resource") &&
			strings.Contains(w, "app_db_control") {
			t.Fatalf("unexpected unreadable control warning: %s", w)
		}
	}

	t.Run("D_app_db_control", func(t *testing.T) {
		f := flowComputeToDB(doc, "aws_ecs_service.app", "aws_db_instance.main")
		if f == nil {
			t.Fatal("missing app→main flow")
		}
		if f.AuthzScope == "" {
			t.Fatal("want FR-028 authz_scope unchanged")
		}
		if f.AuthzDBControlScope != "resource" {
			t.Fatalf("control scope=%q want resource", f.AuthzDBControlScope)
		}
		wantD := []string{"reset_credentials", "snapshot_exfiltrate"}
		if !slices.Equal(f.AuthzDBControlClasses, wantD) {
			t.Fatalf("classes=%v want %v", f.AuthzDBControlClasses, wantD)
		}
		if f.Causes["authz_db_control_classes"] != "data.aws_iam_policy_document.app_db_control" {
			t.Fatalf("cause=%q", f.Causes["authz_db_control_classes"])
		}
	})
	t.Run("E_db_control_wildcard", func(t *testing.T) {
		f := flowComputeToDB(doc, "aws_ecs_service.db_control_wildcard", "aws_db_instance.main")
		if f == nil {
			t.Fatal("missing wildcard→main flow")
		}
		if f.AuthzScope != "" {
			t.Fatalf("authz_scope=%q want empty", f.AuthzScope)
		}
		if f.AuthzDBControlScope != "account" || len(f.AuthzDBControlClasses) != 4 {
			t.Fatalf("control scope=%q classes=%v", f.AuthzDBControlScope, f.AuthzDBControlClasses)
		}
	})
}

func TestCoverageLambdaS3FGH(t *testing.T) {
	doc, _ := parseCoveragePlan(t, "coverage-lambda-s3-plan.json")

	t.Run("F_b71_reader", func(t *testing.T) {
		f := flowLambdaToBucket(doc, "aws_lambda_function.b71_reader", "aws_s3_bucket.b71_one")
		if f == nil {
			t.Fatal("missing reader→b71_one flow")
		}
		if f.AuthzScope != "resource" {
			t.Fatalf("authz_scope=%q want resource", f.AuthzScope)
		}
	})
	t.Run("G_b71_dual", func(t *testing.T) {
		a := flowLambdaToBucket(doc, "aws_lambda_function.b71_dual", "aws_s3_bucket.b71_a")
		b := flowLambdaToBucket(doc, "aws_lambda_function.b71_dual", "aws_s3_bucket.b71_b")
		if a == nil || b == nil {
			t.Fatal("missing dual bucket flows")
		}
		if a.Causes["authz_scope"] != b.Causes["authz_scope"] {
			t.Fatalf("causes differ: %q vs %q", a.Causes["authz_scope"], b.Causes["authz_scope"])
		}
	})
	t.Run("H_b71_h", func(t *testing.T) {
		f := flowLambdaToBucket(doc, "aws_lambda_function.b71_h", "aws_s3_bucket.b71_h")
		if f == nil {
			t.Fatal("missing b71_h flow")
		}
		if f.AuthzScope != "account" {
			t.Fatalf("authz_scope=%q want account", f.AuthzScope)
		}
		if !strings.Contains(f.Causes["authz_scope"], "b71_h_readonly") {
			t.Fatalf("cause=%q want ReadOnly attachment", f.Causes["authz_scope"])
		}
	})
}

func TestDBControlUnreadableResourceWarningOnParse(t *testing.T) {
	src := &Element{Kind: "virtual_machine", Evidence: Evidence{Addresses: []string{"aws_ecs_service.app"}}}
	dest := &Element{Kind: "relational_db", Evidence: Evidence{Addresses: []string{"aws_db_instance.main"}}}
	resources := []planResource{
		{address: "aws_ecs_service.app", typ: "aws_ecs_service", values: map[string]any{"task_definition": "aws_ecs_task_definition.app"}},
		{address: "aws_ecs_task_definition.app", typ: "aws_ecs_task_definition", values: map[string]any{"family": "app"}},
		{address: "aws_iam_role.app", typ: "aws_iam_role", values: map[string]any{"name": "app"}},
		{address: "aws_iam_role_policy.app_ctl", typ: "aws_iam_role_policy", values: map[string]any{"name": "ctl", "role": "app", "policy": "{}"}},
		{address: "aws_db_instance.main", typ: "aws_db_instance", values: map[string]any{"arn": "arn:aws:rds:us-east-1:111122223333:db:main", "identifier": "main"}},
	}
	data := []planResource{
		iamPolicyDoc("data.aws_iam_policy_document.app_ctl", []iamStatement{
			{actions: []string{"rds:ModifyDBInstance"}, allow: true, resources: []any{nil}, doc: "data.aws_iam_policy_document.app_ctl"},
		}),
	}
	idx := configIndex{resources: map[string]exprSet{
		"aws_ecs_task_definition.app": {refs: map[string][]string{"task_role_arn": {"aws_iam_role.app.arn", "aws_iam_role.app"}}},
		"aws_iam_role_policy.app_ctl": {refs: map[string][]string{
			"role":   {"aws_iam_role.app.name", "aws_iam_role.app"},
			"policy": {"data.aws_iam_policy_document.app_ctl.json", "data.aws_iam_policy_document.app_ctl"},
		}},
	}}
	flow := &Flow{From: src.canonicalKey(), To: dest.canonicalKey()}
	var warnings []string
	attachDBControlPlane(flow, src, dest, resources, data, idx, []*Element{src, dest}, &warnings)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "db control-plane grant with unreadable Resource") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want unreadable control warning; got %v flow=%+v", warnings, flow)
	}
	if len(flow.AuthzDBControlClasses) != 0 {
		t.Fatalf("want control fields omitted; classes=%v", flow.AuthzDBControlClasses)
	}
}
