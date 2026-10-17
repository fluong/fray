package client

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func parseCoveragePlanModule(t *testing.T, planName, moduleDir string) (DFD, []string) {
	t.Helper()
	plan, err := os.ReadFile(filepath.Join("testdata", planName))
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "fluong/fray", Commit: "abcdef1234567890abcdef1234567890abcd", Tool: "terraform", Fidelity: "plan"}, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	return doc, warnings
}

func TestCoverageB72JsonencodeAndLocal(t *testing.T) {
	modDir := filepath.Join("testdata", "b72_hcl")
	doc, warnings := parseCoveragePlanModule(t, "coverage-b72-plan.json", modDir)

	t.Run("I_b72_jsonencode", func(t *testing.T) {
		f := flowLambdaToBucket(doc, "aws_lambda_function.b72_jsonencode", "aws_s3_bucket.b72_jsonencode")
		if f == nil {
			t.Fatal("missing lambda→bucket flow")
		}
		if f.AuthzScope != "resource" {
			t.Fatalf("authz_scope=%q want resource", f.AuthzScope)
		}
		if f.Causes["authz_scope"] != "aws_iam_role_policy.b72_jsonencode" {
			t.Fatalf("cause=%q want aws_iam_role_policy.b72_jsonencode", f.Causes["authz_scope"])
		}
	})
	t.Run("J_b72_local", func(t *testing.T) {
		_ = doc
		plan, err := os.ReadFile(filepath.Join("testdata", "coverage-b72-plan.json"))
		if err != nil {
			t.Fatal(err)
		}
		resources, err := loadResources(plan)
		if err != nil {
			t.Fatal(err)
		}
		idx, err := indexConfig(plan)
		if err != nil {
			t.Fatal(err)
		}
		idx.iamHCL, err = readRootIAMPolicyLiterals(modDir)
		if err != nil {
			t.Fatal(err)
		}
		docs, unknown, _ := roleDocuments("", []string{"aws_iam_role.b72_local"}, resources, nil, idx)
		if !unknown || len(docs) != 0 {
			t.Fatalf("want unknown unreadable policy; docs=%d unknown=%v", len(docs), unknown)
		}
		for _, w := range warnings {
			if strings.Contains(w, "b72_local") {
				t.Fatalf("unexpected warning: %s", w)
			}
		}
	})
}

func TestB72HCLNegativeConstructs(t *testing.T) {
	bucket := "neg-bucket"
	role := "aws_iam_role.task"
	idxBase := func(dir string) configIndex {
		hcl, err := readRootIAMPolicyLiterals(dir)
		if err != nil {
			t.Fatal(err)
		}
		return configIndex{resources: map[string]exprSet{}, iamHCL: hcl}
	}
	cases := []struct {
		name   string
		tf     string
		addr   string
		module string
	}{
		{name: "merge", addr: "aws_iam_role_policy.p", tf: `resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.task.id
  policy = merge(jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  }), {})
}`},
		{name: "for_expression", addr: "aws_iam_role_policy.p", tf: `resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [for x in ["s3:GetObject"] : {
      Effect   = "Allow"
      Action   = [x]
      Resource = "*"
    }]
  })
}`},
		{name: "conditional", addr: "aws_iam_role_policy.p", tf: `resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.task.id
  policy = true ? jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  }) : "{}"
}`},
		{name: "var_ref", addr: "aws_iam_role_policy.p", tf: `resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = var.x
    }]
  })
}`},
		{name: "count_index", addr: "aws_iam_role_policy.p[0]", tf: `resource "aws_iam_role_policy" "p" {
  count = 1
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  })
}`},
		{name: "module_policy", addr: "module.m.aws_iam_role_policy.p", module: "module.m", tf: `module "m" {
  source = "./modules/m"
}`},
		{name: "condition_ref", addr: "aws_iam_role_policy.p", tf: `resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = ["s3:GetObject"]
      Resource  = "*"
      Condition = { StringEquals = { "aws:SourceArn" = aws_s3_bucket.neg.arn } }
    }]
  })
}`},
		{name: "local_resource", addr: "aws_iam_role_policy.p", tf: `resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = local.x
    }]
  })
}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.name == "module_policy" {
				_ = os.MkdirAll(filepath.Join(dir, "modules", "m"), 0o755)
				writeTF(t, filepath.Join(dir, "modules", "m"), `resource "aws_iam_role_policy" "p" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  })
}`)
			}
			writeTF(t, dir, tc.tf)
			rp := planResource{
				address:      tc.addr,
				typ:          "aws_iam_role_policy",
				values:       map[string]any{},
				afterUnknown: map[string]any{"policy": true},
			}
			res := []planResource{
				{address: role, typ: "aws_iam_role", values: map[string]any{"name": "task"}},
				{address: "aws_s3_bucket.neg", typ: "aws_s3_bucket", values: map[string]any{"bucket": bucket}, afterUnknown: map[string]any{"arn": true}},
				rp,
			}
			idx := idxBase(dir)
			got, unk := resolvePolicyContent(rp, "policy", tc.module, nil, res, idx)
			if !unk || len(got) != 0 {
				t.Fatalf("want unknown; got docs=%d unknown=%v", len(got), unk)
			}
		})
	}
}

func TestB72HCLJSONEquivalence(t *testing.T) {
	bucket := "equiv-bucket"
	bucketARN := "arn:aws:s3:::" + bucket + "/*"
	knownJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["` + bucketARN + `"]}]}`
	denyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:DeleteObject"],"Resource":["` + bucketARN + `"]},{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["` + bucketARN + `"]}]}`
	condJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["` + bucketARN + `"],"Condition":{"StringEquals":{"aws:SourceAccount":"111122223333"}}}]}`
	cases := []struct {
		name string
		hcl  string
		json string
	}{
		{
			name: "allow",
			hcl: `resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject"]
      Resource = "${aws_s3_bucket.b.arn}/*"
    }]
  })
}`,
			json: knownJSON,
		},
		{
			name: "deny",
			hcl: `resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Deny"
        Action   = ["s3:DeleteObject"]
        Resource = "${aws_s3_bucket.b.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.b.arn}/*"
      },
    ]
  })
}`,
			json: denyJSON,
		},
		{
			name: "condition",
			hcl: `resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:PutObject"]
      Resource = "${aws_s3_bucket.b.arn}/*"
      Condition = { StringEquals = { "aws:SourceAccount" = "111122223333" } }
    }]
  })
}`,
			json: condJSON,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTF(t, dir, tc.hcl)
			resources := []planResource{
				{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "task"}},
				{address: "aws_s3_bucket.b", typ: "aws_s3_bucket", values: map[string]any{"bucket": bucket}, afterUnknown: map[string]any{"arn": true}},
				{address: "aws_lambda_function.fn", typ: "aws_lambda_function", values: map[string]any{
					"role": "arn:aws:iam::111122223333:role/task", "function_name": "fn",
				}},
				{address: "aws_iam_role_policy.p", typ: "aws_iam_role_policy", values: map[string]any{}, afterUnknown: map[string]any{"policy": true}},
				{address: "aws_iam_role_policy.known", typ: "aws_iam_role_policy", values: map[string]any{"policy": tc.json, "role": "task"}},
			}
			idx, err := readRootIAMPolicyLiterals(dir)
			if err != nil {
				t.Fatal(err)
			}
			ci := configIndex{iamHCL: idx, resources: map[string]exprSet{
				"aws_lambda_function.fn":    {refs: map[string][]string{"role": {"aws_iam_role.task.arn", "aws_iam_role.task"}}},
				"aws_iam_role_policy.p":     {refs: map[string][]string{"role": {"aws_iam_role.task.id", "aws_iam_role.task"}}},
				"aws_iam_role_policy.known": {refs: map[string][]string{"role": {"aws_iam_role.task.id", "aws_iam_role.task"}}},
			}}
			els := []*Element{
				{Kind: "virtual_machine", Evidence: Evidence{Addresses: []string{"aws_lambda_function.fn"}}},
				{Kind: "object_storage", Evidence: Evidence{Addresses: []string{"aws_s3_bucket.b"}}},
			}
			hclDocs, unk, _ := roleDocuments("", []string{"aws_iam_role.task"}, resources, nil, ci)
			if unk || len(hclDocs) == 0 {
				t.Fatalf("hcl docs unknown=%v len=%d", unk, len(hclDocs))
			}
			jsonResources := []planResource{
				resources[0],
				resources[1],
				{address: "aws_iam_role_policy.known", typ: "aws_iam_role_policy", values: map[string]any{"policy": tc.json, "role": "task"}},
			}
			jsonDocs, unk2, _ := roleDocuments("", []string{"aws_iam_role.task"}, jsonResources, nil, configIndex{resources: ci.resources})
			if unk2 {
				t.Fatal("known json should resolve")
			}
			hits1, grants1, actions1, cause1, _, warn1 := bucketsFromDocs(hclDocs, ci.resources["aws_lambda_function.fn"].refs["role"], resources, els)
			hits2, grants2, actions2, cause2, _, warn2 := bucketsFromDocs(jsonDocs, ci.resources["aws_lambda_function.fn"].refs["role"], resources, els)
			if len(hits1) != len(hits2) || len(hits1) != 1 {
				t.Fatalf("hits hcl=%d json=%d", len(hits1), len(hits2))
			}
			if !slices.Equal(grants1, grants2) || !slices.Equal(actions1, actions2) {
				t.Fatalf("hcl grants=%v actions=%v json grants=%v actions=%v (causes %q vs %q)",
					grants1, actions1, grants2, actions2, cause1, cause2)
			}
			if (cause1 == "") != (cause2 == "") {
				t.Fatalf("cause presence mismatch: %q vs %q", cause1, cause2)
			}
			if (warn1 == "") != (warn2 == "") {
				t.Fatalf("warn presence mismatch: %q vs %q", warn1, warn2)
			}
			if warn1 != "" && !strings.Contains(warn1, "Condition") {
				t.Fatalf("unexpected warn: %q", warn1)
			}
		})
	}
}

func TestB72S3ARNsynthesisGuardrails(t *testing.T) {
	t.Run("bucket_prefix_unknown", func(t *testing.T) {
		r := planResource{
			address: "aws_s3_bucket.pref",
			typ:     "aws_s3_bucket",
			values:  map[string]any{"bucket_prefix": "uploads-"},
			afterUnknown: map[string]any{
				"arn": true, "bucket": true,
			},
		}
		if _, ok := planRootResourceAttr("aws_s3_bucket.pref.arn", []planResource{r}); ok {
			t.Fatal("want no synthesis for bucket_prefix-only bucket")
		}
	})
	t.Run("cn_north_1_unknown", func(t *testing.T) {
		r := planResource{
			address: "aws_s3_bucket.cn",
			typ:     "aws_s3_bucket",
			values: map[string]any{
				"bucket": "my-bucket",
				"region": "cn-north-1",
			},
			afterUnknown: map[string]any{"arn": true},
		}
		if _, ok := planRootResourceAttr("aws_s3_bucket.cn.arn", []planResource{r}); ok {
			t.Fatal("want no synthesis in cn-* region")
		}
	})
	t.Run("known_bucket_us_east", func(t *testing.T) {
		r := planResource{
			address: "aws_s3_bucket.ok",
			typ:     "aws_s3_bucket",
			values: map[string]any{
				"bucket": "my-bucket",
				"region": "us-east-1",
			},
			afterUnknown: map[string]any{"arn": true},
		}
		got, ok := planRootResourceAttr("aws_s3_bucket.ok.arn", []planResource{r})
		if !ok || got != "arn:aws:s3:::my-bucket" {
			t.Fatalf("got %q ok=%v", got, ok)
		}
	})
}

func TestB72FR046JsonencodeRDS(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, `resource "aws_iam_role_policy" "snap" {
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["rds:CreateDBSnapshot"]
      Resource = "${aws_db_instance.main.arn}"
    }]
  })
}`)
	instARN := "arn:aws:rds:us-east-1:111122223333:db:main"
	resources := []planResource{
		{address: "aws_iam_role.task", typ: "aws_iam_role", values: map[string]any{"name": "task"}},
		{address: "aws_db_instance.main", typ: "aws_db_instance", values: map[string]any{"arn": instARN, "identifier": "main"}},
		{address: "aws_ecs_service.app", typ: "aws_ecs_service", values: map[string]any{"task_definition": "aws_ecs_task_definition.app"}},
		{address: "aws_ecs_task_definition.app", typ: "aws_ecs_task_definition", values: map[string]any{"family": "app", "task_role_arn": "arn:aws:iam::111122223333:role/task"}},
		{address: "aws_iam_role_policy.snap", typ: "aws_iam_role_policy", values: map[string]any{"role": "task"}, afterUnknown: map[string]any{"policy": true}},
	}
	idx, err := readRootIAMPolicyLiterals(dir)
	if err != nil {
		t.Fatal(err)
	}
	ci := configIndex{
		iamHCL: idx,
		resources: map[string]exprSet{
			"aws_ecs_task_definition.app": {refs: map[string][]string{"task_role_arn": {"aws_iam_role.task.arn", "aws_iam_role.task"}}},
			"aws_iam_role_policy.snap": {refs: map[string][]string{
				"role": {"aws_iam_role.task.id", "aws_iam_role.task"},
			}},
		},
	}
	src := &Element{Kind: "virtual_machine", Evidence: Evidence{Addresses: []string{"aws_ecs_service.app"}}}
	dest := &Element{Kind: "relational_db", Evidence: Evidence{Addresses: []string{"aws_db_instance.main"}}}
	flow := &Flow{From: src.canonicalKey(), To: dest.canonicalKey()}
	attachDBControlPlane(flow, src, dest, resources, nil, ci, []*Element{src, dest}, nil)
	if flow.AuthzDBControlScope != "resource" {
		t.Fatalf("scope=%q want resource", flow.AuthzDBControlScope)
	}
	if !slices.Contains(flow.AuthzDBControlClasses, "snapshot_exfiltrate") {
		t.Fatalf("classes=%v want snapshot_exfiltrate", flow.AuthzDBControlClasses)
	}
	if flow.Causes["authz_db_control_classes"] != "aws_iam_role_policy.snap" {
		t.Fatalf("cause=%q", flow.Causes["authz_db_control_classes"])
	}
}
