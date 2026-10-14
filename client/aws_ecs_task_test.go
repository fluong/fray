package client

import (
	"encoding/json"
	"strings"
	"testing"
)

// B-44 / B-43: ECS task definition → S3 flows and root-module container_definitions.

func ecsMultiTaskPlan(t *testing.T, opts ecsMultiOpts) string {
	t.Helper()
	type taskSpec struct {
		name, role, bucket string
		roleUnknown        bool
		emitRole, emitBkt  bool
	}
	tasks := []taskSpec{
		{name: "a", role: "role_a", bucket: opts.bucketA, emitRole: true, emitBkt: true},
		{name: "b", role: "role_b", bucket: opts.bucketB, emitRole: true, emitBkt: opts.bucketB != opts.bucketA},
	}
	if opts.shareRole {
		tasks[1].role = "role_a"
		tasks[1].emitRole = false
		tasks[1].bucket = opts.bucketA
		tasks[1].emitBkt = false
	}
	if opts.bRoleUnknown {
		tasks[1].roleUnknown = true
	}

	var resources []map[string]any
	var cfg []map[string]any
	emittedRole := map[string]bool{}
	emittedBkt := map[string]bool{}

	for _, ts := range tasks {
		svcName := "svc_" + ts.name
		taskName := "task_" + ts.name
		resources = append(resources,
			map[string]any{
				"address": "aws_ecs_service." + svcName, "mode": "managed", "type": "aws_ecs_service", "name": svcName,
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": svcName}},
			},
			map[string]any{
				"address": "aws_ecs_task_definition." + taskName, "mode": "managed", "type": "aws_ecs_task_definition", "name": taskName,
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"family":                taskName,
					"container_definitions": `[{"name":"app","image":"app:1"}]`,
				}, "after_unknown": map[string]any{"task_role_arn": true, "execution_role_arn": true}},
			},
		)
		if ts.emitBkt && !emittedBkt[ts.bucket] {
			emittedBkt[ts.bucket] = true
			resources = append(resources, map[string]any{
				"address": "aws_s3_bucket." + ts.bucket, "mode": "managed", "type": "aws_s3_bucket", "name": ts.bucket,
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"bucket": ts.bucket, "arn": "arn:aws:s3:::" + ts.bucket,
				}},
			})
			cfg = append(cfg, map[string]any{"address": "aws_s3_bucket." + ts.bucket, "type": "aws_s3_bucket", "name": ts.bucket, "expressions": map[string]any{}})
		}
		if ts.emitRole && !emittedRole[ts.role] {
			emittedRole[ts.role] = true
			resources = append(resources, map[string]any{
				"address": "aws_iam_role." + ts.role, "mode": "managed", "type": "aws_iam_role", "name": ts.role,
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": ts.role},
					"after_unknown": map[string]any{"inline_policy": true, "managed_policy_arns": true}},
			})
			cfg = append(cfg, map[string]any{"address": "aws_iam_role." + ts.role, "type": "aws_iam_role", "name": ts.role, "expressions": map[string]any{}})
			if !ts.roleUnknown {
				pol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:DeleteObject"],"Resource":["arn:aws:s3:::` + ts.bucket + `/*"]}]}`
				resources = append(resources, map[string]any{
					"address": "aws_iam_role_policy." + ts.role + "_s3", "mode": "managed", "type": "aws_iam_role_policy", "name": ts.role + "_s3",
					"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
						"name": ts.role + "-s3", "policy": pol,
					}},
				})
				cfg = append(cfg, map[string]any{
					"address": "aws_iam_role_policy." + ts.role + "_s3", "type": "aws_iam_role_policy", "name": ts.role + "_s3",
					"expressions": map[string]any{
						"role":   map[string]any{"references": []any{"aws_iam_role." + ts.role + ".name", "aws_iam_role." + ts.role}},
						"policy": map[string]any{"constant_value": pol},
					},
				})
			}
		}
		cfg = append(cfg,
			map[string]any{
				"address": "aws_ecs_service." + svcName, "type": "aws_ecs_service", "name": svcName,
				"expressions": map[string]any{
					"task_definition": map[string]any{"references": []any{
						"aws_ecs_task_definition." + taskName + ".arn",
						"aws_ecs_task_definition." + taskName,
					}},
				},
			},
			map[string]any{
				"address": "aws_ecs_task_definition." + taskName, "type": "aws_ecs_task_definition", "name": taskName,
				"expressions": map[string]any{
					"task_role_arn": map[string]any{"references": []any{
						"aws_iam_role." + ts.role + ".arn", "aws_iam_role." + ts.role,
					}},
				},
			},
		)
	}

	root := map[string]any{
		"format_version":   "1.2",
		"resource_changes": resources,
		"configuration":    map[string]any{"root_module": map[string]any{"resources": cfg}},
		"prior_state":      map[string]any{"values": map[string]any{"root_module": map[string]any{"resources": []any{}}}},
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

type ecsMultiOpts struct {
	bucketA, bucketB string
	shareRole        bool
	bRoleUnknown     bool
}

func parseECSPlan(t *testing.T, plan string) DFD {
	t.Helper()
	doc, _, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "fray.yaml",
		Source{Repo: "t/ecs", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func s3FlowsByBucket(t *testing.T, doc DFD) map[string][]Flow {
	t.Helper()
	bucketOf := map[string]string{} // element id → bucket name from evidence address
	for _, el := range doc.Elements {
		if el.Kind != "object_storage" || len(el.Evidence.Addresses) != 1 {
			continue
		}
		addr := el.Evidence.Addresses[0]
		// aws_s3_bucket.NAME
		if i := strings.LastIndex(addr, "."); i >= 0 {
			bucketOf[el.ID] = addr[i+1:]
		}
	}
	svcOf := map[string]string{}
	for _, el := range doc.Elements {
		if el.Kind != "container_service" || len(el.Evidence.Addresses) != 1 {
			continue
		}
		svcOf[el.ID] = el.Evidence.Addresses[0]
	}
	out := map[string][]Flow{}
	for _, f := range doc.Flows {
		bkt, ok := bucketOf[f.To]
		if !ok {
			continue
		}
		out[bkt] = append(out[bkt], f)
	}
	return out
}

func TestB44TwoTaskDefsTwoRolesTwoBuckets(t *testing.T) {
	plan := ecsMultiTaskPlan(t, ecsMultiOpts{bucketA: "bucket_a", bucketB: "bucket_b"})
	doc := parseECSPlan(t, plan)
	byBkt := s3FlowsByBucket(t, doc)
	if len(byBkt["bucket_a"]) != 1 || len(byBkt["bucket_b"]) != 1 {
		t.Fatalf("want one flow each bucket; got a=%d b=%d flows=%v",
			len(byBkt["bucket_a"]), len(byBkt["bucket_b"]), summarizeS3Flows(doc))
	}
	if byBkt["bucket_a"][0].AuthzScope != "resource" || byBkt["bucket_b"][0].AuthzScope != "resource" {
		t.Fatalf("want resource scope on both; a=%q b=%q", byBkt["bucket_a"][0].AuthzScope, byBkt["bucket_b"][0].AuthzScope)
	}
	// Workloads must differ.
	if byBkt["bucket_a"][0].From == byBkt["bucket_b"][0].From {
		t.Fatal("expected distinct workloads for each bucket flow")
	}
}

func TestB44UnresolvableTaskRoleOmitsOnlyThatTask(t *testing.T) {
	plan := ecsMultiTaskPlan(t, ecsMultiOpts{bucketA: "bucket_a", bucketB: "bucket_b", bRoleUnknown: true})
	doc := parseECSPlan(t, plan)
	byBkt := s3FlowsByBucket(t, doc)
	if len(byBkt["bucket_a"]) != 1 {
		t.Fatalf("bucket_a flows=%d want 1", len(byBkt["bucket_a"]))
	}
	if len(byBkt["bucket_b"]) != 0 {
		t.Fatalf("bucket_b flows=%d want 0 (unresolvable role)", len(byBkt["bucket_b"]))
	}
}

func TestB44SharedTaskRoleBothGetFlows(t *testing.T) {
	plan := ecsMultiTaskPlan(t, ecsMultiOpts{bucketA: "shared_bucket", bucketB: "shared_bucket", shareRole: true})
	doc := parseECSPlan(t, plan)
	byBkt := s3FlowsByBucket(t, doc)
	if len(byBkt["shared_bucket"]) != 2 {
		t.Fatalf("shared role flows=%d want 2 (one per service)", len(byBkt["shared_bucket"]))
	}
	froms := map[string]bool{}
	for _, f := range byBkt["shared_bucket"] {
		froms[f.From] = true
		if f.AuthzScope != "resource" {
			t.Fatalf("authz_scope=%q want resource", f.AuthzScope)
		}
	}
	if len(froms) != 2 {
		t.Fatalf("want 2 distinct workloads, got %d", len(froms))
	}
}

func summarizeS3Flows(doc DFD) []string {
	var out []string
	for _, f := range doc.Flows {
		for _, el := range doc.Elements {
			if el.ID == f.To && el.Kind == "object_storage" {
				out = append(out, f.From+"→"+el.Evidence.Addresses[0]+" scope="+f.AuthzScope)
			}
		}
	}
	return out
}

func TestB44SingleTaskDefMatchesPriorBehavior(t *testing.T) {
	// Existing synthetic fixture: one task def → still resource-scoped S3 flow.
	// s3FlowsByBucket keys by local resource name (uploads), not the bucket id.
	plan := flatCoverageS3Plan(t, false)
	doc := parseECSPlan(t, plan)
	byBkt := s3FlowsByBucket(t, doc)
	if len(byBkt["uploads"]) != 1 {
		t.Fatalf("single-task flows=%v", summarizeS3Flows(doc))
	}
	if byBkt["uploads"][0].AuthzScope != "resource" {
		t.Fatalf("authz_scope=%q", byBkt["uploads"][0].AuthzScope)
	}
}

// TestB44UnresolvableTaskDefFallsBackToSoleTask: service.task_definition via
// var/local only (no aws_ecs_task_definition ref) with exactly one task def →
// same S3 flows as the resolvable pre-B-44 path.
func TestB44UnresolvableTaskDefFallsBackToSoleTask(t *testing.T) {
	baseline := parseECSPlan(t, flatCoverageS3Plan(t, false))
	viaVar := parseECSPlan(t, flatCoverageS3PlanTaskDefRefs(t, false, []string{"var.task_definition", "local.task_arn"}))
	want := summarizeS3Flows(baseline)
	got := summarizeS3Flows(viaVar)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("var/local task_definition flows=%v want %v (sole-task fallback)", got, want)
	}
}

// TestB44TaskDefFamilyRefResolves: task_definition = aws_ecs_task_definition.x.family
// resolves (or sole-task falls back) to x.
func TestB44TaskDefFamilyRefResolves(t *testing.T) {
	baseline := parseECSPlan(t, flatCoverageS3Plan(t, false))
	viaFamily := parseECSPlan(t, flatCoverageS3PlanTaskDefRefs(t, false, []string{
		"aws_ecs_task_definition.app.family", "aws_ecs_task_definition.app",
	}))
	want := summarizeS3Flows(baseline)
	got := summarizeS3Flows(viaFamily)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("family ref flows=%v want %v", got, want)
	}
}

// TestB44TwoTaskDefsOneServiceUnresolvable: two task defs; unresolvable service
// contributes no S3 flows; the resolvable service keeps its own.
func TestB44TwoTaskDefsOneServiceUnresolvable(t *testing.T) {
	plan := ecsMultiTaskPlanServiceBUnresolvable(t)
	doc := parseECSPlan(t, plan)
	byBkt := s3FlowsByBucket(t, doc)
	if len(byBkt["bucket_a"]) != 1 {
		t.Fatalf("resolvable svc_a → bucket_a flows=%d want 1; all=%v", len(byBkt["bucket_a"]), summarizeS3Flows(doc))
	}
	if len(byBkt["bucket_b"]) != 0 {
		t.Fatalf("unresolvable svc_b → bucket_b flows=%d want 0; all=%v", len(byBkt["bucket_b"]), summarizeS3Flows(doc))
	}
	// Flow must be from svc_a, not svc_b.
	svcOf := map[string]string{}
	for _, el := range doc.Elements {
		if el.Kind == "container_service" && len(el.Evidence.Addresses) == 1 {
			svcOf[el.ID] = el.Evidence.Addresses[0]
		}
	}
	if addr := svcOf[byBkt["bucket_a"][0].From]; addr != "aws_ecs_service.svc_a" {
		t.Fatalf("bucket_a flow from %q want aws_ecs_service.svc_a", addr)
	}
}

// TestB44AppAndAppWorkerPrefixNames: task defs app and app_worker; each service
// must resolve to its own task def (no prefix steal) and get only its role's flows.
func TestB44AppAndAppWorkerPrefixNames(t *testing.T) {
	plan := ecsAppAndAppWorkerPlan(t)
	doc := parseECSPlan(t, plan)
	byBkt := s3FlowsByBucket(t, doc)
	if len(byBkt["bucket_app"]) != 1 || len(byBkt["bucket_worker"]) != 1 {
		t.Fatalf("want one flow each; got app=%d worker=%d all=%v",
			len(byBkt["bucket_app"]), len(byBkt["bucket_worker"]), summarizeS3Flows(doc))
	}
	svcOf := map[string]string{}
	for _, el := range doc.Elements {
		if el.Kind == "container_service" && len(el.Evidence.Addresses) == 1 {
			svcOf[el.ID] = el.Evidence.Addresses[0]
		}
	}
	if addr := svcOf[byBkt["bucket_app"][0].From]; addr != "aws_ecs_service.svc_app" {
		t.Fatalf("bucket_app from %q want aws_ecs_service.svc_app", addr)
	}
	if addr := svcOf[byBkt["bucket_worker"][0].From]; addr != "aws_ecs_service.svc_worker" {
		t.Fatalf("bucket_worker from %q want aws_ecs_service.svc_worker", addr)
	}
}

func ecsAppAndAppWorkerPlan(t *testing.T) string {
	t.Helper()
	type pair struct{ svc, task, role, bucket string }
	pairs := []pair{
		{"svc_app", "app", "role_app", "bucket_app"},
		{"svc_worker", "app_worker", "role_worker", "bucket_worker"},
	}
	var resources, cfg []map[string]any
	for _, p := range pairs {
		pol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:DeleteObject"],"Resource":["arn:aws:s3:::` + p.bucket + `/*"]}]}`
		resources = append(resources,
			map[string]any{
				"address": "aws_ecs_service." + p.svc, "mode": "managed", "type": "aws_ecs_service", "name": p.svc,
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": p.svc}},
			},
			map[string]any{
				"address": "aws_ecs_task_definition." + p.task, "mode": "managed", "type": "aws_ecs_task_definition", "name": p.task,
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"family": p.task, "container_definitions": `[{"name":"app","image":"app:1"}]`,
				}, "after_unknown": map[string]any{"task_role_arn": true}},
			},
			map[string]any{
				"address": "aws_iam_role." + p.role, "mode": "managed", "type": "aws_iam_role", "name": p.role,
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": p.role},
					"after_unknown": map[string]any{"inline_policy": true, "managed_policy_arns": true}},
			},
			map[string]any{
				"address": "aws_iam_role_policy." + p.role + "_s3", "mode": "managed", "type": "aws_iam_role_policy", "name": p.role + "_s3",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": p.role + "-s3", "policy": pol}},
			},
			map[string]any{
				"address": "aws_s3_bucket." + p.bucket, "mode": "managed", "type": "aws_s3_bucket", "name": p.bucket,
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"bucket": p.bucket, "arn": "arn:aws:s3:::" + p.bucket,
				}},
			},
		)
		cfg = append(cfg,
			map[string]any{
				"address": "aws_ecs_service." + p.svc, "type": "aws_ecs_service", "name": p.svc,
				"expressions": map[string]any{
					"task_definition": map[string]any{"references": []any{
						"aws_ecs_task_definition." + p.task + ".arn",
						"aws_ecs_task_definition." + p.task,
					}},
				},
			},
			map[string]any{
				"address": "aws_ecs_task_definition." + p.task, "type": "aws_ecs_task_definition", "name": p.task,
				"expressions": map[string]any{
					"task_role_arn": map[string]any{"references": []any{
						"aws_iam_role." + p.role + ".arn", "aws_iam_role." + p.role,
					}},
				},
			},
			map[string]any{"address": "aws_iam_role." + p.role, "type": "aws_iam_role", "name": p.role, "expressions": map[string]any{}},
			map[string]any{
				"address": "aws_iam_role_policy." + p.role + "_s3", "type": "aws_iam_role_policy", "name": p.role + "_s3",
				"expressions": map[string]any{
					"role":   map[string]any{"references": []any{"aws_iam_role." + p.role + ".name", "aws_iam_role." + p.role}},
					"policy": map[string]any{"constant_value": pol},
				},
			},
			map[string]any{"address": "aws_s3_bucket." + p.bucket, "type": "aws_s3_bucket", "name": p.bucket, "expressions": map[string]any{}},
		)
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

// flatCoverageS3PlanTaskDefRefs is flatCoverageS3Plan with custom
// aws_ecs_service.app task_definition configuration references.
func flatCoverageS3PlanTaskDefRefs(t *testing.T, dataInResourceChanges bool, taskDefRefs []string) string {
	t.Helper()
	raw := flatCoverageS3Plan(t, dataInResourceChanges)
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		t.Fatal(err)
	}
	cfg := root["configuration"].(map[string]any)["root_module"].(map[string]any)
	resources := cfg["resources"].([]any)
	for i, r := range resources {
		m := r.(map[string]any)
		if m["address"] != "aws_ecs_service.app" {
			continue
		}
		m["expressions"] = map[string]any{
			"task_definition": map[string]any{"references": taskDefRefs},
		}
		resources[i] = m
		break
	}
	cfg["resources"] = resources
	out, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// ecsMultiTaskPlanServiceBUnresolvable: two task defs / two roles / two buckets;
// svc_b.task_definition references only a variable (unresolvable with 2+ tasks).
func ecsMultiTaskPlanServiceBUnresolvable(t *testing.T) string {
	t.Helper()
	raw := ecsMultiTaskPlan(t, ecsMultiOpts{bucketA: "bucket_a", bucketB: "bucket_b"})
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		t.Fatal(err)
	}
	cfg := root["configuration"].(map[string]any)["root_module"].(map[string]any)
	resources := cfg["resources"].([]any)
	for i, r := range resources {
		m := r.(map[string]any)
		if m["address"] != "aws_ecs_service.svc_b" {
			continue
		}
		m["expressions"] = map[string]any{
			"task_definition": map[string]any{"references": []any{"var.other_task"}},
		}
		resources[i] = m
		break
	}
	cfg["resources"] = resources
	out, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func rootModuleSecretPlan(t *testing.T, containerDefs string, unknown bool) string {
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
			"address": "module.db.aws_secretsmanager_secret.db", "mode": "managed", "type": "aws_secretsmanager_secret", "name": "db",
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
		{"address": "module.db.aws_secretsmanager_secret.db", "type": "aws_secretsmanager_secret", "name": "db", "expressions": map[string]any{}},
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

func secretDeliveryFlows(doc DFD) []Flow {
	var out []Flow
	for _, f := range doc.Flows {
		if f.SecretDelivery == "env" && f.DataClass == "credentials" {
			out = append(out, f)
		}
	}
	return out
}

func TestB43RootModuleContainerDefinitionsJSON(t *testing.T) {
	// Whitespace / key-order tolerant jsonencode string on a root-module task def.
	defs := "[\n  { \"image\" : \"app:1\" , \"name\" : \"app\" , \"secrets\" : [ { \"valueFrom\" : \"module.db.aws_secretsmanager_secret.db.arn\" , \"name\" : \"DB\" } ] }\n]"
	rootDoc := parseECSPlan(t, rootModuleSecretPlan(t, defs, false))
	rootFlows := secretDeliveryFlows(rootDoc)
	if len(rootFlows) != 1 {
		t.Fatalf("root secret flows=%d want 1", len(rootFlows))
	}

	modDoc := parseECSPlan(t, moduleSecretPlan(t, defs))
	modFlows := secretDeliveryFlows(modDoc)
	if len(modFlows) != 1 {
		t.Fatalf("module secret flows=%d want 1", len(modFlows))
	}
	if rootFlows[0].SecretDelivery != modFlows[0].SecretDelivery ||
		rootFlows[0].DataClass != modFlows[0].DataClass ||
		rootFlows[0].AuthzScope != modFlows[0].AuthzScope {
		t.Fatalf("root fragment delivery=%q class=%q scope=%q; module delivery=%q class=%q scope=%q",
			rootFlows[0].SecretDelivery, rootFlows[0].DataClass, rootFlows[0].AuthzScope,
			modFlows[0].SecretDelivery, modFlows[0].DataClass, modFlows[0].AuthzScope)
	}
}

func moduleSecretPlan(t *testing.T, containerDefs string) string {
	t.Helper()
	secretARN := "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db-AbCdEf"
	execPol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["secretsmanager:GetSecretValue"],"Resource":["` + secretARN + `"]}]}`
	resources := []map[string]any{
		{
			"address": "module.ecs.aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
		},
		{
			"address": "module.ecs.aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"family": "app", "container_definitions": containerDefs,
			}, "after_unknown": map[string]any{"task_role_arn": true, "execution_role_arn": true}},
		},
		{
			"address": "module.ecs.aws_iam_role.exec", "mode": "managed", "type": "aws_iam_role", "name": "exec",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "exec"}},
		},
		{
			"address": "module.ecs.aws_iam_role_policy.exec_secrets", "mode": "managed", "type": "aws_iam_role_policy", "name": "exec_secrets",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "exec-secrets", "policy": execPol}},
		},
		{
			"address": "module.db.aws_secretsmanager_secret.db", "mode": "managed", "type": "aws_secretsmanager_secret", "name": "db",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app/db", "arn": secretARN}},
		},
	}
	cfg := map[string]any{
		"module_calls": map[string]any{
			"ecs": map[string]any{
				"module": map[string]any{
					"resources": []any{
						map[string]any{
							"address": "aws_ecs_service.app", "type": "aws_ecs_service", "name": "app", "mode": "managed",
							"expressions": map[string]any{
								"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.app.arn", "aws_ecs_task_definition.app"}},
							},
						},
						map[string]any{
							"address": "aws_ecs_task_definition.app", "type": "aws_ecs_task_definition", "name": "app", "mode": "managed",
							"expressions": map[string]any{
								"execution_role_arn": map[string]any{"references": []any{"aws_iam_role.exec.arn", "aws_iam_role.exec"}},
							},
						},
						map[string]any{"address": "aws_iam_role.exec", "type": "aws_iam_role", "name": "exec", "mode": "managed", "expressions": map[string]any{}},
						map[string]any{
							"address": "aws_iam_role_policy.exec_secrets", "type": "aws_iam_role_policy", "name": "exec_secrets", "mode": "managed",
							"expressions": map[string]any{
								"role":   map[string]any{"references": []any{"aws_iam_role.exec.name", "aws_iam_role.exec"}},
								"policy": map[string]any{"constant_value": execPol},
							},
						},
					},
				},
			},
			"db": map[string]any{
				"module": map[string]any{
					"resources": []any{
						map[string]any{"address": "aws_secretsmanager_secret.db", "type": "aws_secretsmanager_secret", "name": "db", "mode": "managed", "expressions": map[string]any{}},
					},
				},
			},
		},
	}
	root := map[string]any{
		"format_version":   "1.2",
		"resource_changes": resources,
		"configuration":    map[string]any{"root_module": cfg},
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestB43RootModuleContainerDefinitionsUnknownOmits(t *testing.T) {
	doc := parseECSPlan(t, rootModuleSecretPlan(t, "", true))
	if flows := secretDeliveryFlows(doc); len(flows) != 0 {
		t.Fatalf("unknown container_definitions: secret flows=%d want 0", len(flows))
	}
}

func TestB43RootModuleARNValueFrom(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db-AbCdEf"
	defs := `[{"name":"app","image":"app:1","secrets":[{"name":"DB","valueFrom":"` + secretARN + `"}]}]`
	doc := parseECSPlan(t, rootModuleSecretPlan(t, defs, false))
	flows := secretDeliveryFlows(doc)
	if len(flows) != 1 {
		t.Fatalf("ARN valueFrom secret flows=%d want 1", len(flows))
	}
	if flows[0].SecretDelivery != "env" || flows[0].AuthzScope != "resource" {
		t.Fatalf("delivery=%q scope=%q", flows[0].SecretDelivery, flows[0].AuthzScope)
	}
}

// TestB43ARNValueFromMatchesPlannedSecret: literal ARN of a secret in the plan
// matches that existing secret_store element (never creates one).
func TestB43ARNValueFromMatchesPlannedSecret(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db-AbCdEf"
	defs := `[{"name":"app","image":"app:1","secrets":[{"name":"DB","valueFrom":"` + secretARN + `"}]}]`
	doc := parseECSPlan(t, rootModuleSecretPlan(t, defs, false))
	flows := secretDeliveryFlows(doc)
	if len(flows) != 1 {
		t.Fatalf("flows=%d want 1", len(flows))
	}
	var fromAddr string
	for _, el := range doc.Elements {
		if el.ID == flows[0].From && len(el.Evidence.Addresses) == 1 {
			fromAddr = el.Evidence.Addresses[0]
		}
	}
	if fromAddr != "module.db.aws_secretsmanager_secret.db" {
		t.Fatalf("matched %q want module.db.aws_secretsmanager_secret.db", fromAddr)
	}
}

// TestB43ARNValueFromUnknownSecretOmits: ARN of a secret not in the plan → no
// new element, no secret-delivery flow, element count unchanged vs no-secrets plan.
func TestB43ARNValueFromUnknownSecretOmits(t *testing.T) {
	baseline := parseECSPlan(t, rootModuleSecretPlan(t, `[{"name":"app","image":"app:1"}]`, false))
	foreign := "arn:aws:secretsmanager:eu-west-1:111122223333:secret:other/not-in-plan-XyZ123"
	defs := `[{"name":"app","image":"app:1","secrets":[{"name":"DB","valueFrom":"` + foreign + `"}]}]`
	doc := parseECSPlan(t, rootModuleSecretPlan(t, defs, false))
	if len(doc.Elements) != len(baseline.Elements) {
		t.Fatalf("elements=%d want %d (must not invent secret_store)", len(doc.Elements), len(baseline.Elements))
	}
	if flows := secretDeliveryFlows(doc); len(flows) != 0 {
		t.Fatalf("foreign ARN flows=%d want 0", len(flows))
	}
}

// TestB43UnqualifiedSecretRefRootOnly: root + module.m both have secret db;
// root task def refs aws_secretsmanager_secret.db.arn → root element only.
func TestB43UnqualifiedSecretRefRootOnly(t *testing.T) {
	doc := parseECSPlan(t, dualModuleSecretRefPlan(t, dualSecretOpts{
		taskModule: "", valueFrom: "aws_secretsmanager_secret.db.arn",
		rootSecret: true, moduleSecret: true,
	}))
	flows := secretDeliveryFlows(doc)
	if len(flows) != 1 {
		t.Fatalf("flows=%d want 1", len(flows))
	}
	if addr := secretFlowFromAddr(doc, flows[0]); addr != "aws_secretsmanager_secret.db" {
		t.Fatalf("matched %q want aws_secretsmanager_secret.db", addr)
	}
}

// TestB43UnqualifiedSecretRefModuleLocal: task def inside module.m refs
// aws_secretsmanager_secret.db.arn → module.m's element only.
func TestB43UnqualifiedSecretRefModuleLocal(t *testing.T) {
	doc := parseECSPlan(t, dualModuleSecretRefPlan(t, dualSecretOpts{
		taskModule: "module.m", valueFrom: "aws_secretsmanager_secret.db.arn",
		rootSecret: true, moduleSecret: true,
	}))
	flows := secretDeliveryFlows(doc)
	if len(flows) != 1 {
		t.Fatalf("flows=%d want 1", len(flows))
	}
	if addr := secretFlowFromAddr(doc, flows[0]); addr != "module.m.aws_secretsmanager_secret.db" {
		t.Fatalf("matched %q want module.m.aws_secretsmanager_secret.db", addr)
	}
}

// TestB43UnqualifiedSecretRefNoCrossModule: root task refs unqualified db but
// only module.m has db → omit.
func TestB43UnqualifiedSecretRefNoCrossModule(t *testing.T) {
	doc := parseECSPlan(t, dualModuleSecretRefPlan(t, dualSecretOpts{
		taskModule: "", valueFrom: "aws_secretsmanager_secret.db.arn",
		rootSecret: false, moduleSecret: true,
	}))
	if flows := secretDeliveryFlows(doc); len(flows) != 0 {
		t.Fatalf("cross-module unqualified ref: flows=%d want 0", len(flows))
	}
}

type dualSecretOpts struct {
	taskModule               string // "" = root, "module.m" = inside m
	valueFrom                string
	rootSecret, moduleSecret bool
}

func secretFlowFromAddr(doc DFD, f Flow) string {
	for _, el := range doc.Elements {
		if el.ID == f.From && len(el.Evidence.Addresses) == 1 {
			return el.Evidence.Addresses[0]
		}
	}
	return ""
}

func dualModuleSecretRefPlan(t *testing.T, opts dualSecretOpts) string {
	t.Helper()
	rootARN := "arn:aws:secretsmanager:eu-west-1:111122223333:secret:root/db-Root01"
	modARN := "arn:aws:secretsmanager:eu-west-1:111122223333:secret:mod/db-Mod001"
	grantARN := rootARN
	if opts.taskModule != "" {
		grantARN = modARN
	}
	if !opts.rootSecret && opts.moduleSecret {
		grantARN = modARN
	}
	execPol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["secretsmanager:GetSecretValue"],"Resource":["` + grantARN + `"]}]}`
	defs := `[{"name":"app","image":"app:1","secrets":[{"name":"DB","valueFrom":"` + opts.valueFrom + `"}]}]`

	var resources []map[string]any
	prefix := opts.taskModule
	if prefix != "" {
		prefix += "."
	}
	resources = append(resources,
		map[string]any{
			"address": prefix + "aws_ecs_service.app", "mode": "managed", "type": "aws_ecs_service", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
		},
		map[string]any{
			"address": prefix + "aws_ecs_task_definition.app", "mode": "managed", "type": "aws_ecs_task_definition", "name": "app",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"family": "app", "container_definitions": defs,
			}, "after_unknown": map[string]any{"execution_role_arn": true}},
		},
		map[string]any{
			"address": prefix + "aws_iam_role.exec", "mode": "managed", "type": "aws_iam_role", "name": "exec",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "exec"}},
		},
		map[string]any{
			"address": prefix + "aws_iam_role_policy.exec_secrets", "mode": "managed", "type": "aws_iam_role_policy", "name": "exec_secrets",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "exec-secrets", "policy": execPol}},
		},
	)
	if opts.rootSecret {
		resources = append(resources, map[string]any{
			"address": "aws_secretsmanager_secret.db", "mode": "managed", "type": "aws_secretsmanager_secret", "name": "db",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "root/db", "arn": rootARN}},
		})
	}
	if opts.moduleSecret {
		resources = append(resources, map[string]any{
			"address": "module.m.aws_secretsmanager_secret.db", "mode": "managed", "type": "aws_secretsmanager_secret", "name": "db",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "mod/db", "arn": modARN}},
		})
	}

	svcExpr := map[string]any{
		"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.app.arn", "aws_ecs_task_definition.app"}},
	}
	taskExpr := map[string]any{
		"execution_role_arn": map[string]any{"references": []any{"aws_iam_role.exec.arn", "aws_iam_role.exec"}},
	}
	polExpr := map[string]any{
		"role":   map[string]any{"references": []any{"aws_iam_role.exec.name", "aws_iam_role.exec"}},
		"policy": map[string]any{"constant_value": execPol},
	}

	var root map[string]any
	if opts.taskModule == "" {
		cfg := []map[string]any{
			{"address": "aws_ecs_service.app", "type": "aws_ecs_service", "name": "app", "expressions": svcExpr},
			{"address": "aws_ecs_task_definition.app", "type": "aws_ecs_task_definition", "name": "app", "expressions": taskExpr},
			{"address": "aws_iam_role.exec", "type": "aws_iam_role", "name": "exec", "expressions": map[string]any{}},
			{"address": "aws_iam_role_policy.exec_secrets", "type": "aws_iam_role_policy", "name": "exec_secrets", "expressions": polExpr},
		}
		if opts.rootSecret {
			cfg = append(cfg, map[string]any{"address": "aws_secretsmanager_secret.db", "type": "aws_secretsmanager_secret", "name": "db", "expressions": map[string]any{}})
		}
		moduleCalls := map[string]any{}
		if opts.moduleSecret {
			moduleCalls["m"] = map[string]any{
				"module": map[string]any{
					"resources": []any{
						map[string]any{"address": "aws_secretsmanager_secret.db", "type": "aws_secretsmanager_secret", "name": "db", "mode": "managed", "expressions": map[string]any{}},
					},
				},
			}
		}
		root = map[string]any{
			"format_version":   "1.2",
			"resource_changes": resources,
			"configuration": map[string]any{"root_module": map[string]any{
				"resources": cfg, "module_calls": moduleCalls,
			}},
		}
	} else {
		modResources := []any{
			map[string]any{"address": "aws_ecs_service.app", "type": "aws_ecs_service", "name": "app", "mode": "managed", "expressions": svcExpr},
			map[string]any{"address": "aws_ecs_task_definition.app", "type": "aws_ecs_task_definition", "name": "app", "mode": "managed", "expressions": taskExpr},
			map[string]any{"address": "aws_iam_role.exec", "type": "aws_iam_role", "name": "exec", "mode": "managed", "expressions": map[string]any{}},
			map[string]any{"address": "aws_iam_role_policy.exec_secrets", "type": "aws_iam_role_policy", "name": "exec_secrets", "mode": "managed", "expressions": polExpr},
		}
		if opts.moduleSecret {
			modResources = append(modResources, map[string]any{
				"address": "aws_secretsmanager_secret.db", "type": "aws_secretsmanager_secret", "name": "db", "mode": "managed", "expressions": map[string]any{},
			})
		}
		rootCfg := []map[string]any{}
		if opts.rootSecret {
			rootCfg = append(rootCfg, map[string]any{"address": "aws_secretsmanager_secret.db", "type": "aws_secretsmanager_secret", "name": "db", "expressions": map[string]any{}})
		}
		root = map[string]any{
			"format_version":   "1.2",
			"resource_changes": resources,
			"configuration": map[string]any{"root_module": map[string]any{
				"resources": rootCfg,
				"module_calls": map[string]any{
					"m": map[string]any{"module": map[string]any{"resources": modResources}},
				},
			}},
		}
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestB43ARNValueFromComputedSecretARNOmits: planned secret with after_unknown
// arn → no match from a literal valueFrom ARN (do not guess via name).
func TestB43ARNValueFromComputedSecretARNOmits(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db-AbCdEf"
	defs := `[{"name":"app","image":"app:1","secrets":[{"name":"DB","valueFrom":"` + secretARN + `"}]}]`
	raw := rootModuleSecretPlan(t, defs, false)
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		t.Fatal(err)
	}
	for i, r := range root["resource_changes"].([]any) {
		m := r.(map[string]any)
		if m["address"] != "module.db.aws_secretsmanager_secret.db" {
			continue
		}
		ch := m["change"].(map[string]any)
		after := ch["after"].(map[string]any)
		delete(after, "arn")
		ch["after"] = after
		ch["after_unknown"] = map[string]any{"arn": true}
		m["change"] = ch
		root["resource_changes"].([]any)[i] = m
		break
	}
	out, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	doc := parseECSPlan(t, string(out))
	if flows := secretDeliveryFlows(doc); len(flows) != 0 {
		t.Fatalf("computed secret ARN: flows=%d want 0", len(flows))
	}
}
