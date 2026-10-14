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

