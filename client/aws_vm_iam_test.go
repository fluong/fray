package client

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testConfigIndex(refs map[string]map[string][]string) configIndex {
	idx := configIndex{
		resources: map[string]exprSet{},
		calls:     map[string]exprSet{},
		outputs:   map[string]exprSet{},
	}
	for addr, attrs := range refs {
		key, ok := resourceKey(addr)
		if !ok {
			continue
		}
		es := exprSet{refs: map[string][]string{}}
		for a, r := range attrs {
			es.refs[a] = r
		}
		idx.resources[key] = es
	}
	return idx
}

func TestInstanceProfileRoleRefsTable(t *testing.T) {
	roleA := planResource{address: "aws_iam_role.app", typ: "aws_iam_role", values: map[string]any{"name": "app"}}
	roleB := planResource{address: "aws_iam_role.other", typ: "aws_iam_role", values: map[string]any{"name": "other"}}
	profA := planResource{address: "aws_iam_instance_profile.app", typ: "aws_iam_instance_profile", values: map[string]any{"name": "app"}}
	profB := planResource{address: "aws_iam_instance_profile.other", typ: "aws_iam_instance_profile", values: map[string]any{"name": "other"}}
	lt1 := planResource{address: "aws_launch_template.a", typ: "aws_launch_template", values: map[string]any{"name": "a", "id": "lt-1"}, actions: []string{"create"}}
	lt2 := planResource{address: "aws_launch_template.b", typ: "aws_launch_template", values: map[string]any{"name": "b", "id": "lt-b"}, actions: []string{"create"}}
	lc := planResource{address: "aws_launch_configuration.app", typ: "aws_launch_configuration", values: map[string]any{"iam_instance_profile": "app"}}
	inst := planResource{address: "aws_instance.web", typ: "aws_instance", values: map[string]any{"iam_instance_profile": "app"}}
	asg := planResource{address: "aws_autoscaling_group.web", typ: "aws_autoscaling_group", values: map[string]any{
		"launch_template": []any{map[string]any{"id": "lt-1", "version": "$Latest"}},
	}}
	ng := planResource{address: "aws_eks_node_group.workers", typ: "aws_eks_node_group", values: map[string]any{}}
	baseIdx := testConfigIndex(map[string]map[string][]string{
		"aws_iam_instance_profile.app":   {"role": {"aws_iam_role.app"}},
		"aws_iam_instance_profile.other": {"role": {"aws_iam_role.other"}},
		"aws_launch_template.a":          {"iam_instance_profile": {"aws_iam_instance_profile.app"}},
		"aws_launch_template.b":          {"iam_instance_profile": {"aws_iam_instance_profile.other"}},
		"aws_autoscaling_group.web":      {"launch_template": {"aws_launch_template.a.id", "aws_launch_template.a"}},
		"aws_eks_node_group.workers":     {"node_role_arn": {"aws_iam_role.app.arn", "aws_iam_role.app"}},
	})
	baseRes := []planResource{roleA, roleB, profA, profB, lt1, lt2, lc, inst, asg, ng}

	tests := []struct {
		name      string
		el        *Element
		resources []planResource
		idx       configIndex
		wantRefs  bool
		wantOmit  string
	}{
		{name: "instance_literal_name", el: vmEl(inst.address), resources: baseRes, idx: baseIdx, wantRefs: true},
		{name: "instance_ref", el: vmEl("aws_instance.ref"), resources: append(append([]planResource{}, baseRes...), planResource{
			address: "aws_instance.ref", typ: "aws_instance", values: map[string]any{},
		}), idx: testConfigIndex(map[string]map[string][]string{
			"aws_iam_instance_profile.app": {"role": {"aws_iam_role.app"}},
			"aws_instance.ref":             {"iam_instance_profile": {"aws_iam_instance_profile.app"}},
		}), wantRefs: true},
		{name: "profile_outside_plan", el: vmEl("aws_instance.missing"), resources: append(append([]planResource{}, baseRes...), planResource{
			address: "aws_instance.missing", typ: "aws_instance", values: map[string]any{"iam_instance_profile": "nope"},
		}), idx: baseIdx, wantOmit: iamOmitProfileNotInPlan},
		{name: "asg_launch_template", el: vmEl(asg.address), resources: baseRes, idx: baseIdx, wantRefs: true},
		{name: "asg_launch_configuration", el: vmEl("aws_autoscaling_group.lc"), resources: append(append([]planResource{}, baseRes...), planResource{
			address: "aws_autoscaling_group.lc", typ: "aws_autoscaling_group", values: map[string]any{"launch_configuration": "app"},
		}), idx: testConfigIndex(map[string]map[string][]string{
			"aws_iam_instance_profile.app": {"role": {"aws_iam_role.app"}},
			"aws_autoscaling_group.lc":     {"launch_configuration": {"aws_launch_configuration.app.name", "aws_launch_configuration.app"}},
		}), wantRefs: true},
		{name: "asg_mixed_same_role", el: vmEl("aws_autoscaling_group.mix"), resources: append(append([]planResource{}, baseRes...), planResource{
			address: "aws_autoscaling_group.mix", typ: "aws_autoscaling_group",
			values: map[string]any{"mixed_instances_policy": []any{map[string]any{
				"launch_template": []any{map[string]any{
					"launch_template_specification": []any{map[string]any{"launch_template_id": "lt-1"}},
					"override": []any{map[string]any{
						"launch_template_specification": []any{map[string]any{"launch_template_id": "lt-1"}},
					}},
				}},
			}}},
		}), idx: baseIdx, wantRefs: true},
		{name: "asg_mixed_different_roles", el: vmEl("aws_autoscaling_group.bad"), resources: append(append([]planResource{}, baseRes...), planResource{
			address: "aws_autoscaling_group.bad", typ: "aws_autoscaling_group",
			values: map[string]any{"mixed_instances_policy": []any{map[string]any{
				"launch_template": []any{map[string]any{
					"launch_template_specification": []any{map[string]any{"launch_template_id": "lt-1"}},
					"override": []any{map[string]any{
						"launch_template_specification": []any{map[string]any{"launch_template_id": "lt-b"}},
					}},
				}},
			}}},
		}), idx: baseIdx, wantOmit: iamOmitRoleAmbiguous},
		{name: "latest_unusable", el: vmEl("aws_autoscaling_group.ver"), resources: append(append([]planResource{}, baseRes...),
			planResource{address: "aws_launch_template.old", typ: "aws_launch_template", values: map[string]any{"id": "lt-old", "update_default_version": false}, actions: []string{"no-op"}},
			planResource{address: "aws_autoscaling_group.ver", typ: "aws_autoscaling_group", values: map[string]any{
				"launch_template": []any{map[string]any{"id": "lt-old", "version": "$Latest"}},
			}},
		), idx: testConfigIndex(map[string]map[string][]string{
			"aws_launch_template.old":      {"iam_instance_profile": {"aws_iam_instance_profile.app"}},
			"aws_iam_instance_profile.app": {"role": {"aws_iam_role.app"}},
		}), wantOmit: iamOmitLaunchVersion},
		{name: "eks_node_role", el: vmEl(ng.address), resources: baseRes, idx: baseIdx, wantRefs: true},
		{name: "eks_node_role_missing", el: vmEl("aws_eks_node_group.missing"), resources: append(append([]planResource{}, baseRes...), planResource{
			address: "aws_eks_node_group.missing", typ: "aws_eks_node_group", values: map[string]any{},
		}), idx: testConfigIndex(map[string]map[string][]string{
			"aws_eks_node_group.missing": {"node_role_arn": {"aws_iam_role.ghost.arn", "aws_iam_role.ghost"}},
		}), wantOmit: iamOmitNodeRoleNotInPlan},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, refs, omit := iamRoleRefsForCompute(tc.el, tc.resources, nil, tc.idx)
			if omit != tc.wantOmit {
				t.Fatalf("omit=%q want %q refs=%v", omit, tc.wantOmit, refs)
			}
			if tc.wantOmit != "" {
				return
			}
			if tc.wantRefs && len(refs) == 0 {
				t.Fatal("want role refs")
			}
		})
	}
}

func vmEl(addr string) *Element {
	return &Element{
		Kind: "virtual_machine", Type: "process", Provider: "aws", Provenance: "iac",
		Evidence: Evidence{Addresses: []string{addr}},
	}
}

func TestVMIAMFlowsAndSingleWarning(t *testing.T) {
	plan := instanceProfileIAMPlan(t)
	doc, warnings, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "t/vm-iam", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var s3Flow, dbFlow, bedrockFlow *Flow
	byID := map[string]Element{}
	for _, el := range doc.Elements {
		byID[el.ID] = el
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		to := byID[f.To]
		from := byID[f.From]
		if from.Kind != "virtual_machine" {
			continue
		}
		switch to.Kind {
		case "object_storage":
			s3Flow = f
		case "relational_db":
			dbFlow = f
		case "llm_api":
			bedrockFlow = f
		}
	}
	if s3Flow == nil || s3Flow.AuthzScope != "resource" {
		t.Fatalf("want VM→S3 resource scope, got %#v", s3Flow)
	}
	if dbFlow == nil || dbFlow.AuthzScope != "resource" {
		t.Fatalf("want VM→RDS resource scope, got %#v", dbFlow)
	}
	if bedrockFlow == nil {
		t.Fatal("want VM→Bedrock flow")
	}
	omitWarns := 0
	for _, w := range warnings {
		if strings.HasPrefix(w, "IAM flows omitted for ") {
			omitWarns++
		}
	}
	if omitWarns != 0 {
		t.Fatalf("want no IAM omit warnings, got %v", warnings)
	}

	// Ambiguous ASG: exactly one omit warning.
	planAmb := instanceProfileAmbiguousASGPlan(t)
	_, warnings2, err := Parse([]byte(planAmb), []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "t/vm-iam", Commit: "abcdef2", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	omitWarns = 0
	for _, w := range warnings2 {
		if strings.HasPrefix(w, "IAM flows omitted for aws_autoscaling_group.amb") {
			omitWarns++
		}
	}
	if omitWarns != 1 {
		t.Fatalf("want one IAM omit warning for ASG, got %d: %v", omitWarns, warnings2)
	}
}

func TestInstanceProfileIAMGolden(t *testing.T) {
	plan := instanceProfileIAMPlan(t)
	doc, warnings, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "t/vm-iam", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.HasPrefix(w, "IAM flows omitted for ") {
			t.Fatalf("unexpected omit warning: %s", w)
		}
	}
	got, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "testdata", "golden", "instance-profile-iam.dfd.json")
	if os.Getenv("UPDATE") != "" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		_ = os.WriteFile("/tmp/instance-profile-iam.dfd.json", got, 0o644)
		t.Fatalf("missing golden %s (wrote /tmp/instance-profile-iam.dfd.json): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		_ = os.WriteFile("/tmp/instance-profile-iam.dfd.json", got, 0o644)
		t.Fatalf("golden drift; wrote /tmp/instance-profile-iam.dfd.json (%d vs %d bytes)", len(got), len(want))
	}
}

func TestASGDBFlowWithLTInstanceProfileRole(t *testing.T) {
	plan := asgDBIAMPlan(t, false)
	doc, warnings, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "t/asg-db", Commit: "abcdef3", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var asgToDB *Flow
	byID := map[string]Element{}
	for _, el := range doc.Elements {
		byID[el.ID] = el
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		from := byID[f.From]
		to := byID[f.To]
		if from.Kind != "virtual_machine" || from.Evidence.Addresses[0] != "aws_autoscaling_group.web" {
			continue
		}
		if to.Kind == "relational_db" {
			asgToDB = f
		}
	}
	if asgToDB == nil {
		t.Fatalf("want ASG→RDS flow, got flows %#v warnings %v", doc.Flows, warnings)
	}
	if asgToDB.AuthzScope != "resource" {
		t.Fatalf("want resource authz_scope, got %#v", asgToDB)
	}
	for _, w := range warnings {
		if strings.HasPrefix(w, "IAM flows omitted for ") {
			t.Fatalf("unexpected omit warning: %s", w)
		}
	}
}

func TestASGDBFlowLatestUnusableNoEdgeOneWarning(t *testing.T) {
	plan := asgDBIAMPlan(t, true)
	doc, warnings, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "t/asg-db", Commit: "abcdef4", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		fromAddr := elementAddress(doc.Elements, f.From)
		if fromAddr == "aws_autoscaling_group.web" {
			toKind := elementKind(doc.Elements, f.To)
			if toKind == "relational_db" {
				t.Fatalf("want no ASG→RDS edge when $Latest is unusable, got flow %#v", f)
			}
		}
	}
	omitWarns := 0
	for _, w := range warnings {
		if w == "IAM flows omitted for aws_autoscaling_group.web: "+iamOmitLaunchVersion {
			omitWarns++
		}
	}
	if omitWarns != 1 {
		t.Fatalf("want one IAM omit warning, got %d: %v", omitWarns, warnings)
	}
}

func elementAddress(elements []Element, id string) string {
	for _, el := range elements {
		if el.ID == id && len(el.Evidence.Addresses) == 1 {
			return el.Evidence.Addresses[0]
		}
	}
	return ""
}

func elementKind(elements []Element, id string) string {
	for _, el := range elements {
		if el.ID == id {
			return el.Kind
		}
	}
	return ""
}

func asgDBIAMPlan(t *testing.T, latestUnusable bool) string {
	t.Helper()
	ltVersion := "1"
	ltActions := []any{"create"}
	ltAfter := map[string]any{
		"id": "lt-asg-db", "name": "asg-db",
	}
	if latestUnusable {
		ltVersion = "$Latest"
		ltActions = []any{"no-op"}
		ltAfter["update_default_version"] = false
	}
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_autoscaling_group.web", "mode": "managed", "type": "aws_autoscaling_group", "name": "web",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"launch_template": []any{map[string]any{"id": "lt-asg-db", "version": ltVersion}},
				}},
			},
			map[string]any{
				"address": "aws_launch_template.asg", "mode": "managed", "type": "aws_launch_template", "name": "asg",
				"change": map[string]any{"actions": ltActions, "after": ltAfter},
			},
			map[string]any{
				"address": "aws_iam_instance_profile.app", "mode": "managed", "type": "aws_iam_instance_profile", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
			},
			map[string]any{
				"address": "aws_iam_role.app", "mode": "managed", "type": "aws_iam_role", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
			},
			map[string]any{
				"address": "aws_iam_role_policy.app", "mode": "managed", "type": "aws_iam_role_policy", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"name":   "app",
					"policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["rds-db:connect"],"Resource":["arn:aws:rds-db:us-east-1:123456789012:dbuser:db-ABC/app"]}]}`,
				}},
			},
			map[string]any{
				"address": "aws_db_instance.main", "mode": "managed", "type": "aws_db_instance", "name": "main",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"resource_id": "db-ABC", "identifier": "main",
				}},
			},
			map[string]any{
				"address": "aws_security_group.app", "mode": "managed", "type": "aws_security_group", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{}},
			},
			map[string]any{
				"address": "aws_security_group.db", "mode": "managed", "type": "aws_security_group", "name": "db",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{}},
			},
		},
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{"address": "aws_autoscaling_group.web", "type": "aws_autoscaling_group", "name": "web", "expressions": map[string]any{
						"launch_template": map[string]any{"references": []any{"aws_launch_template.asg.id", "aws_launch_template.asg"}},
					}},
					map[string]any{"address": "aws_launch_template.asg", "type": "aws_launch_template", "name": "asg", "expressions": map[string]any{
						"iam_instance_profile":   map[string]any{"references": []any{"aws_iam_instance_profile.app"}},
						"vpc_security_group_ids": map[string]any{"references": []any{"aws_security_group.app.id", "aws_security_group.app"}},
					}},
					map[string]any{"address": "aws_iam_instance_profile.app", "type": "aws_iam_instance_profile", "name": "app", "expressions": map[string]any{
						"role": map[string]any{"references": []any{"aws_iam_role.app.arn", "aws_iam_role.app"}},
					}},
					map[string]any{"address": "aws_iam_role_policy.app", "type": "aws_iam_role_policy", "name": "app", "expressions": map[string]any{
						"role": map[string]any{"references": []any{"aws_iam_role.app.id", "aws_iam_role.app"}},
					}},
					map[string]any{"address": "aws_db_instance.main", "type": "aws_db_instance", "name": "main", "expressions": map[string]any{
						"vpc_security_group_ids": map[string]any{"references": []any{"aws_security_group.db.id", "aws_security_group.db"}},
					}},
					map[string]any{"address": "aws_security_group.db", "type": "aws_security_group", "name": "db", "expressions": map[string]any{
						"ingress": map[string]any{"references": []any{"aws_security_group.app.id", "aws_security_group.app"}},
					}},
				},
			},
		},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func instanceProfileIAMPlan(t *testing.T) string {
	t.Helper()
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "aws_instance.app", "mode": "managed", "type": "aws_instance", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"iam_instance_profile": "app",
				}},
			},
			map[string]any{
				"address": "aws_iam_instance_profile.app", "mode": "managed", "type": "aws_iam_instance_profile", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
			},
			map[string]any{
				"address": "aws_iam_role.app", "mode": "managed", "type": "aws_iam_role", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
			},
			map[string]any{
				"address": "aws_iam_role_policy.app", "mode": "managed", "type": "aws_iam_role_policy", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"name":   "app",
					"policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::uploads/*"]},{"Effect":"Allow","Action":["bedrock:InvokeModel"],"Resource":["*"]},{"Effect":"Allow","Action":["rds-db:connect"],"Resource":["arn:aws:rds-db:us-east-1:123456789012:dbuser:db-ABC/app"]}]}`,
				}},
			},
			map[string]any{
				"address": "aws_s3_bucket.uploads", "mode": "managed", "type": "aws_s3_bucket", "name": "uploads",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"bucket": "uploads"}},
			},
			map[string]any{
				"address": "aws_db_instance.main", "mode": "managed", "type": "aws_db_instance", "name": "main",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"resource_id": "db-ABC", "identifier": "main",
				}},
			},
			map[string]any{
				"address": "aws_security_group.app", "mode": "managed", "type": "aws_security_group", "name": "app",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{}},
			},
			map[string]any{
				"address": "aws_security_group.db", "mode": "managed", "type": "aws_security_group", "name": "db",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{}},
			},
		},
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{"address": "aws_iam_instance_profile.app", "type": "aws_iam_instance_profile", "name": "app", "expressions": map[string]any{
						"role": map[string]any{"references": []any{"aws_iam_role.app.arn", "aws_iam_role.app"}},
					}},
					map[string]any{"address": "aws_iam_role_policy.app", "type": "aws_iam_role_policy", "name": "app", "expressions": map[string]any{
						"role": map[string]any{"references": []any{"aws_iam_role.app.id", "aws_iam_role.app"}},
					}},
					map[string]any{"address": "aws_db_instance.main", "type": "aws_db_instance", "name": "main", "expressions": map[string]any{
						"vpc_security_group_ids": map[string]any{"references": []any{"aws_security_group.db.id", "aws_security_group.db"}},
					}},
					map[string]any{"address": "aws_instance.app", "type": "aws_instance", "name": "app", "expressions": map[string]any{
						"vpc_security_group_ids": map[string]any{"references": []any{"aws_security_group.app.id", "aws_security_group.app"}},
					}},
					map[string]any{"address": "aws_security_group.db", "type": "aws_security_group", "name": "db", "expressions": map[string]any{
						"ingress": map[string]any{"references": []any{"aws_security_group.app.id", "aws_security_group.app"}},
					}},
				},
			},
		},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func instanceProfileAmbiguousASGPlan(t *testing.T) string {
	t.Helper()
	// Two launch templates, different profiles/roles — IAM omitted once for ASG.
	base := instanceProfileIAMPlan(t)
	var m map[string]any
	if err := json.Unmarshal([]byte(base), &m); err != nil {
		t.Fatal(err)
	}
	changes := m["resource_changes"].([]any)
	changes = append(changes,
		map[string]any{
			"address": "aws_launch_template.a", "mode": "managed", "type": "aws_launch_template", "name": "a",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"id": "lt-a", "name": "a"}},
		},
		map[string]any{
			"address": "aws_launch_template.b", "mode": "managed", "type": "aws_launch_template", "name": "b",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"id": "lt-b", "name": "b"}},
		},
		map[string]any{
			"address": "aws_iam_instance_profile.other", "mode": "managed", "type": "aws_iam_instance_profile", "name": "other",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "other"}},
		},
		map[string]any{
			"address": "aws_iam_role.other", "mode": "managed", "type": "aws_iam_role", "name": "other",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "other"}},
		},
		map[string]any{
			"address": "aws_autoscaling_group.amb", "mode": "managed", "type": "aws_autoscaling_group", "name": "amb",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"mixed_instances_policy": []any{map[string]any{
					"launch_template": []any{map[string]any{
						"launch_template_specification": []any{map[string]any{"launch_template_id": "lt-a"}},
						"override": []any{map[string]any{
							"launch_template_specification": []any{map[string]any{"launch_template_id": "lt-b"}},
						}},
					}},
				}},
			}},
		},
	)
	m["resource_changes"] = changes
	cfg := m["configuration"].(map[string]any)["root_module"].(map[string]any)
	res := cfg["resources"].([]any)
	res = append(res,
		map[string]any{"address": "aws_launch_template.a", "type": "aws_launch_template", "name": "a", "expressions": map[string]any{
			"iam_instance_profile": map[string]any{"references": []any{"aws_iam_instance_profile.app"}},
		}},
		map[string]any{"address": "aws_launch_template.b", "type": "aws_launch_template", "name": "b", "expressions": map[string]any{
			"iam_instance_profile": map[string]any{"references": []any{"aws_iam_instance_profile.other"}},
		}},
		map[string]any{"address": "aws_iam_instance_profile.other", "type": "aws_iam_instance_profile", "name": "other", "expressions": map[string]any{
			"role": map[string]any{"references": []any{"aws_iam_role.other.arn", "aws_iam_role.other"}},
		}},
	)
	cfg["resources"] = res
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
