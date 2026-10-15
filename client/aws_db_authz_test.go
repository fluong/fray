package client

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRDSAction(t *testing.T) {
	cases := []struct {
		action string
		want   bool
	}{
		{"rds-db:connect", true},
		{"rds-db:*", true},
		{"rds-data:*", true},
		{"rds-data:ExecuteStatement", true},
		{"*", true},
		{"RDS-DB:Connect", true},
		{"rds:DescribeDBInstances", false},
		{"rds:*", false},
		{"s3:GetObject", false},
	}
	for _, tc := range cases {
		if got := rdsAction(tc.action); got != tc.want {
			t.Fatalf("rdsAction(%q)=%v want %v", tc.action, got, tc.want)
		}
	}
}

func TestClassifyRDSdbARN(t *testing.T) {
	db := planResource{
		address: "aws_db_instance.main",
		typ:     "aws_db_instance",
		values: map[string]any{
			"resource_id": "db-ABCDEF",
			"identifier":  "main",
		},
	}
	other := planResource{
		address: "aws_db_instance.other",
		typ:     "aws_db_instance",
		values:  map[string]any{"resource_id": "db-OTHER"},
	}
	cluster := planResource{
		address: "aws_rds_cluster.main",
		typ:     "aws_rds_cluster",
		values: map[string]any{
			"cluster_resource_id": "cluster-XYZ",
			"cluster_identifier":  "main",
		},
	}
	dbEl := &Element{
		Evidence: Evidence{Addresses: []string{db.address}},
		Kind:     "relational_db", Type: "datastore", Provider: "aws", Provenance: "iac",
	}
	clusterEl := &Element{
		Evidence: Evidence{Addresses: []string{cluster.address}},
		Kind:     "relational_db", Type: "datastore", Provider: "aws", Provenance: "iac",
	}
	resources := []planResource{db, other, cluster}

	cases := []struct {
		name            string
		arn             string
		dest            *Element
		wantAcc, wantCov bool
	}{
		{name: "star", arn: "*", dest: dbEl, wantAcc: true},
		{name: "scoped_dbuser", arn: "arn:aws:rds-db:us-east-1:111122223333:dbuser:db-ABCDEF/app", dest: dbEl, wantCov: true},
		{name: "other_instance", arn: "arn:aws:rds-db:us-east-1:111122223333:dbuser:db-OTHER/app", dest: dbEl},
		{name: "wildcard_dbi", arn: "arn:aws:rds-db:us-east-1:111122223333:dbuser:*/app", dest: dbEl, wantAcc: true},
		{name: "wildcard_user_same_dbi", arn: "arn:aws:rds-db:us-east-1:111122223333:dbuser:db-ABCDEF/*", dest: dbEl, wantCov: true},
		{name: "wildcard_user_other_dbi", arn: "arn:aws:rds-db:us-east-1:111122223333:dbuser:db-OTHER/*", dest: dbEl},
		{name: "wildcard_region_account_same_dbi", arn: "arn:aws:rds-db:*:*:dbuser:db-ABCDEF/app", dest: dbEl, wantCov: true},
		{name: "rds_data_cluster", arn: "arn:aws:rds:us-east-1:111122223333:cluster:main", dest: clusterEl, wantCov: true},
		{name: "rds_data_star", arn: "arn:aws:rds:us-east-1:111122223333:cluster:*", dest: clusterEl, wantAcc: true},
		{name: "rds_data_db_arn_covers", arn: "arn:aws:rds:us-east-1:111122223333:db:main", dest: dbEl, wantCov: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acc, cov := classifyRDSdbARN(tc.arn, tc.dest, resources)
			if acc != tc.wantAcc || cov != tc.wantCov {
				t.Fatalf("account=%v covers=%v want account=%v covers=%v", acc, cov, tc.wantAcc, tc.wantCov)
			}
		})
	}
}

func TestAwsDBScopeTable(t *testing.T) {
	db := planResource{
		address: "aws_db_instance.main", typ: "aws_db_instance",
		values: map[string]any{"resource_id": "db-ABCDEF", "identifier": "main"},
	}
	other := planResource{
		address: "aws_db_instance.other", typ: "aws_db_instance",
		values: map[string]any{"resource_id": "db-OTHER"},
	}
	dbEl := &Element{
		Evidence: Evidence{Addresses: []string{db.address}},
		Kind:     "relational_db", Type: "datastore", Provider: "aws", Provenance: "iac",
	}
	resources := []planResource{db, other}
	idx := configIndex{resources: map[string]exprSet{}}

	doc := func(actions []any, resources []any) planResource {
		return planResource{
			address: "data.aws_iam_policy_document.db",
			typ:     "aws_iam_policy_document",
			values: map[string]any{"statement": []any{map[string]any{
				"effect": "Allow", "actions": actions, "resources": resources,
			}}},
		}
	}

	t.Run("wildcard_connect_account", func(t *testing.T) {
		scope, grants, _ := awsDBScope(dbEl, []planResource{doc([]any{"rds-db:connect"}, []any{"*"})}, idx, resources, nil)
		if scope != "account" || strings.Join(grants, ",") != "account" {
			t.Fatalf("scope=%q grants=%v", scope, grants)
		}
	})
	t.Run("scoped_dbuser_resource", func(t *testing.T) {
		arn := "arn:aws:rds-db:us-east-1:111122223333:dbuser:db-ABCDEF/app"
		scope, grants, _ := awsDBScope(dbEl, []planResource{doc([]any{"rds-db:connect"}, []any{arn})}, idx, resources, nil)
		if scope != "resource" || strings.Join(grants, ",") != "resource" {
			t.Fatalf("scope=%q grants=%v", scope, grants)
		}
	})
	t.Run("both_grants_account_wins", func(t *testing.T) {
		docs := []planResource{
			doc([]any{"rds-db:connect"}, []any{"arn:aws:rds-db:us-east-1:111122223333:dbuser:db-ABCDEF/app"}),
			{
				address: "data.aws_iam_policy_document.wide",
				typ:     "aws_iam_policy_document",
				values: map[string]any{"statement": []any{map[string]any{
					"effect": "Allow", "actions": []any{"rds-db:connect"}, "resources": []any{"*"},
				}}},
			},
		}
		scope, grants, _ := awsDBScope(dbEl, docs, idx, resources, nil)
		if scope != "account" {
			t.Fatalf("scope=%q want account", scope)
		}
		got := strings.Join(grants, ",")
		if got != "resource,account" {
			t.Fatalf("grants=%q want resource,account", got)
		}
	})
	t.Run("rds_data_star_account", func(t *testing.T) {
		scope, _, _ := awsDBScope(dbEl, []planResource{doc([]any{"rds-data:*"}, []any{"*"})}, idx, resources, nil)
		if scope != "account" {
			t.Fatalf("scope=%q want account", scope)
		}
	})
	t.Run("other_instance_only_omitted", func(t *testing.T) {
		arn := "arn:aws:rds-db:us-east-1:111122223333:dbuser:db-OTHER/app"
		scope, grants, _ := awsDBScope(dbEl, []planResource{doc([]any{"rds-db:connect"}, []any{arn})}, idx, resources, nil)
		if scope != "" || len(grants) != 0 {
			t.Fatalf("scope=%q grants=%v want omit", scope, grants)
		}
	})
	t.Run("password_only_omitted", func(t *testing.T) {
		scope, _, _ := awsDBScope(dbEl, []planResource{doc([]any{"s3:GetObject"}, []any{"*"})}, idx, resources, nil)
		if scope != "" {
			t.Fatalf("scope=%q want omit", scope)
		}
	})
	t.Run("resource_id_ref_when_unknown", func(t *testing.T) {
		refDoc := planResource{
			address: "data.aws_iam_policy_document.ref",
			typ:     "aws_iam_policy_document",
			values: map[string]any{"statement": []any{map[string]any{
				"effect": "Allow", "actions": []any{"rds-db:connect"}, "resources": []any{nil},
			}}},
		}
		refIdx := configIndex{resources: map[string]exprSet{
			"aws_iam_policy_document.ref": {refs: map[string][]string{
				"statement": {"aws_db_instance.main.resource_id", "aws_db_instance.main"},
			}},
		}}
		scope, grants, _ := awsDBScope(dbEl, []planResource{refDoc}, refIdx, resources, nil)
		if scope != "resource" {
			t.Fatalf("scope=%q grants=%v want resource via config ref", scope, grants)
		}
	})
}

func TestParseDBAuthzScopeAWS(t *testing.T) {
	cases := []struct {
		name      string
		policy    string // IAM policy JSON on task role; empty = password-only
		managedARN bool
		wantScope string
		wantGrants string
	}{
		{
			name: "wildcard_connect",
			policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["rds-db:connect"],"Resource":["*"]}]}`,
			wantScope: "account", wantGrants: "account",
		},
		{
			name: "scoped_dbuser",
			policy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["rds-db:connect"],"Resource":["arn:aws:rds-db:us-east-1:111122223333:dbuser:db-ABCDEF/app"]}]}`,
			wantScope: "resource", wantGrants: "resource",
		},
		{
			name: "password_only",
			wantScope: "",
		},
		{
			name: "managed_policy_arn_only",
			managedARN: true,
			wantScope: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := dbAuthzECSPlan(t, tc.policy, tc.managedARN)
			doc, _, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "fray.yaml",
				Source{Repo: "t/db-authz", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var dbFlow *Flow
			for i := range doc.Flows {
				f := &doc.Flows[i]
				for _, el := range doc.Elements {
					if el.ID == f.To && el.Kind == "relational_db" {
						dbFlow = f
						break
					}
				}
				if dbFlow != nil {
					break
				}
			}
			if dbFlow == nil {
				t.Fatal("expected container → relational_db flow")
			}
			if dbFlow.AuthzScope != tc.wantScope {
				t.Fatalf("authz_scope=%q want %q grants=%v", dbFlow.AuthzScope, tc.wantScope, dbFlow.AuthzGrants)
			}
			if tc.wantGrants != "" && strings.Join(dbFlow.AuthzGrants, ",") != tc.wantGrants {
				t.Fatalf("grants=%v want %s", dbFlow.AuthzGrants, tc.wantGrants)
			}
			if tc.wantScope == "" && len(dbFlow.AuthzGrants) != 0 {
				t.Fatalf("grants=%v want empty", dbFlow.AuthzGrants)
			}
		})
	}
}

// dbAuthzECSPlan builds module.ecs + module.db linked by security groups, with
// an optional task-role policy for rds-db:connect.
func dbAuthzECSPlan(t *testing.T, policyJSON string, managedARNOnly bool) string {
	t.Helper()
	resources := []map[string]any{
		{
			"address": "aws_security_group.tasks", "mode": "managed", "type": "aws_security_group", "name": "tasks",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{}},
		},
		{
			"address": "aws_security_group.db", "mode": "managed", "type": "aws_security_group", "name": "db",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"ingress": []any{map[string]any{"from_port": 5432, "to_port": 5432, "protocol": "tcp"}},
			}},
		},
		{
			"address": "module.ecs.aws_ecs_service.this", "mode": "managed", "type": "aws_ecs_service", "name": "this",
			"module_address": "module.ecs",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "app"}},
		},
		{
			"address": "module.ecs.aws_ecs_task_definition.this", "mode": "managed", "type": "aws_ecs_task_definition", "name": "this",
			"module_address": "module.ecs",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"family":                "app",
				"container_definitions": `[{"name":"app","image":"app:1"}]`,
			}, "after_unknown": map[string]any{"task_role_arn": true}},
		},
		{
			"address": "module.ecs.aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task",
			"module_address": "module.ecs",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{"name": "task"},
				"after_unknown": map[string]any{"inline_policy": true, "managed_policy_arns": true}},
		},
		{
			"address": "module.db.aws_db_instance.this", "mode": "managed", "type": "aws_db_instance", "name": "this",
			"module_address": "module.db",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"identifier": "main", "resource_id": "db-ABCDEF", "engine": "postgres",
			}},
		},
	}
	roleExprs := map[string]any{}
	if managedARNOnly {
		resources[4]["change"] = map[string]any{"actions": []any{"create"}, "after": map[string]any{
			"name": "task", "managed_policy_arns": []any{"arn:aws:iam::aws:policy/AmazonRDSFullAccess"},
		}, "after_unknown": map[string]any{"inline_policy": true}}
		roleExprs["managed_policy_arns"] = map[string]any{
			"constant_value": []any{"arn:aws:iam::aws:policy/AmazonRDSFullAccess"},
		}
	} else if policyJSON != "" {
		resources = append(resources, map[string]any{
			"address": "module.ecs.aws_iam_role_policy.db", "mode": "managed", "type": "aws_iam_role_policy", "name": "db",
			"module_address": "module.ecs",
			"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
				"name": "db-access", "policy": policyJSON,
			}},
		})
	}

	cfgResources := []map[string]any{
		{"address": "aws_security_group.tasks", "type": "aws_security_group", "name": "tasks", "expressions": map[string]any{}},
		{"address": "aws_security_group.db", "type": "aws_security_group", "name": "db", "expressions": map[string]any{
			"ingress": map[string]any{"references": []any{"aws_security_group.tasks.id", "aws_security_group.tasks"}},
		}},
	}
	ecsModResources := []map[string]any{
		{"address": "aws_ecs_service.this", "type": "aws_ecs_service", "name": "this", "expressions": map[string]any{
			"task_definition": map[string]any{"references": []any{"aws_ecs_task_definition.this.arn", "aws_ecs_task_definition.this"}},
		}},
		{"address": "aws_ecs_task_definition.this", "type": "aws_ecs_task_definition", "name": "this", "expressions": map[string]any{
			"task_role_arn": map[string]any{"references": []any{"aws_iam_role.task.arn", "aws_iam_role.task"}},
		}},
		{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task", "expressions": roleExprs},
	}
	if policyJSON != "" && !managedARNOnly {
		ecsModResources = append(ecsModResources, map[string]any{
			"address": "aws_iam_role_policy.db", "type": "aws_iam_role_policy", "name": "db",
			"expressions": map[string]any{
				"role":   map[string]any{"references": []any{"aws_iam_role.task.id", "aws_iam_role.task"}},
				"policy": map[string]any{"constant_value": policyJSON},
			},
		})
	}
	dbModResources := []map[string]any{
		{"address": "aws_db_instance.this", "type": "aws_db_instance", "name": "this", "expressions": map[string]any{}},
	}

	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": resources,
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": cfgResources,
				"module_calls": map[string]any{
					"ecs": map[string]any{
						"source": "./ecs",
						"expressions": map[string]any{
							"security_group_ids": map[string]any{"references": []any{"aws_security_group.tasks.id", "aws_security_group.tasks"}},
						},
						"module": map[string]any{"resources": ecsModResources},
					},
					"db": map[string]any{
						"source": "./db",
						"expressions": map[string]any{
							"vpc_security_group_ids": map[string]any{"references": []any{"aws_security_group.db.id", "aws_security_group.db"}},
						},
						"module": map[string]any{"resources": dbModResources},
					},
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
