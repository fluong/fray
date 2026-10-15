package client

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCloudSQLScopeTable(t *testing.T) {
	sql := planResource{
		address: "google_sql_database_instance.main",
		typ:     "google_sql_database_instance",
		values:  map[string]any{"name": "main-db", "project": "p"},
	}
	sa := "app@p.iam.gserviceaccount.com"
	idx := configIndex{resources: map[string]exprSet{}}

	member := func(addr, role, expression string) planResource {
		vals := map[string]any{
			"role":   role,
			"member": "serviceAccount:" + sa,
		}
		if expression != "" {
			vals["condition"] = map[string]any{
				"title": "this", "expression": expression,
			}
		}
		return planResource{address: addr, typ: "google_project_iam_member", values: vals}
	}

	t.Run("unconditional_project", func(t *testing.T) {
		scope, grants, _ := cloudSQLScope(sa, sql, []planResource{
			member("google_project_iam_member.client", "roles/cloudsql.client", ""),
		}, idx)
		if scope != "project" || strings.Join(grants, ",") != "project" {
			t.Fatalf("scope=%q grants=%v", scope, grants)
		}
	})
	t.Run("condition_literal_resource", func(t *testing.T) {
		expr := `resource.name == "projects/p/instances/main-db"`
		scope, grants, _ := cloudSQLScope(sa, sql, []planResource{
			member("google_project_iam_member.scoped", "roles/cloudsql.client", expr),
		}, idx)
		if scope != "resource" || strings.Join(grants, ",") != "resource" {
			t.Fatalf("scope=%q grants=%v", scope, grants)
		}
	})
	t.Run("condition_with_type_clause", func(t *testing.T) {
		expr := `resource.name == "projects/p/instances/main-db" && resource.type == "sqladmin.googleapis.com/Instance"`
		scope, _, _ := cloudSQLScope(sa, sql, []planResource{
			member("google_project_iam_member.typed", "roles/cloudsql.client", expr),
		}, idx)
		if scope != "resource" {
			t.Fatalf("scope=%q want resource", scope)
		}
	})
	t.Run("condition_other_instance_omitted", func(t *testing.T) {
		expr := `resource.name == "projects/p/instances/other-db"`
		scope, grants, _ := cloudSQLScope(sa, sql, []planResource{
			member("google_project_iam_member.other", "roles/cloudsql.client", expr),
		}, idx)
		if scope != "" || len(grants) != 0 {
			t.Fatalf("scope=%q grants=%v want omit", scope, grants)
		}
	})
	t.Run("unparseable_condition_omitted", func(t *testing.T) {
		scope, grants, _ := cloudSQLScope(sa, sql, []planResource{
			member("google_project_iam_member.weird", "roles/cloudsql.client", `request.time < timestamp("2020-01-01T00:00:00Z")`),
		}, idx)
		if scope != "" || len(grants) != 0 {
			t.Fatalf("scope=%q grants=%v want omit", scope, grants)
		}
	})
	t.Run("both_project_wins", func(t *testing.T) {
		expr := `resource.name == "projects/p/instances/main-db"`
		scope, grants, _ := cloudSQLScope(sa, sql, []planResource{
			member("google_project_iam_member.scoped", "roles/cloudsql.client", expr),
			member("google_project_iam_member.wide", "roles/cloudsql.client", ""),
		}, idx)
		if scope != "project" {
			t.Fatalf("scope=%q want project", scope)
		}
		if strings.Join(grants, ",") != "resource,project" {
			t.Fatalf("grants=%v", grants)
		}
	})
	t.Run("condition_name_ref", func(t *testing.T) {
		m := planResource{
			address: "google_project_iam_member.ref",
			typ:     "google_project_iam_member",
			values: map[string]any{
				"role":   "roles/cloudsql.client",
				"member": "serviceAccount:" + sa,
				// expression unknown at plan; config refs the instance name
			},
		}
		refIdx := configIndex{resources: map[string]exprSet{
			"google_project_iam_member.ref": {refs: map[string][]string{
				"condition": {"google_sql_database_instance.main.name", "google_sql_database_instance.main"},
			}},
		}}
		scope, _, _ := cloudSQLScope(sa, sql, []planResource{m}, refIdx)
		if scope != "resource" {
			t.Fatalf("scope=%q want resource via condition name ref", scope)
		}
	})
	t.Run("condition_unknown_var_refs_omitted", func(t *testing.T) {
		m := planResource{
			address: "google_project_iam_member.varcond",
			typ:     "google_project_iam_member",
			values: map[string]any{
				"role":   "roles/cloudsql.client",
				"member": "serviceAccount:" + sa,
				// condition block present; expression unreadable
			},
			afterUnknown: map[string]any{"condition": true},
		}
		varIdx := configIndex{resources: map[string]exprSet{
			"google_project_iam_member.varcond": {
				raw:  map[string]any{"condition": map[string]any{}},
				refs: map[string][]string{"condition": {"var.condition_expr"}},
			},
		}}
		scope, grants, _ := cloudSQLScope(sa, sql, []planResource{m}, varIdx)
		if scope != "" || len(grants) != 0 {
			t.Fatalf("scope=%q grants=%v want omit (condition present, unreadable)", scope, grants)
		}
	})
	t.Run("binding_members_list", func(t *testing.T) {
		b := planResource{
			address: "google_project_iam_binding.client",
			typ:     "google_project_iam_binding",
			values: map[string]any{
				"role":    "roles/cloudsql.client",
				"members": []any{"serviceAccount:" + sa, "serviceAccount:other@p.iam.gserviceaccount.com"},
			},
		}
		scope, _, _ := cloudSQLScope(sa, sql, []planResource{b}, idx)
		if scope != "project" {
			t.Fatalf("scope=%q want project", scope)
		}
	})
}

func TestParseCloudSQLAuthzScope(t *testing.T) {
	cases := []struct {
		name       string
		expression string // empty = unconditional
		wantScope  string
	}{
		{name: "unconditional", wantScope: "project"},
		{name: "scoped", expression: `resource.name == "projects/demo/instances/fray-db"`, wantScope: "resource"},
		{name: "other_instance", expression: `resource.name == "projects/demo/instances/other"`, wantScope: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := cloudSQLAuthzPlanJSON(tc.expression)
			doc, _, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "fray.yaml",
				Source{Repo: "t/sql-authz", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var sqlFlow *Flow
			for i := range doc.Flows {
				f := &doc.Flows[i]
				for _, el := range doc.Elements {
					if el.ID == f.To && el.Kind == "relational_db" && el.Provenance == "iac" {
						sqlFlow = f
						break
					}
				}
				if sqlFlow != nil {
					break
				}
			}
			if sqlFlow == nil {
				t.Fatal("expected Cloud Run → Cloud SQL attachment flow")
			}
			if sqlFlow.AuthzScope != tc.wantScope {
				t.Fatalf("authz_scope=%q want %q grants=%v", sqlFlow.AuthzScope, tc.wantScope, sqlFlow.AuthzGrants)
			}
		})
	}
}

func cloudSQLAuthzPlanJSON(conditionExpr string) string {
	sa := "fray-api@demo.iam.gserviceaccount.com"
	iamAfter := map[string]any{
		"role":    "roles/cloudsql.client",
		"member":  "serviceAccount:" + sa,
		"project": "demo",
	}
	iamExprs := map[string]any{
		"role":   map[string]any{"constant_value": "roles/cloudsql.client"},
		"member": map[string]any{"constant_value": "serviceAccount:" + sa},
	}
	if conditionExpr != "" {
		iamAfter["condition"] = []any{map[string]any{
			"title": "instance", "expression": conditionExpr,
		}}
		iamExprs["condition"] = map[string]any{
			"constant_value": []any{map[string]any{"title": "instance", "expression": conditionExpr}},
		}
	}
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			map[string]any{
				"address": "google_cloud_run_v2_service.api", "mode": "managed",
				"type": "google_cloud_run_v2_service", "name": "api",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"name": "api",
					"template": []any{map[string]any{
						"service_account": sa,
						"volumes": []any{map[string]any{
							"name": "cloudsql",
							"cloud_sql_instance": []any{map[string]any{
								"instances": []any{"demo:us-central1:fray-db"},
							}},
						}},
						"containers": []any{map[string]any{"image": "gcr.io/demo/api:1"}},
					}},
				}},
			},
			map[string]any{
				"address": "google_sql_database_instance.db", "mode": "managed",
				"type": "google_sql_database_instance", "name": "db",
				"change": map[string]any{"actions": []any{"create"}, "after": map[string]any{
					"name": "fray-db", "project": "demo", "region": "us-central1",
					"database_version": "POSTGRES_15",
					"settings": []any{map[string]any{
						"ip_configuration": []any{map[string]any{"ipv4_enabled": false}},
					}},
					"connection_name": "demo:us-central1:fray-db",
				}},
			},
			map[string]any{
				"address": "google_project_iam_member.client", "mode": "managed",
				"type": "google_project_iam_member", "name": "client",
				"change": map[string]any{"actions": []any{"create"}, "after": iamAfter},
			},
		},
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{
						"address": "google_cloud_run_v2_service.api", "type": "google_cloud_run_v2_service", "name": "api",
						"expressions": map[string]any{},
					},
					map[string]any{
						"address": "google_sql_database_instance.db", "type": "google_sql_database_instance", "name": "db",
						"expressions": map[string]any{},
					},
					map[string]any{
						"address": "google_project_iam_member.client", "type": "google_project_iam_member", "name": "client",
						"expressions": iamExprs,
					},
				},
			},
		},
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
