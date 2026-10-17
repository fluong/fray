package client

import (
	"encoding/json"
	"testing"
)

func TestParseCloudSQLAdminDBControl(t *testing.T) {
	plan := cloudSQLAdminControlPlanJSON()
	doc, warnings, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "t/cloudsql-admin", Commit: "a000001", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_ = warnings
	var sqlFlow *Flow
	for i := range doc.Flows {
		f := &doc.Flows[i]
		if f.AuthzDBControlScope == "account" && len(f.AuthzDBControlClasses) == 4 {
			sqlFlow = f
			break
		}
	}
	if sqlFlow == nil {
		t.Fatalf("expected Cloud Run → Cloud SQL flow (elements=%d flows=%d)", len(doc.Elements), len(doc.Flows))
	}
	if sqlFlow.AuthzScope != "project" {
		t.Fatalf("authz_scope=%q want project (client role)", sqlFlow.AuthzScope)
	}
	if sqlFlow.AuthzDBControlScope != "account" {
		t.Fatalf("control scope=%q want account", sqlFlow.AuthzDBControlScope)
	}
	if len(sqlFlow.AuthzDBControlClasses) != 4 {
		t.Fatalf("control classes=%v", sqlFlow.AuthzDBControlClasses)
	}
	if sqlFlow.Causes["authz_db_control_classes"] != "google_project_iam_member.admin" {
		t.Fatalf("control cause=%q", sqlFlow.Causes["authz_db_control_classes"])
	}
}

func cloudSQLAdminControlPlanJSON() string {
	base := cloudSQLAuthzPlanJSON("")
	var root map[string]any
	if err := json.Unmarshal([]byte(base), &root); err != nil {
		panic(err)
	}
	sa := "fray-api@demo.iam.gserviceaccount.com"
	adminAfter := map[string]any{
		"role": "roles/cloudsql.admin", "member": "serviceAccount:" + sa, "project": "demo",
	}
	rc := root["resource_changes"].([]any)
	rc = append(rc, map[string]any{
		"address": "google_project_iam_member.admin", "mode": "managed",
		"type": "google_project_iam_member", "name": "admin",
		"change": map[string]any{"actions": []any{"create"}, "after": adminAfter},
	})
	root["resource_changes"] = rc
	cfg := root["configuration"].(map[string]any)["root_module"].(map[string]any)
	res := cfg["resources"].([]any)
	res = append(res, map[string]any{
		"address": "google_project_iam_member.admin", "type": "google_project_iam_member", "name": "admin",
		"expressions": map[string]any{
			"role":   map[string]any{"constant_value": "roles/cloudsql.admin"},
			"member": map[string]any{"constant_value": "serviceAccount:" + sa},
		},
	})
	cfg["resources"] = res
	b, _ := json.Marshal(root)
	return string(b)
}
