package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoverageDBWorkerTrimmedRealPlan(t *testing.T) {
	planPath := filepath.Join("testdata", "coverage-db-worker-plan.json")
	plan, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "",
		Source{Repo: "fluong/fray-demo-coverage", Commit: "trimmed", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "aws_autoscaling_group.db_worker") {
			t.Fatalf("unexpected db_worker warning: %s", w)
		}
		if strings.HasPrefix(w, "IAM flows omitted for aws_autoscaling_group.db_worker") {
			t.Fatalf("unexpected omit: %s", w)
		}
	}
	var dbFlow *Flow
	byID := map[string]Element{}
	for _, el := range doc.Elements {
		byID[el.ID] = el
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		from := byID[f.From]
		to := byID[f.To]
		if from.Kind == "virtual_machine" && len(from.Evidence.Addresses) > 0 &&
			from.Evidence.Addresses[0] == "aws_autoscaling_group.db_worker" && to.Kind == "relational_db" {
			dbFlow = f
		}
	}
	if dbFlow == nil {
		t.Fatalf("want ASG→RDS flow")
	}
	if dbFlow.AuthzScope != "account" {
		t.Fatalf("authz_scope=%q want account", dbFlow.AuthzScope)
	}
	if dbFlow.Causes["authz_scope"] != "aws_iam_role_policy.asg_db_rds" {
		t.Fatalf("cause=%q", dbFlow.Causes["authz_scope"])
	}
}
