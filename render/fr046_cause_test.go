package render

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
)

func TestFR046CauseAddressDistinctFingerprints(t *testing.T) {
	plan, err := os.ReadFile(filepath.Join("..", "client", "testdata", "coverage-db-control-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, _, err := client.Parse(plan, []byte("schema_version: fray-config/v1\n"), "",
		client.Source{Repo: "fluong/fray", Commit: "coverage", Tool: "terraform", Fidelity: "plan"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exists := apiv1.Condition{Op: "exists", Field: "authz_db_control_classes"}
	rule := apiv1.RuleText{
		ID: "FR-046",
		Pass: []apiv1.Condition{{
			Op:   "not",
			Cond: &exists,
		}},
	}
	byID := map[string]client.Element{}
	flows := map[string]client.Flow{}
	for _, el := range doc.Elements {
		byID[el.ID] = el
	}
	for _, f := range doc.Flows {
		flows[f.ID] = f
	}
	want := map[string]string{
		"aws_ecs_service.app":                 "data.aws_iam_policy_document.app_db_control",
		"aws_ecs_service.db_control_wildcard": "aws_iam_role_policy.db_control_wildcard",
	}
	gotCause := map[string]string{}
	for id, f := range flows {
		to := byID[f.To]
		from := byID[f.From]
		if to.Kind != "relational_db" || len(f.AuthzDBControlClasses) == 0 {
			continue
		}
		fa := ""
		if len(from.Evidence.Addresses) > 0 {
			fa = from.Evidence.Addresses[0]
		}
		wantCause, ok := want[fa]
		if !ok {
			continue
		}
		cause := CauseAddress(apiv1.Finding{RuleID: "FR-046", Target: id, Status: "open"}, rule, byID, flows)
		if cause != wantCause {
			t.Fatalf("%s CauseAddress=%q want %q", fa, cause, wantCause)
		}
		gotCause[fa] = cause
	}
	if len(gotCause) != 2 {
		t.Fatalf("want 2 control-plane flows, got %v", gotCause)
	}
	fp := func(cause string) string {
		sum := sha256.Sum256([]byte("FR-046|" + cause))
		return hex.EncodeToString(sum[:])
	}
	if fp(gotCause["aws_ecs_service.app"]) == fp(gotCause["aws_ecs_service.db_control_wildcard"]) {
		t.Fatal("fingerprints must differ for D and E")
	}
}
