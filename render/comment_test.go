package render

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
)

func TestPRCommentAWSAdvisoryFR007(t *testing.T) {
	root := filepath.Join("..", "testdata")
	doc := loadDFD(t, filepath.Join(root, "fixtures", "aws-advisory.dfd.json"))
	injectFlowCause(doc, "f4545fe8f60fa981b", "authz_scope", "module.ecs_service.data.aws_iam_policy_document.execution[0]")
	base := loadFindings(t, filepath.Join(root, "fixtures", "aws-baseline.findings.json"))
	cur := loadFindings(t, filepath.Join(root, "fixtures", "aws-advisory-fr007.findings.json"))
	texts := loadTexts(t, filepath.Join(root, "fixtures", "rule_texts.json"))
	locs, err := client.ResourceLocations(filepath.Join(root, "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	// Baseline compare: only task_exec_secret_arns changed to ["*"].
	changed := map[string][]string{"module.ecs_service": {"task_exec_secret_arns"}}
	got := PRComment(doc, cur, base, texts, locs, changed, "")
	want := readGolden(t, filepath.Join(root, "golden", "pr-comment-aws-advisory-fr007.md"))
	if got != want {
		t.Fatalf("comment mismatch:\n%s", got)
	}
}

func TestPRCommentAWSAdvisoryFR007IAMStatements(t *testing.T) {
	// Exact demo PR #1: secret_arns unchanged; task_exec_iam_statements added with Resource "*".
	root := filepath.Join("..", "testdata")
	doc := loadDFD(t, filepath.Join(root, "fixtures", "aws-advisory.dfd.json"))
	injectFlowCause(doc, "f4545fe8f60fa981b", "authz_scope", "module.ecs_service.data.aws_iam_policy_document.execution[0]")
	base := loadFindings(t, filepath.Join(root, "fixtures", "aws-baseline.findings.json"))
	cur := loadFindings(t, filepath.Join(root, "fixtures", "aws-advisory-fr007.findings.json"))
	texts := loadTexts(t, filepath.Join(root, "fixtures", "rule_texts.json"))
	locs, err := client.ResourceLocations(filepath.Join(root, "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	changed := map[string][]string{"module.ecs_service": {"task_exec_iam_statements"}}
	got := PRComment(doc, cur, base, texts, locs, changed, "")
	want := readGolden(t, filepath.Join(root, "golden", "pr-comment-aws-advisory-fr007-iam-statements.md"))
	if got != want {
		t.Fatalf("comment mismatch:\n%s", got)
	}
}

func TestPRCommentAWSAdvisoryFR007OmitsGuessedInputs(t *testing.T) {
	root := filepath.Join("..", "testdata")
	doc := loadDFD(t, filepath.Join(root, "fixtures", "aws-advisory.dfd.json"))
	injectFlowCause(doc, "f4545fe8f60fa981b", "authz_scope", "module.ecs_service.data.aws_iam_policy_document.execution[0]")
	base := loadFindings(t, filepath.Join(root, "fixtures", "aws-baseline.findings.json"))
	cur := loadFindings(t, filepath.Join(root, "fixtures", "aws-advisory-fr007.findings.json"))
	texts := loadTexts(t, filepath.Join(root, "fixtures", "rule_texts.json"))
	locs, err := client.ResourceLocations(filepath.Join(root, "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	got := PRComment(doc, cur, base, texts, locs, nil, "")
	if strings.Contains(got, "task_exec_") {
		t.Fatalf("must omit inputs without a baseline compare:\n%s", got)
	}
	if !strings.Contains(got, "`module.ecs_service` · aws-web-app/main.tf:112") {
		t.Fatalf("want module call + file:line only:\n%s", got)
	}
}

func TestPRCommentGCPAdvisoryFR007(t *testing.T) {
	doc := client.DFD{
		Elements: []client.Element{
			{ID: "e-api", Name: "fray-api", Kind: "container_service", Provider: "gcp"},
			{
				ID: "e-secret", Name: "fray-database-url", Kind: "secret_store", Provider: "gcp",
				Evidence: client.Evidence{Addresses: []string{"google_secret_manager_secret.database_url"}},
			},
		},
		Flows: []client.Flow{{
			ID: "f-cred", From: "e-secret", To: "e-api", DataClass: "credentials",
			SecretDelivery: "env", AuthzScope: "project",
			Causes: map[string]string{"authz_scope": "google_project_iam_member.database_url_accessor"},
		}},
	}
	base := apiv1.Findings{Findings: []apiv1.Finding{{
		RuleID: "FR-007", Target: "f-cred", Status: "mitigated", Severity: "medium",
	}}}
	cur := apiv1.Findings{Findings: []apiv1.Finding{{
		RuleID: "FR-007", Target: "f-cred", Status: "open", Severity: "medium",
		Stride: []string{"elevation_of_privilege"},
	}}}
	texts := loadTexts(t, filepath.Join("..", "testdata", "fixtures", "rule_texts.json"))
	dir := t.TempDir()
	infra := filepath.Join(dir, "infra")
	if err := os.MkdirAll(infra, 0o755); err != nil {
		t.Fatal(err)
	}
	src := `
resource "google_project_iam_member" "database_url_accessor" {
  role   = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:run@example.iam.gserviceaccount.com"
}
`
	if err := os.WriteFile(filepath.Join(infra, "main.tf"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	locs, err := client.ResourceLocations(infra)
	if err != nil {
		t.Fatal(err)
	}
	got := PRComment(doc, cur, base, texts, locs, nil, "")
	want := readGolden(t, filepath.Join("..", "testdata", "golden", "pr-comment-gcp-advisory-fr007.md"))
	if got != want {
		t.Fatalf("comment mismatch:\n%s", got)
	}
}

func TestPRCommentAWSBlockingHigh(t *testing.T) {
	root := filepath.Join("..", "testdata")
	doc := loadDFD(t, filepath.Join(root, "fixtures", "aws-blocking.dfd.json"))
	injectElementCause(doc, "e269fe54ebe835ad4", "public", "module.uploads.aws_s3_bucket_public_access_block.this[0]")
	base := loadFindings(t, filepath.Join(root, "fixtures", "aws-baseline.findings.json"))
	cur := loadFindings(t, filepath.Join(root, "fixtures", "aws-blocking-high.findings.json"))
	texts := loadTexts(t, filepath.Join(root, "fixtures", "rule_texts.json"))
	locs, err := client.ResourceLocations(filepath.Join(root, "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	changed := map[string][]string{
		"module.uploads": {
			"block_public_acls",
			"block_public_policy",
			"ignore_public_acls",
			"restrict_public_buckets",
		},
	}
	got := PRComment(doc, cur, base, texts, locs, changed, "")
	want := readGolden(t, filepath.Join(root, "golden", "pr-comment-aws-blocking-high.md"))
	if got != want {
		t.Fatalf("comment mismatch:\n%s", got)
	}
}

func TestPRCommentByteIdenticalWithRedaction(t *testing.T) {
	// Redaction changes wire ids only. After mapping findings back, PR comments
	// must match the unredacted golden output for both AWS scenarios.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	root := filepath.Join("..", "testdata")
	locs, err := client.ResourceLocations(filepath.Join(root, "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	texts := loadTexts(t, filepath.Join(root, "fixtures", "rule_texts.json"))

	cases := []struct {
		name    string
		dfd     string
		cur     string
		base    string
		golden  string
		inject  func(client.DFD)
		changed map[string][]string
	}{
		{
			name:   "advisory-fr007",
			dfd:    "aws-advisory.dfd.json",
			cur:    "aws-advisory-fr007.findings.json",
			base:   "aws-baseline.findings.json",
			golden: "pr-comment-aws-advisory-fr007.md",
			inject: func(doc client.DFD) {
				injectFlowCause(doc, "f4545fe8f60fa981b", "authz_scope", "module.ecs_service.data.aws_iam_policy_document.execution[0]")
			},
			changed: map[string][]string{"module.ecs_service": {"task_exec_secret_arns"}},
		},
		{
			name:   "blocking-high",
			dfd:    "aws-blocking.dfd.json",
			cur:    "aws-blocking-high.findings.json",
			base:   "aws-baseline.findings.json",
			golden: "pr-comment-aws-blocking-high.md",
			inject: func(doc client.DFD) {
				injectElementCause(doc, "e269fe54ebe835ad4", "public", "module.uploads.aws_s3_bucket_public_access_block.this[0]")
			},
			changed: map[string][]string{
				"module.uploads": {
					"block_public_acls",
					"block_public_policy",
					"ignore_public_acls",
					"restrict_public_buckets",
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := loadDFD(t, filepath.Join(root, "fixtures", tc.dfd))
			tc.inject(doc)
			base := loadFindings(t, filepath.Join(root, "fixtures", tc.base))
			cur := loadFindings(t, filepath.Join(root, "fixtures", tc.cur))
			want := readGolden(t, filepath.Join(root, "golden", tc.golden))

			off := PRComment(doc, cur, base, texts, locs, tc.changed, "")
			if off != want {
				t.Fatalf("unredacted comment drifted from golden")
			}

			_, idMap, err := client.Redact(doc, key)
			if err != nil {
				t.Fatal(err)
			}
			// Simulate server response that cites redacted ids, then client remap.
			curWire := remapFindingsCopy(cur, idMap.ToRedacted)
			baseWire := remapFindingsCopy(base, idMap.ToRedacted)
			curLocal := remapFindingsCopy(curWire, idMap.ToPlain)
			baseLocal := remapFindingsCopy(baseWire, idMap.ToPlain)
			on := PRComment(doc, curLocal, baseLocal, texts, locs, tc.changed, "")
			if on != want {
				t.Fatalf("redacted-path comment not byte-identical to golden")
			}
			if on != off {
				t.Fatalf("redaction on/off comments differ")
			}
		})
	}
}

func remapFindingsCopy(in apiv1.Findings, m map[string]string) apiv1.Findings {
	out := in
	out.Findings = make([]apiv1.Finding, len(in.Findings))
	copy(out.Findings, in.Findings)
	for i := range out.Findings {
		if rid, ok := m[out.Findings[i].Target]; ok {
			out.Findings[i].Target = rid
		}
	}
	return out
}

func injectFlowCause(doc client.DFD, id, field, cause string) {
	for i := range doc.Flows {
		if doc.Flows[i].ID != id {
			continue
		}
		if doc.Flows[i].Causes == nil {
			doc.Flows[i].Causes = map[string]string{}
		}
		doc.Flows[i].Causes[field] = cause
	}
}

func injectElementCause(doc client.DFD, id, field, cause string) {
	for i := range doc.Elements {
		if doc.Elements[i].ID != id {
			continue
		}
		if doc.Elements[i].Causes == nil {
			doc.Elements[i].Causes = map[string]string{}
		}
		doc.Elements[i].Causes[field] = cause
	}
}

func loadDFD(t *testing.T, path string) client.DFD {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d client.DFD
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func loadFindings(t *testing.T, path string) apiv1.Findings {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f apiv1.Findings
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func loadTexts(t *testing.T, path string) map[string]apiv1.RuleText {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var texts map[string]apiv1.RuleText
	if err := json.Unmarshal(raw, &texts); err != nil {
		t.Fatal(err)
	}
	return texts
}

func readGolden(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
