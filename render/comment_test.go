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
	got := PRComment(doc, cur, base, texts, locs, changed, "", nil, nil)
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
	got := PRComment(doc, cur, base, texts, locs, changed, "", nil, nil)
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
	got := PRComment(doc, cur, base, texts, locs, nil, "", nil, nil)
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
	got := PRComment(doc, cur, base, texts, locs, nil, "", nil, nil)
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
	got := PRComment(doc, cur, base, texts, locs, changed, "", nil, nil)
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

			off := PRComment(doc, cur, base, texts, locs, tc.changed, "", nil, nil)
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
			on := PRComment(doc, curLocal, baseLocal, texts, locs, tc.changed, "", nil, nil)
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

// Target-text goldens (*-target.md) are hand-written expected output, not
// recorded model responses (see testdata/golden/README.md).

func TestPRCommentFR007EnrichmentTarget(t *testing.T) {
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
	enrichments := []apiv1.FindingEnrichment{{
		RuleID:  "FR-007",
		Target:  "f4545fe8f60fa981b",
		WhyHere: "{e84ae99cb3fa981eb} already has a resource-scoped grant to {ea971486d1a0a3baf} alongside this account-wide path.",
		FixHere: "Drop the account-wide grant; the secret-scoped grant already authorizes this flow.",
	}}
	// Duplicate advisory content must be dropped — no Advisory section.
	advisory := &apiv1.Advisory{
		Observations: []apiv1.AdvisoryObservation{{
			Stride:     "elevation_of_privilege",
			ElementIDs: []string{"e84ae99cb3fa981eb", "ea971486d1a0a3baf"},
			Text:       "{e84ae99cb3fa981eb} already has a resource-scoped grant to {ea971486d1a0a3baf} alongside this account-wide path.",
			Suggestion: "Drop the account-wide grant; the secret-scoped grant already authorizes this flow.",
		}},
	}
	got := PRComment(doc, cur, base, texts, locs, changed, "", advisory, enrichments)
	want := readGolden(t, filepath.Join(root, "golden", "pr-comment-aws-fr007-enrichment-target.md"))
	if got != want {
		t.Fatalf("comment mismatch:\n%s", got)
	}
	if strings.Contains(got, "Advisory (AI)") {
		t.Fatal("Advisory section must be omitted when it only restates enrichment")
	}
}

func TestPRCommentFR025EnrichmentTarget(t *testing.T) {
	root := filepath.Join("..", "testdata")
	doc := loadDFD(t, filepath.Join(root, "fixtures", "aws-blocking-fr025.dfd.json"))
	injectElementCause(doc, "e269fe54ebe835ad4", "public_access_blocked", "module.uploads.aws_s3_bucket.this[0]")
	base := loadFindings(t, filepath.Join(root, "fixtures", "aws-baseline.findings.json"))
	cur := loadFindings(t, filepath.Join(root, "fixtures", "aws-blocking-fr025.findings.json"))
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
	enrichments := []apiv1.FindingEnrichment{{
		RuleID:  "FR-025",
		Target:  "e269fe54ebe835ad4",
		WhyHere: "ACLs are already disabled on this bucket, so a bucket policy is now the only way it could become public — and nothing blocks one anymore.",
	}}
	got := PRComment(doc, cur, base, texts, locs, changed, "", nil, enrichments)
	want := readGolden(t, filepath.Join(root, "golden", "pr-comment-aws-fr025-enrichment-target.md"))
	if got != want {
		t.Fatalf("comment mismatch:\n%s", got)
	}
	if strings.Contains(got, "Advisory (AI)") {
		t.Fatal("Advisory section must be omitted for enrichment-only demo golden")
	}
}

func TestPRCommentAdvisoryEmptyOmitsSection(t *testing.T) {
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
	got := PRComment(doc, cur, base, texts, locs, changed, "", &apiv1.Advisory{}, nil)
	if strings.Contains(got, "Advisory (AI)") {
		t.Fatalf("empty advisory must omit section:\n%s", got)
	}
	got = PRComment(doc, cur, base, texts, locs, changed, "", nil, nil)
	if strings.Contains(got, "Advisory (AI)") {
		t.Fatalf("nil advisory must omit section:\n%s", got)
	}
}

func TestPRCommentAdvisoryNovelTarget(t *testing.T) {
	root := filepath.Join("..", "testdata")
	doc := loadDFD(t, filepath.Join(root, "fixtures", "aws-blocking-fr025.dfd.json"))
	texts := loadTexts(t, filepath.Join(root, "fixtures", "rule_texts.json"))
	locs, err := client.ResourceLocations(filepath.Join(root, "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	// No finding delta — only a novel advisory observation.
	base := loadFindings(t, filepath.Join(root, "fixtures", "aws-baseline.findings.json"))
	cur := loadFindings(t, filepath.Join(root, "fixtures", "aws-baseline.findings.json"))
	advisory := &apiv1.Advisory{
		Observations: []apiv1.AdvisoryObservation{{
			Stride:     "tampering",
			ElementIDs: []string{"e269fe54ebe835ad4"},
			Text:       "Object lock is off on {e269fe54ebe835ad4} while a process holds write credentials into it.",
			Suggestion: "Enable object lock, or remove write credentials from non-audit principals.",
		}},
	}
	got := PRComment(doc, cur, base, texts, locs, nil, "", advisory, nil)
	want := readGolden(t, filepath.Join(root, "golden", "pr-comment-advisory-novel-target.md"))
	if got != want {
		t.Fatalf("comment mismatch:\n%s", got)
	}
}

func TestSanitizeAdvisoryText(t *testing.T) {
	in := "See [docs](https://evil.example) and <script>x</script> **bold** `code`"
	got := SanitizeAdvisoryText(in)
	for _, bad := range []string{"http", "<", "**", "`"} {
		if strings.Contains(got, bad) {
			t.Fatalf("still contains %q: %q", bad, got)
		}
	}
	if !strings.Contains(got, "docs") || !strings.Contains(got, "bold") || !strings.Contains(got, "code") {
		t.Fatalf("lost text: %q", got)
	}
}
