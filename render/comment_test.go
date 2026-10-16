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
	injectFlowCause(doc, "module.ecs_service.data.aws_iam_policy_document.execution[0]")
	base := loadFindings(t, filepath.Join(root, "fixtures", "aws-baseline.findings.json"))
	cur := loadFindings(t, filepath.Join(root, "fixtures", "aws-advisory-fr007.findings.json"))
	texts := loadTexts(t, filepath.Join(root, "fixtures", "rule_texts.json"))
	locs, err := client.ResourceLocations(filepath.Join(root, "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	// Baseline compare: only task_exec_secret_arns changed to ["*"].
	changed := map[string][]string{"module.ecs_service": {"task_exec_secret_arns"}}
	got := PRComment(doc, cur, base, texts, locs, changed, "", nil, nil, nil, true, nil)
	want := readGolden(t, filepath.Join(root, "golden", "pr-comment-aws-advisory-fr007.md"))
	if got != want {
		t.Fatalf("comment mismatch:\n%s", got)
	}
}

func TestPRCommentAWSAdvisoryFR007IAMStatements(t *testing.T) {
	// Exact demo PR #1: secret_arns unchanged; task_exec_iam_statements added with Resource "*".
	root := filepath.Join("..", "testdata")
	doc := loadDFD(t, filepath.Join(root, "fixtures", "aws-advisory.dfd.json"))
	injectFlowCause(doc, "module.ecs_service.data.aws_iam_policy_document.execution[0]")
	base := loadFindings(t, filepath.Join(root, "fixtures", "aws-baseline.findings.json"))
	cur := loadFindings(t, filepath.Join(root, "fixtures", "aws-advisory-fr007.findings.json"))
	texts := loadTexts(t, filepath.Join(root, "fixtures", "rule_texts.json"))
	locs, err := client.ResourceLocations(filepath.Join(root, "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	changed := map[string][]string{"module.ecs_service": {"task_exec_iam_statements"}}
	got := PRComment(doc, cur, base, texts, locs, changed, "", nil, nil, nil, true, nil)
	want := readGolden(t, filepath.Join(root, "golden", "pr-comment-aws-advisory-fr007-iam-statements.md"))
	if got != want {
		t.Fatalf("comment mismatch:\n%s", got)
	}
}

func TestPRCommentAWSAdvisoryFR007OmitsGuessedInputs(t *testing.T) {
	root := filepath.Join("..", "testdata")
	doc := loadDFD(t, filepath.Join(root, "fixtures", "aws-advisory.dfd.json"))
	injectFlowCause(doc, "module.ecs_service.data.aws_iam_policy_document.execution[0]")
	base := loadFindings(t, filepath.Join(root, "fixtures", "aws-baseline.findings.json"))
	cur := loadFindings(t, filepath.Join(root, "fixtures", "aws-advisory-fr007.findings.json"))
	texts := loadTexts(t, filepath.Join(root, "fixtures", "rule_texts.json"))
	locs, err := client.ResourceLocations(filepath.Join(root, "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	got := PRComment(doc, cur, base, texts, locs, nil, "", nil, nil, nil, true, nil)
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
	got := PRComment(doc, cur, base, texts, locs, nil, "", nil, nil, nil, true, nil)
	want := readGolden(t, filepath.Join("..", "testdata", "golden", "pr-comment-gcp-advisory-fr007.md"))
	if got != want {
		t.Fatalf("comment mismatch:\n%s", got)
	}
}

func TestPRCommentAWSBlockingHigh(t *testing.T) {
	root := filepath.Join("..", "testdata")
	doc := loadDFD(t, filepath.Join(root, "fixtures", "aws-blocking.dfd.json"))
	injectElementCause(doc, "public", "module.uploads.aws_s3_bucket_public_access_block.this[0]")
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
	got := PRComment(doc, cur, base, texts, locs, changed, "", nil, nil, nil, true, nil)
	want := readGolden(t, filepath.Join(root, "golden", "pr-comment-aws-blocking-high.md"))
	if got != want {
		t.Fatalf("comment mismatch:\n%s", got)
	}
}

func TestPRCommentNoBaselineAbsolute(t *testing.T) {
	root := filepath.Join("..", "testdata")
	doc := loadDFD(t, filepath.Join(root, "fixtures", "aws-blocking.dfd.json"))
	injectElementCause(doc, "public", "module.uploads.aws_s3_bucket_public_access_block.this[0]")
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
	empty := apiv1.Findings{SchemaVersion: "finding/v1"}
	got := PRComment(doc, cur, empty, texts, locs, changed, NoBaselineNote, nil, nil, nil, true, nil)
	wantPath := filepath.Join(root, "golden", "pr-comment-no-baseline.md")
	want, err := os.ReadFile(wantPath)
	if err != nil {
		_ = os.WriteFile("/tmp/pr-comment-no-baseline.md", []byte(got), 0o644)
		t.Fatalf("missing golden (wrote /tmp/pr-comment-no-baseline.md): %v", err)
	}
	if got != string(want) {
		_ = os.WriteFile("/tmp/pr-comment-no-baseline.md", []byte(got), 0o644)
		t.Fatalf("no-baseline comment drifted; wrote /tmp/pr-comment-no-baseline.md\n%s", got)
	}
	if !strings.HasPrefix(got, NoBaselineNote) {
		t.Fatalf("want no-baseline note first: %q", got)
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
				injectFlowCause(doc, "module.ecs_service.data.aws_iam_policy_document.execution[0]")
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
				injectElementCause(doc, "public", "module.uploads.aws_s3_bucket_public_access_block.this[0]")
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

			off := PRComment(doc, cur, base, texts, locs, tc.changed, "", nil, nil, nil, true, nil)
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
			on := PRComment(doc, curLocal, baseLocal, texts, locs, tc.changed, "", nil, nil, nil, true, nil)
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

func injectFlowCause(doc client.DFD, cause string) {
	const flowID = "f4545fe8f60fa981b"
	const field = "authz_scope"
	for i := range doc.Flows {
		if doc.Flows[i].ID != flowID {
			continue
		}
		if doc.Flows[i].Causes == nil {
			doc.Flows[i].Causes = map[string]string{}
		}
		doc.Flows[i].Causes[field] = cause
	}
}

func injectElementCause(doc client.DFD, field, cause string) {
	const elementID = "e269fe54ebe835ad4"
	for i := range doc.Elements {
		if doc.Elements[i].ID != elementID {
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
	injectFlowCause(doc, "module.ecs_service.data.aws_iam_policy_document.execution[0]")
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
		FixHere: "Drop the account-wide grant; the scoped grant already gives {e84ae99cb3fa981eb} access to {ea971486d1a0a3baf}.",
	}}
	// Duplicate advisory content must be dropped — no Advisory section.
	advisory := &apiv1.Advisory{
		Observations: []apiv1.AdvisoryObservation{{
			Stride:     "elevation_of_privilege",
			ElementIDs: []string{"e84ae99cb3fa981eb", "ea971486d1a0a3baf"},
			Text:       "{e84ae99cb3fa981eb} already has a resource-scoped grant to {ea971486d1a0a3baf} alongside this account-wide path.",
			Suggestion: "Drop the account-wide grant; the scoped grant already gives {e84ae99cb3fa981eb} access to {ea971486d1a0a3baf}.",
		}},
	}
	got := PRComment(doc, cur, base, texts, locs, changed, "", advisory, enrichments, nil, true, nil)
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
	injectElementCause(doc, "public_access_blocked", "module.uploads.aws_s3_bucket.this[0]")
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
	got := PRComment(doc, cur, base, texts, locs, changed, "", nil, enrichments, nil, true, nil)
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
	injectFlowCause(doc, "module.ecs_service.data.aws_iam_policy_document.execution[0]")
	base := loadFindings(t, filepath.Join(root, "fixtures", "aws-baseline.findings.json"))
	cur := loadFindings(t, filepath.Join(root, "fixtures", "aws-advisory-fr007.findings.json"))
	texts := loadTexts(t, filepath.Join(root, "fixtures", "rule_texts.json"))
	locs, err := client.ResourceLocations(filepath.Join(root, "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	changed := map[string][]string{"module.ecs_service": {"task_exec_iam_statements"}}
	got := PRComment(doc, cur, base, texts, locs, changed, "", &apiv1.Advisory{}, nil, nil, true, nil)
	if strings.Contains(got, "Advisory (AI)") {
		t.Fatalf("empty advisory must omit section:\n%s", got)
	}
	got = PRComment(doc, cur, base, texts, locs, changed, "", nil, nil, nil, true, nil)
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
	got := PRComment(doc, cur, base, texts, locs, nil, "", advisory, nil, nil, true, nil)
	want := readGolden(t, filepath.Join(root, "golden", "pr-comment-advisory-novel-target.md"))
	if got != want {
		t.Fatalf("comment mismatch:\n%s", got)
	}
}

func TestPRCommentNoDeltaWithWaivers(t *testing.T) {
	// Mirrors demo PR #13 shape: no open new/fixed, Waivers section present.
	root := filepath.Join("..", "testdata")
	doc := loadDFD(t, filepath.Join(root, "fixtures", "aws-blocking-fr025.dfd.json"))
	texts := loadTexts(t, filepath.Join(root, "fixtures", "rule_texts.json"))
	locs, err := client.ResourceLocations(filepath.Join(root, "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	base := loadFindings(t, filepath.Join(root, "fixtures", "aws-baseline.findings.json"))
	cur := loadFindings(t, filepath.Join(root, "fixtures", "aws-baseline.findings.json"))
	waivers := &apiv1.Waivers{Applied: []string{"waiver-demo"}}
	got := PRComment(doc, cur, base, texts, locs, nil, "", nil, nil, waivers, true, nil)
	want := readGolden(t, filepath.Join(root, "golden", "pr-comment-no-delta-waivers.md"))
	if got != want {
		t.Fatalf("comment mismatch:\n%s", got)
	}
}

func TestPRCommentNewRuleSuffix(t *testing.T) {
	doc := client.DFD{
		Elements: []client.Element{{
			ID: "e1111111111111111", Name: "uploads bucket", Kind: "object_storage",
			Evidence: client.Evidence{Addresses: []string{"aws_s3_bucket.uploads"}},
		}},
	}
	base := apiv1.Findings{SchemaVersion: "finding/v1"}
	cur := apiv1.Findings{Findings: []apiv1.Finding{{
		RuleID: "FR-AWS-0001", Target: "e1111111111111111", Status: "open",
		Severity: "high", Stride: []string{"information_disclosure"}, NewRule: true,
	}}}
	texts := map[string]apiv1.RuleText{
		"FR-AWS-0001": {
			ID: "FR-AWS-0001", Title: "Object storage is encrypted",
			Threat:      "Bucket is not encrypted at rest",
			GroupTitle:  "{label} is not encrypted at rest",
			Explanation: "{element} is not encrypted at rest.",
			Mitigation:  "Enable encryption at rest.",
			Severity:    "high", Stride: []string{"information_disclosure"},
			Pass: []apiv1.Condition{{Op: "equals", Field: "attributes.encrypted_at_rest", Value: true}},
		},
	}
	got := PRComment(doc, cur, base, texts, nil, nil, "", nil, nil, nil, true, nil)
	const suffix = " — new rule; not blocking until the default branch is rescanned"
	if !strings.Contains(got, "**Uploads bucket is not encrypted at rest**"+suffix) {
		t.Fatalf("missing new-rule suffix:\n%s", got)
	}
	// Without new_rule the suffix must not appear (older servers).
	cur.Findings[0].NewRule = false
	got = PRComment(doc, cur, base, texts, nil, nil, "", nil, nil, nil, true, nil)
	if strings.Contains(got, "new rule; not blocking") {
		t.Fatalf("suffix must be omitted when new_rule is false:\n%s", got)
	}
}

func TestPRCommentDeclaredScope(t *testing.T) {
	ws := t.TempDir()
	t.Setenv("GITHUB_WORKSPACE", ws)
	cause := filepath.Join(ws, "infra", "fray.yaml") + "#aws_ecs_service.app -> aws_db_instance.main unknown"
	doc := client.DFD{
		Elements: []client.Element{
			{ID: "svc", Name: "app", Kind: "container_service", Type: "process", Provenance: "iac", Evidence: client.Evidence{Addresses: []string{"aws_ecs_service.app"}}},
			{ID: "db", Name: "main", Kind: "relational_db", Type: "datastore", Provenance: "iac", Evidence: client.Evidence{Addresses: []string{"aws_db_instance.main"}}},
		},
		Flows: []client.Flow{{
			ID: "flow1", From: "svc", To: "db", DataClass: "unknown",
			AuthzScope: "account", AuthzGrants: []string{"account"},
			Causes: map[string]string{"authz_scope": cause},
		}},
	}
	cur := apiv1.Findings{SchemaVersion: "finding/v1", Findings: []apiv1.Finding{{
		RuleID: "FR-028", Target: "flow1", Status: "open", Severity: "medium",
		Stride: []string{"elevation_of_privilege"},
	}}}
	texts := map[string]apiv1.RuleText{
		"FR-028": {
			ID: "FR-028", Title: "Database access is scoped to one resource",
			Explanation: "The caller can reach every database in the account.",
			Mitigation:  "Grant access on this database only.",
			Severity:    "medium", Stride: []string{"elevation_of_privilege"},
			Pass: []apiv1.Condition{{Op: "equals", Field: "authz_scope", Value: "resource"}},
		},
	}
	got := PRComment(doc, cur, apiv1.Findings{SchemaVersion: "finding/v1"}, texts, nil, nil, "", nil, nil, nil, true, nil)
	if !strings.Contains(got, "(scope declared in infra/fray.yaml)") {
		t.Fatalf("missing relative declared-scope note:\n%s", got)
	}
	// An inline-policy cause is not a declared-scope token.
	if path, ok := declaredScopeConfig("aws_iam_role.task#inline_policy.db"); ok {
		t.Fatalf("inline policy path %q", path)
	}
}

func TestRulesSkippedSummary(t *testing.T) {
	if got := RulesSkippedSummary(nil); got != "" {
		t.Fatalf("nil: %q", got)
	}
	if got := RulesSkippedSummary([]apiv1.RuleSkipped{}); got != "" {
		t.Fatalf("empty: %q", got)
	}
	one := RulesSkippedSummary([]apiv1.RuleSkipped{
		{RuleID: "FR-029", MinAction: "v0.13.0"},
	})
	wantOne := "1 rule not evaluated because this Fray Action is older than it requires: [FR-029](https://github.com/fluong/fray/blob/main/docs/rules/FR-029.md) (needs v0.13.0). Upgrade for full results.\n"
	if one != wantOne {
		t.Fatalf("one:\n got %q\nwant %q", one, wantOne)
	}
	two := RulesSkippedSummary([]apiv1.RuleSkipped{
		{RuleID: "FR-029", MinAction: "v0.13.0"},
		{RuleID: "FR-031", MinAction: "v0.16.0"},
	})
	wantTwo := "2 rules not evaluated because this Fray Action is older than they require: [FR-029](https://github.com/fluong/fray/blob/main/docs/rules/FR-029.md) (needs v0.13.0), [FR-031](https://github.com/fluong/fray/blob/main/docs/rules/FR-031.md) (needs v0.16.0). Upgrade for full results.\n"
	if two != wantTwo {
		t.Fatalf("two:\n got %q\nwant %q", two, wantTwo)
	}
}

func TestPRCommentRulesSkipped(t *testing.T) {
	doc := client.DFD{}
	cur := apiv1.Findings{SchemaVersion: "finding/v1"}
	base := apiv1.Findings{SchemaVersion: "finding/v1"}
	skipped := []apiv1.RuleSkipped{
		{RuleID: "FR-029", MinAction: "v0.13.0"},
		{RuleID: "FR-031", MinAction: "v0.16.0"},
	}
	got := PRComment(doc, cur, base, nil, nil, nil, "", nil, nil, nil, true, skipped)
	want := "No change in open findings.\n\n" +
		"2 rules not evaluated because this Fray Action is older than they require: [FR-029](https://github.com/fluong/fray/blob/main/docs/rules/FR-029.md) (needs v0.13.0), [FR-031](https://github.com/fluong/fray/blob/main/docs/rules/FR-031.md) (needs v0.16.0). Upgrade for full results.\n"
	if got != want {
		t.Fatalf("two-rule comment:\n got %q\nwant %q", got, want)
	}
	got = PRComment(doc, cur, base, nil, nil, nil, "", nil, nil, nil, true, nil)
	if strings.Contains(got, "not evaluated") {
		t.Fatalf("absent rules_skipped must not render line:\n%s", got)
	}
}

func TestNoChangeSummary(t *testing.T) {
	if got := noChangeSummary(nil); got != "No change in open findings.\n" {
		t.Fatalf("empty: %q", got)
	}
	got := noChangeSummary([]apiv1.Finding{
		{Status: "open"},
		{Status: "open"},
		{Status: "mitigated"},
		{Status: "waived"},
		{Status: "accepted"},
	})
	want := "No change in open findings · 2 open · 1 mitigated · 2 waived\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
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
