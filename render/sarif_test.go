package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
	"github.com/fluong/fray/version"
)

func TestSARIFAWSBlockingHighHasRegion(t *testing.T) {
	root := filepath.Join("..", "testdata")
	doc := loadDFD(t, filepath.Join(root, "fixtures", "aws-blocking.dfd.json"))
	injectElementCause(doc, "e269fe54ebe835ad4", "public", "module.uploads.aws_s3_bucket_public_access_block.this[0]")
	findings := loadFindings(t, filepath.Join(root, "fixtures", "aws-blocking-high.findings.json"))
	texts := loadTexts(t, filepath.Join(root, "fixtures", "rule_texts.json"))

	src := withUploadsModule(t, filepath.Join(root, "aws-web-app"))
	locs, err := client.ResourceLocations(src)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := SARIF(doc, findings, texts, locs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatal("SARIF must end with a newline")
	}

	var docSARIF struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Properties *struct {
					SecuritySeverity string `json:"security-severity"`
				} `json:"properties"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &docSARIF); err != nil {
		t.Fatal(err)
	}
	if docSARIF.Version != "2.1.0" {
		t.Fatalf("version %s", docSARIF.Version)
	}
	if len(docSARIF.Runs) != 1 || docSARIF.Runs[0].Tool.Driver.Name != "Fray" {
		t.Fatalf("tool %+v", docSARIF.Runs)
	}

	wantN := 0
	for _, f := range findings.Findings {
		if f.Status == "open" || f.Status == "waived" {
			wantN++
		}
	}
	if len(docSARIF.Runs[0].Results) != wantN {
		t.Fatalf("results %d want %d open/waived findings", len(docSARIF.Runs[0].Results), wantN)
	}

	var fr010 *struct {
		RuleID    string `json:"ruleId"`
		Level     string `json:"level"`
		Properties *struct {
			SecuritySeverity string `json:"security-severity"`
		} `json:"properties"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region *struct {
					StartLine int `json:"startLine"`
				} `json:"region"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	}
	for i := range docSARIF.Runs[0].Results {
		r := &docSARIF.Runs[0].Results[i]
		if r.RuleID == "FR-010" {
			fr010 = r
			break
		}
	}
	if fr010 == nil {
		t.Fatal("missing FR-010 result")
	}
	if fr010.Level != "error" {
		t.Fatalf("FR-010 level %s", fr010.Level)
	}
	if fr010.Properties == nil || fr010.Properties.SecuritySeverity != "7.5" {
		t.Fatalf("FR-010 security-severity %+v", fr010.Properties)
	}
	if len(fr010.Locations) == 0 || fr010.Locations[0].PhysicalLocation.Region == nil {
		t.Fatal("FR-010 missing region")
	}
	if line := fr010.Locations[0].PhysicalLocation.Region.StartLine; line <= 0 {
		t.Fatalf("FR-010 startLine %d", line)
	}
	if uri := fr010.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri == "" {
		t.Fatal("FR-010 missing uri")
	}
}

func TestSARIFFallbackLocationWhenUnknown(t *testing.T) {
	doc := client.DFD{
		Elements: []client.Element{{
			ID:   "e1",
			Name: "bucket",
			Kind: "object_storage",
			Evidence: client.Evidence{
				Addresses: []string{"aws_s3_bucket.missing"},
			},
		}},
	}
	findings := apiv1.Findings{Findings: []apiv1.Finding{{
		RuleID:   "FR-010",
		Target:   "e1",
		Status:   "open",
		Severity: "high",
	}}}
	texts := map[string]apiv1.RuleText{"FR-010": {ID: "FR-010", Title: "Object storage is not public"}}
	raw, err := SARIF(doc, findings, texts, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var docSARIF struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &docSARIF); err != nil {
		t.Fatal(err)
	}
	if len(docSARIF.Runs) != 1 || len(docSARIF.Runs[0].Results) != 1 {
		t.Fatalf("want one result, got %+v", docSARIF)
	}
	locs := docSARIF.Runs[0].Results[0].Locations
	if len(locs) != 1 {
		t.Fatalf("want one fallback location, got %+v", locs)
	}
	if locs[0].PhysicalLocation.ArtifactLocation.URI != "fray.yaml" {
		t.Fatalf("fallback uri %q", locs[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if locs[0].PhysicalLocation.Region == nil || locs[0].PhysicalLocation.Region.StartLine != 1 {
		t.Fatalf("fallback region %+v", locs[0].PhysicalLocation.Region)
	}
}

func TestSARIFGolden(t *testing.T) {
	doc := client.DFD{
		Elements: []client.Element{{
			ID:   "e1",
			Name: "bucket",
			Kind: "object_storage",
			Evidence: client.Evidence{
				Addresses: []string{"aws_s3_bucket.missing"},
			},
		}},
	}
	findings := apiv1.Findings{Findings: []apiv1.Finding{
		{RuleID: "FR-010", Target: "e1", Status: "open", Severity: "high"},
		{RuleID: "FR-001", Target: "e1", Status: "open", Severity: "medium"},
		{RuleID: "FR-003", Target: "e1", Status: "open", Severity: "low"},
	}}
	texts := map[string]apiv1.RuleText{
		"FR-010": {ID: "FR-010", Title: "Object storage is not public"},
		"FR-001": {ID: "FR-001", Title: "Example medium"},
		"FR-003": {ID: "FR-003", Title: "Example low"},
	}
	raw, err := SARIF(doc, findings, texts, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join("..", "testdata", "golden", "findings.sarif")
	want, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(want) {
		_ = os.WriteFile("/tmp/findings.sarif", raw, 0o644)
		t.Fatalf("SARIF drifted from golden; wrote /tmp/findings.sarif")
	}
}

func TestSARIFFR025AttributeRegion(t *testing.T) {
	// PR #2 shape: FR-025 attributed to block_public_* module inputs — SARIF
	// primary region must cover those lines (not the module "uploads" header).
	root := filepath.Join("..", "testdata")
	doc := loadDFD(t, filepath.Join(root, "fixtures", "aws-blocking-fr025.dfd.json"))
	injectElementCause(doc, "e269fe54ebe835ad4", "public_access_blocked", "module.uploads.aws_s3_bucket.this[0]")
	findings := loadFindings(t, filepath.Join(root, "fixtures", "aws-blocking-fr025.findings.json"))
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
	raw, err := SARIF(doc, findings, texts, locs, changed, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(root, "golden", "findings-fr025.sarif")
	want, err := os.ReadFile(wantPath)
	if err != nil {
		_ = os.WriteFile("/tmp/findings-fr025.sarif", raw, 0o644)
		t.Fatalf("missing golden (wrote /tmp/findings-fr025.sarif): %v", err)
	}
	if string(raw) != string(want) {
		_ = os.WriteFile("/tmp/findings-fr025.sarif", raw, 0o644)
		t.Fatalf("FR-025 SARIF drifted from golden; wrote /tmp/findings-fr025.sarif")
	}

	var docSARIF struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string `json:"id"`
						Properties *struct {
							Tags []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						Region *struct {
							StartLine int `json:"startLine"`
							EndLine   int `json:"endLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &docSARIF); err != nil {
		t.Fatal(err)
	}
	if len(docSARIF.Runs) != 1 {
		t.Fatal("want one run")
	}
	for _, rule := range docSARIF.Runs[0].Tool.Driver.Rules {
		if rule.Properties == nil || len(rule.Properties.Tags) == 0 || rule.Properties.Tags[0] != "security" {
			t.Fatalf("rule %s missing tags [security]: %+v", rule.ID, rule.Properties)
		}
	}
	var fr025 *struct {
		RuleID string `json:"ruleId"`
		Locations []struct {
			PhysicalLocation struct {
				Region *struct {
					StartLine int `json:"startLine"`
					EndLine   int `json:"endLine"`
				} `json:"region"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	}
	for i := range docSARIF.Runs[0].Results {
		r := &docSARIF.Runs[0].Results[i]
		if r.RuleID == "FR-025" {
			fr025 = r
			break
		}
	}
	if fr025 == nil || len(fr025.Locations) == 0 || fr025.Locations[0].PhysicalLocation.Region == nil {
		t.Fatal("missing FR-025 region")
	}
	reg := fr025.Locations[0].PhysicalLocation.Region
	if reg.StartLine != 268 || reg.EndLine != 271 {
		t.Fatalf("FR-025 region want 268-271, got %d-%d", reg.StartLine, reg.EndLine)
	}
}

// withUploadsModule copies aws-web-app and adds a stub uploads module so
// ResourceLocations can resolve module.uploads.* cause addresses used by the
// blocking fixture (registry modules are not vendored in testdata).
func withUploadsModule(t *testing.T, awsWebApp string) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(awsWebApp)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(awsWebApp, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mod := filepath.Join(dst, ".terraform", "modules", "uploads")
	if err := os.MkdirAll(mod, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{
  "Modules": [
    {"Key": "", "Source": "", "Dir": "."},
    {"Key": "uploads", "Source": "terraform-aws-modules/s3-bucket/aws", "Dir": ".terraform/modules/uploads"}
  ]
}`
	if err := os.WriteFile(filepath.Join(dst, ".terraform", "modules", "modules.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	stub := `
resource "aws_s3_bucket" "this" {
  count = 1
}

resource "aws_s3_bucket_public_access_block" "this" {
  count = 1
  block_public_acls = false
}
`
	if err := os.WriteFile(filepath.Join(mod, "main.tf"), []byte(stub), 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestSARIFWaivedSuppression(t *testing.T) {
	doc := client.DFD{
		Elements: []client.Element{{
			ID:   "e1",
			Name: "bucket",
			Kind: "object_storage",
			Evidence: client.Evidence{
				Addresses: []string{"aws_s3_bucket.assets"},
			},
		}},
	}
	findings := apiv1.Findings{Findings: []apiv1.Finding{
		{RuleID: "FR-010", Target: "e1", Status: "waived", Severity: "high"},
		{RuleID: "FR-001", Target: "e1", Status: "mitigated", Severity: "medium"},
		{RuleID: "FR-003", Target: "e1", Status: "unverified", Severity: "low"},
		{RuleID: "FR-005", Target: "e1", Status: "accepted", Severity: "medium"},
		{RuleID: "FR-012", Target: "e1", Status: "open", Severity: "medium"},
	}}
	texts := map[string]apiv1.RuleText{
		"FR-010": {ID: "FR-010", Title: "Object storage is not public"},
		"FR-012": {ID: "FR-012", Title: "Object storage cannot be destroyed by the tool"},
	}
	waivers := []apiv1.Accepted{{
		RuleID: "FR-010", TargetID: "e1", ID: "public-assets", Expires: "2026-12-08",
	}}
	raw, err := SARIF(doc, findings, texts, nil, nil, waivers)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "reason") || strings.Contains(string(raw), "owner") {
		t.Fatalf("SARIF must not include reason/owner text: %s", raw)
	}

	var docSARIF struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name            string `json:"name"`
					Version         string `json:"version"`
					SemanticVersion string `json:"semanticVersion"`
					InformationURI  string `json:"informationUri"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Suppressions        []struct {
					Kind          string `json:"kind"`
					Status        string `json:"status"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &docSARIF); err != nil {
		t.Fatal(err)
	}
	drv := docSARIF.Runs[0].Tool.Driver
	if drv.Name != "Fray" || drv.Version != version.Version || drv.SemanticVersion != version.Version {
		t.Fatalf("driver %+v", drv)
	}
	if drv.InformationURI != version.InformationURI {
		t.Fatalf("informationUri %q", drv.InformationURI)
	}
	if len(docSARIF.Runs[0].Results) != 2 {
		t.Fatalf("want open+waived only, got %d results", len(docSARIF.Runs[0].Results))
	}
	var waived *struct {
		RuleID              string            `json:"ruleId"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
		Suppressions        []struct {
			Kind          string `json:"kind"`
			Status        string `json:"status"`
			Justification string `json:"justification"`
		} `json:"suppressions"`
	}
	for i := range docSARIF.Runs[0].Results {
		r := &docSARIF.Runs[0].Results[i]
		if r.RuleID == "FR-010" {
			waived = r
			break
		}
	}
	if waived == nil || len(waived.Suppressions) != 1 {
		t.Fatalf("waived result %+v", waived)
	}
	s := waived.Suppressions[0]
	wantJust := "Waived via .fray/waivers.yml (id public-assets, until 2026-12-08)"
	if s.Kind != "external" || s.Status != "accepted" || s.Justification != wantJust {
		t.Fatalf("suppression %+v", s)
	}
	fp := waived.PartialFingerprints["fray/v1"]
	wantFP := Fingerprint("FR-010", "aws_s3_bucket.assets", "e1")
	if fp != wantFP {
		t.Fatalf("fingerprint %s want %s", fp, wantFP)
	}
}

func TestSARIFFingerprintStableAcrossLineMove(t *testing.T) {
	dir := t.TempDir()
	write := func(extraBlank bool) {
		t.Helper()
		body := ""
		if extraBlank {
			body = "\n\n"
		}
		body += `resource "aws_s3_bucket" "assets" {
  bucket = "assets"
}

resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
`
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(false)
	locs1, err := client.ResourceLocations(dir)
	if err != nil {
		t.Fatal(err)
	}
	line1 := locs1["aws_s3_bucket.assets"].Line

	write(true)
	locs2, err := client.ResourceLocations(dir)
	if err != nil {
		t.Fatal(err)
	}
	line2 := locs2["aws_s3_bucket.assets"].Line
	if line2 <= line1 {
		t.Fatalf("expected line to move: before %d after %d", line1, line2)
	}

	doc := client.DFD{
		Elements: []client.Element{
			{ID: "e-assets", Name: "assets", Kind: "object_storage", Evidence: client.Evidence{Addresses: []string{"aws_s3_bucket.assets"}}},
			{ID: "e-logs", Name: "logs", Kind: "object_storage", Evidence: client.Evidence{Addresses: []string{"aws_s3_bucket.logs"}}},
		},
	}
	findings := apiv1.Findings{Findings: []apiv1.Finding{
		{RuleID: "FR-010", Target: "e-assets", Status: "open", Severity: "high"},
		{RuleID: "FR-010", Target: "e-logs", Status: "open", Severity: "high"},
	}}
	texts := map[string]apiv1.RuleText{"FR-010": {ID: "FR-010", Title: "Object storage is not public"}}

	raw1, err := SARIF(doc, findings, texts, locs1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := SARIF(doc, findings, texts, locs2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Results sorted by rule then target: e-assets before e-logs.
	parse := func(raw []byte) (assetsFP, logsFP string, assetsLine int) {
		t.Helper()
		var docSARIF struct {
			Runs []struct {
				Results []struct {
					PartialFingerprints map[string]string `json:"partialFingerprints"`
					Locations           []struct {
						PhysicalLocation struct {
							Region *struct {
								StartLine int `json:"startLine"`
							} `json:"region"`
						} `json:"physicalLocation"`
					} `json:"locations"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(raw, &docSARIF); err != nil {
			t.Fatal(err)
		}
		if len(docSARIF.Runs[0].Results) != 2 {
			t.Fatalf("results %d", len(docSARIF.Runs[0].Results))
		}
		a := docSARIF.Runs[0].Results[0]
		b := docSARIF.Runs[0].Results[1]
		return a.PartialFingerprints["fray/v1"], b.PartialFingerprints["fray/v1"], a.Locations[0].PhysicalLocation.Region.StartLine
	}
	a1, l1, lineBefore := parse(raw1)
	a2, l2, lineAfter := parse(raw2)
	if a1 != a2 {
		t.Fatalf("assets fingerprint changed across line move: %s vs %s", a1, a2)
	}
	if lineBefore == lineAfter {
		t.Fatal("expected SARIF startLine to change when block moves")
	}
	if a1 == l1 {
		t.Fatal("different resources must have different fingerprints")
	}
	if l1 != l2 {
		t.Fatalf("logs fingerprint changed: %s vs %s", l1, l2)
	}
	wantAssets := sha256Hex("FR-010|aws_s3_bucket.assets")
	if a1 != wantAssets {
		t.Fatalf("assets fp %s want %s", a1, wantAssets)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestSARIFFingerprintFallbackToDFDID(t *testing.T) {
	doc := client.DFD{
		Elements: []client.Element{{
			ID:   "e-no-addr",
			Name: "bucket",
			Kind: "object_storage",
		}},
	}
	findings := apiv1.Findings{Findings: []apiv1.Finding{
		{RuleID: "FR-010", Target: "e-no-addr", Status: "open", Severity: "high"},
	}}
	texts := map[string]apiv1.RuleText{"FR-010": {ID: "FR-010", Title: "Object storage is not public"}}
	raw, err := SARIF(doc, findings, texts, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var docSARIF struct {
		Runs []struct {
			Results []struct {
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &docSARIF); err != nil {
		t.Fatal(err)
	}
	got := docSARIF.Runs[0].Results[0].PartialFingerprints["fray/v1"]
	want := sha256Hex("FR-010|e-no-addr")
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

