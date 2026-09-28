package render

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
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

	raw, err := SARIF(doc, findings, texts, locs)
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

	open := 0
	for _, f := range findings.Findings {
		if f.Status == "open" {
			open++
		}
	}
	if len(docSARIF.Runs[0].Results) != open {
		t.Fatalf("results %d want %d open findings", len(docSARIF.Runs[0].Results), open)
	}

	var fr010 *struct {
		RuleID    string `json:"ruleId"`
		Level     string `json:"level"`
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

func TestSARIFOmitsLocationWhenUnknown(t *testing.T) {
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
	raw, err := SARIF(doc, findings, texts, nil)
	if err != nil {
		t.Fatal(err)
	}
	var docSARIF struct {
		Runs []struct {
			Results []struct {
				Locations []any `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &docSARIF); err != nil {
		t.Fatal(err)
	}
	if len(docSARIF.Runs) != 1 || len(docSARIF.Runs[0].Results) != 1 {
		t.Fatalf("want one result, got %+v", docSARIF)
	}
	if len(docSARIF.Runs[0].Results[0].Locations) != 0 {
		t.Fatalf("want no locations, got %+v", docSARIF.Runs[0].Results[0].Locations)
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
