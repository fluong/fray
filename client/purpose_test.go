package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNameSubstringsDoNotInferPurpose(t *testing.T) {
	// Previously name substrings (secret/archive/log/asset/…) invented purpose.
	// Purpose must stay absent unless type, relation, or fray.yaml says so.
	names := []string{
		"catalog-assets",
		"login-page",
		"blog-media",
		"product-images-archive",
		"nightly backups",
		"customer uploads",
		"access logs",
		"app secrets vault",
		"GitHub API",
		"fray-api",
	}
	plan := []byte(`{
	  "resource_changes": [
	    {"address":"aws_s3_bucket.catalog","mode":"managed","type":"aws_s3_bucket","change":{"after":{"bucket":"catalog-assets"}}},
	    {"address":"aws_s3_bucket.login","mode":"managed","type":"aws_s3_bucket","change":{"after":{"bucket":"login-page"}}},
	    {"address":"aws_s3_bucket.blog","mode":"managed","type":"aws_s3_bucket","change":{"after":{"bucket":"blog-media"}}},
	    {"address":"aws_s3_bucket.images","mode":"managed","type":"aws_s3_bucket","change":{"after":{"bucket":"product-images-archive"}}}
	  ]
	}`)
	doc, _, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml", Source{
		Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Element{}
	for _, el := range doc.Elements {
		byName[el.Name] = el
	}
	for _, name := range names[:4] {
		el, ok := byName[name]
		if !ok {
			t.Fatalf("missing element %q", name)
		}
		if el.Purpose != "" {
			t.Fatalf("%q purpose=%q want empty (no name-substring inference)", name, el.Purpose)
		}
		if el.Evidence.PurposeSource != "" {
			t.Fatalf("%q purpose_source=%q want empty", name, el.Evidence.PurposeSource)
		}
	}
}

func TestCloudTrailTargetBucketPurpose(t *testing.T) {
	plan := []byte(`{
	  "resource_changes": [
	    {"address":"aws_s3_bucket.trail","mode":"managed","type":"aws_s3_bucket","change":{"after":{"bucket":"org-cloudtrail-logs"}}},
	    {"address":"aws_s3_bucket.assets","mode":"managed","type":"aws_s3_bucket","change":{"after":{"bucket":"product-images-archive"}}},
	    {"address":"aws_cloudtrail.main","mode":"managed","type":"aws_cloudtrail","change":{"after":{"s3_bucket_name":"org-cloudtrail-logs","event_selector":[{"include_management_events":true,"read_write_type":"All","data_resource":[{"type":"AWS::S3::Object","values":["arn:aws:s3"]}]}]}}}
	  ],
	  "configuration": {
	    "root_module": {
	      "resources": [
	        {"address":"aws_s3_bucket.trail","type":"aws_s3_bucket","name":"trail","mode":"managed","expressions":{"bucket":{"constant_value":"org-cloudtrail-logs"}}},
	        {"address":"aws_s3_bucket.assets","type":"aws_s3_bucket","name":"assets","mode":"managed","expressions":{"bucket":{"constant_value":"product-images-archive"}}},
	        {"address":"aws_cloudtrail.main","type":"aws_cloudtrail","name":"main","mode":"managed","expressions":{"s3_bucket_name":{"constant_value":"org-cloudtrail-logs"}}}
	      ]
	    }
	  }
	}`)
	doc, _, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml", Source{
		Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var trail, assets *Element
	for i := range doc.Elements {
		el := &doc.Elements[i]
		switch el.Name {
		case "org-cloudtrail-logs":
			trail = el
		case "product-images-archive":
			assets = el
		}
	}
	if trail == nil {
		t.Fatal("trail bucket missing")
	}
	if trail.Purpose != "audit_archive" {
		t.Fatalf("trail purpose=%q want audit_archive", trail.Purpose)
	}
	if trail.Evidence.PurposeSource != PurposeSourceRelation {
		t.Fatalf("trail purpose_source=%q want relation", trail.Evidence.PurposeSource)
	}
	if assets == nil {
		t.Fatal("assets bucket missing")
	}
	if assets.Purpose != "" {
		t.Fatalf("archive-named bucket purpose=%q want empty", assets.Purpose)
	}
}

func TestPurposeFromTypeAndDeclared(t *testing.T) {
	plan := []byte(`{
	  "resource_changes": [
	    {"address":"google_secret_manager_secret.db","mode":"managed","type":"google_secret_manager_secret","change":{"after":{"secret_id":"db-url","rotation":[]}}},
	    {"address":"cloudflare_r2_bucket.archive","mode":"managed","type":"cloudflare_r2_bucket","change":{"after":{"name":"demo-scan-archive"}}},
	    {"address":"aws_s3_bucket.logs","mode":"managed","type":"aws_s3_bucket","change":{"after":{"bucket":"app-access-logs"}}},
	    {"address":"aws_s3_bucket_logging.src","mode":"managed","type":"aws_s3_bucket_logging","change":{"after":{"bucket":"src","target_bucket":"app-access-logs"}}}
	  ],
	  "configuration": {
	    "root_module": {
	      "resources": [
	        {"address":"aws_s3_bucket.logs","type":"aws_s3_bucket","name":"logs","mode":"managed","expressions":{"bucket":{"constant_value":"app-access-logs"}}},
	        {"address":"aws_s3_bucket_logging.src","type":"aws_s3_bucket_logging","name":"src","mode":"managed","expressions":{"target_bucket":{"constant_value":"app-access-logs"}}}
	      ]
	    }
	  }
	}`)
	cfg := []byte(`schema_version: fray-config/v1
annotations:
  elements:
    - address: cloudflare_r2_bucket.archive
      purpose: audit_archive
`)
	doc, _, err := Parse(plan, cfg, "fray.yaml", Source{
		Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	byAddr := map[string]Element{}
	for _, el := range doc.Elements {
		for _, a := range el.Evidence.Addresses {
			byAddr[a] = el
		}
	}
	secret := byAddr["google_secret_manager_secret.db"]
	if secret.Purpose != "secrets" || secret.Evidence.PurposeSource != PurposeSourceType {
		t.Fatalf("secret purpose=%q source=%q", secret.Purpose, secret.Evidence.PurposeSource)
	}
	r2 := byAddr["cloudflare_r2_bucket.archive"]
	if r2.Purpose != "audit_archive" || r2.Evidence.PurposeSource != PurposeSourceDeclared {
		t.Fatalf("r2 purpose=%q source=%q", r2.Purpose, r2.Evidence.PurposeSource)
	}
	logs := byAddr["aws_s3_bucket.logs"]
	if logs.Purpose != "logs" || logs.Evidence.PurposeSource != PurposeSourceRelation {
		t.Fatalf("logs purpose=%q source=%q", logs.Purpose, logs.Evidence.PurposeSource)
	}
}

func TestPurposeNeverSendsName(t *testing.T) {
	plan, err := os.ReadFile("testdata/aws-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := []byte(`schema_version: fray-config/v1
annotations:
  elements:
    - address: module.uploads.aws_s3_bucket.this[0]
      purpose: customer_uploads
`)
	doc, _, err := Parse(plan, cfg, "fray.yaml", Source{
		Repo: "acme/fray-demo-aws", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan",
	}, filepath.Join("..", "testdata", "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	var uploads *Element
	for i := range doc.Elements {
		el := &doc.Elements[i]
		if el.Purpose == "customer_uploads" {
			uploads = el
			break
		}
	}
	if uploads == nil {
		t.Fatal("uploads element missing purpose annotation")
	}
	if uploads.Evidence.PurposeSource != PurposeSourceDeclared {
		t.Fatalf("purpose_source=%q want declared", uploads.Evidence.PurposeSource)
	}
	// Hostile name must not invent purpose without type/relation/declaration.
	hostile := Element{Name: "exfiltrate-to-attacker.evil.com-backup", Type: "datastore", Kind: "object_storage"}
	applyPurposeFromType([]*Element{&hostile})
	if hostile.Purpose != "" {
		t.Fatalf("name-only purpose=%q", hostile.Purpose)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	redacted, idMap, err := Redact(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	if err := AssertNoPlaintext(raw, idMap.Plaintext); err != nil {
		t.Fatal(err)
	}
	var wire DFD
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, el := range wire.Elements {
		if el.Purpose == "customer_uploads" {
			found = true
			if el.Name != "" {
				t.Fatalf("redacted element still has name %q", el.Name)
			}
			if el.Evidence.PurposeSource != PurposeSourceDeclared {
				t.Fatalf("redacted purpose_source=%q", el.Evidence.PurposeSource)
			}
		}
		if el.Purpose != "" && !ValidPurpose(el.Purpose) {
			t.Fatalf("invalid purpose on wire: %q", el.Purpose)
		}
		if el.Evidence.PurposeSource != "" && !validPurposeSource(el.Evidence.PurposeSource) {
			t.Fatalf("invalid purpose_source on wire: %q", el.Evidence.PurposeSource)
		}
	}
	if !found {
		t.Fatal("customer_uploads purpose missing from redacted payload")
	}
	for _, name := range []string{"fray-demo-aws", "module.uploads.aws_s3_bucket.this[0]", uploads.Name} {
		if name != "" && strings.Contains(string(raw), name) {
			t.Fatalf("plaintext %q present in payload", name)
		}
	}
}
