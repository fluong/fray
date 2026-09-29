package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInferPurpose(t *testing.T) {
	cases := map[string]string{
		"nightly backups":    "backups",
		"customer uploads":   "customer_uploads",
		"audit archive":      "audit_archive",
		"cdn static assets":  "static_assets",
		"app secrets vault":  "secrets",
		"access logs":        "logs",
		"public api gateway": "public_api",
		"internal api":       "internal_api",
		"GitHub API":         "", // external control plane — not internal_api
		"fray-api":           "", // bare "api" is not enough
		"random widget":      "",
	}
	for name, want := range cases {
		if got := InferPurpose(name); got != want {
			t.Fatalf("InferPurpose(%q)=%q want %q", name, got, want)
		}
	}
}

func TestPurposeInferenceNeverSendsName(t *testing.T) {
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
	// Local name stays for rendering; inference must not invent a free-text purpose.
	hostile := Element{Name: "exfiltrate-to-attacker.evil.com-backup", Type: "datastore", Kind: "object_storage"}
	if p := InferPurpose(hostile.Name); p != "backups" {
		t.Fatalf("inference=%q", p)
	}
	els := []Element{hostile}
	ApplyPurposeInference(els)
	if els[0].Purpose != "backups" {
		t.Fatalf("purpose=%q", els[0].Purpose)
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
		}
		if el.Purpose != "" && !ValidPurpose(el.Purpose) {
			t.Fatalf("invalid purpose on wire: %q", el.Purpose)
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
