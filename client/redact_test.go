package client_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fluong/fray/client"
	"github.com/fluong/fray/schema/validate"
)

func TestRedactStableIDsAndFingerprint(t *testing.T) {
	doc := loadAWSFixture(t)
	key := mustKey(t)

	a, ma, err := client.Redact(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	b, mb, err := client.Redact(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	if a.Redaction.KeyFingerprint != b.Redaction.KeyFingerprint {
		t.Fatalf("fingerprint drifted: %s vs %s", a.Redaction.KeyFingerprint, b.Redaction.KeyFingerprint)
	}
	if len(a.Elements) == 0 {
		t.Fatal("no elements")
	}
	for i := range a.Elements {
		if a.Elements[i].ID != b.Elements[i].ID {
			t.Fatalf("element id drifted at %d: %s vs %s", i, a.Elements[i].ID, b.Elements[i].ID)
		}
	}
	if len(ma.ToRedacted) != len(mb.ToRedacted) {
		t.Fatal("map size drifted")
	}

	other := mustKey(t)
	c, _, err := client.Redact(doc, other)
	if err != nil {
		t.Fatal(err)
	}
	if c.Redaction.KeyFingerprint == a.Redaction.KeyFingerprint {
		t.Fatal("different keys produced the same fingerprint")
	}
	if c.Elements[0].ID == a.Elements[0].ID {
		t.Fatal("different keys produced the same element id")
	}
}

func TestRedactPayloadHasNoPlaintext(t *testing.T) {
	doc := loadAWSFixture(t)
	key := mustKey(t)
	redacted, idMap, err := client.Redact(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	if idMap.FieldsHashed != 7 {
		t.Fatalf("full AWS fixture: want 7 HMAC fields (5 addresses + 1 signal + repo), got %d", idMap.FieldsHashed)
	}
	raw, err := client.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AssertNoPlaintext(raw, idMap.Plaintext); err != nil {
		t.Fatal(err)
	}

	// Guard must cover the full POST body (DFD + request.repo), not only the DFD.
	req, err := json.Marshal(map[string]any{
		"dfd":               json.RawMessage(raw),
		"repo":              redacted.Source.Repo,
		"commit":            "abcdef1234567",
		"is_default_branch": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AssertNoPlaintext(req, idMap.Plaintext); err != nil {
		t.Fatalf("guard on full payload: %v", err)
	}
	leakyReq, err := json.Marshal(map[string]any{
		"dfd":  json.RawMessage(raw),
		"repo": doc.Source.Repo, // plaintext repo from the local DFD
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AssertNoPlaintext(leakyReq, idMap.Plaintext); err == nil {
		t.Fatal("guard should catch plaintext request.repo")
	}

	// Property: every plan-derived name, address, signal name, and repo is absent.
	for _, v := range idMap.Plaintext {
		if v == "" {
			continue
		}
		if bytes.Contains(raw, []byte(v)) || bytes.Contains(req, []byte(v)) {
			t.Fatal("a plaintext identifier from the plan still appears in the redacted payload")
		}
	}
	for _, needle := range []string{"module.uploads", "ecs_service", "db_password", "fluong/fray"} {
		if bytes.Contains(req, []byte(needle)) {
			t.Fatalf("fixture identifier %q present in full payload", needle)
		}
	}

	schema, err := validate.CompileDFD()
	if err != nil {
		t.Fatal(err)
	}
	if err := validate.DFD(schema, raw); err != nil {
		t.Fatalf("redacted DFD failed validation: %v", err)
	}
}

func TestRedactGuardNamesPath(t *testing.T) {
	doc := loadAWSFixture(t)
	key := mustKey(t)
	_, idMap, err := client.Redact(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	leaky := []byte(`{"dfd":{"source":{"repo":"acme/fray-demo-aws"}}}`)
	// Force a known plaintext into the set.
	idMap.Plaintext = append(idMap.Plaintext, "acme/fray-demo-aws")
	err = client.AssertNoPlaintext(leaky, idMap.Plaintext)
	if err == nil {
		t.Fatal("expected guard to fail")
	}
	if !strings.Contains(err.Error(), "/dfd/source/repo") {
		t.Fatalf("error should name path, got %v", err)
	}
	if strings.Contains(err.Error(), "acme/fray-demo-aws") {
		t.Fatal("error must not include the plaintext value")
	}
}

func TestHashFieldDomainSeparation(t *testing.T) {
	key := mustKey(t)
	a := client.HashField(key, "address", "module.x")
	b := client.HashField(key, "name", "module.x")
	if a == b {
		t.Fatal("domain separation failed")
	}
	if len(a) != 64 {
		t.Fatalf("want 64 hex, got %d", len(a))
	}
}

func loadAWSFixture(t *testing.T) client.DFD {
	t.Helper()
	plan, err := os.ReadFile(filepath.Join("testdata", "aws-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := []byte("schema_version: fray-config/v1\n")
	doc, _, err := client.Parse(plan, cfg, "fray.yaml", client.Source{
		Repo: "fluong/fray", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan",
	}, filepath.Join("..", "testdata", "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}
