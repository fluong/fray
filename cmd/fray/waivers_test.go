package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
	"github.com/fluong/fray/render"
)

func TestLoadWaiversGood(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "waivers.yml")
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	raw := `version: 1
waivers:
  - id: pub-s3
    rule: FR-001
    address: aws_s3_bucket.assets
    reason: "CDN origin; WAF reviewed."
    owner: "@security-eng"
    expires: "2026-12-01"
`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadWaivers(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "pub-s3" {
		t.Fatalf("%+v", got)
	}
}

func TestLoadWaiversMissingOK(t *testing.T) {
	got, err := loadWaivers(filepath.Join(t.TempDir(), "missing.yml"), time.Now())
	if err != nil || len(got) != 0 {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestLoadWaiversBadFiles(t *testing.T) {
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		raw     string
		wantSub string
	}{
		{
			name: "bad id",
			raw: `version: 1
waivers:
  - id: Bad_ID
    rule: FR-001
    address: aws_s3_bucket.assets
    reason: "long enough reason text"
    owner: "@sec"
    expires: "2026-12-01"
`,
			wantSub: "pattern",
		},
		{
			name: "bad date pattern",
			raw: `version: 1
waivers:
  - id: pub-s3
    rule: FR-001
    address: aws_s3_bucket.assets
    reason: "long enough reason text"
    owner: "@sec"
    expires: "12/01/2026"
`,
			wantSub: "expires",
		},
		{
			name: "duplicate ids",
			raw: `version: 1
waivers:
  - id: same
    rule: FR-001
    address: aws_s3_bucket.a
    reason: "long enough reason text"
    owner: "@sec"
    expires: "2026-12-01"
  - id: same
    rule: FR-002
    address: aws_s3_bucket.b
    reason: "long enough reason text"
    owner: "@sec"
    expires: "2026-12-01"
`,
			wantSub: "duplicate id",
		},
		{
			name: "beyond 365",
			raw: `version: 1
waivers:
  - id: far
    rule: FR-001
    address: aws_s3_bucket.assets
    reason: "long enough reason text"
    owner: "@sec"
    expires: "2028-01-01"
`,
			wantSub: "365 days",
		},
		{
			name: "short reason",
			raw: `version: 1
waivers:
  - id: short
    rule: FR-001
    address: aws_s3_bucket.assets
    reason: "too short"
    owner: "@sec"
    expires: "2026-12-01"
`,
			wantSub: "minLength",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "w.yml")
			if err := os.WriteFile(path, []byte(tc.raw), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := loadWaivers(path, now)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err=%v want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestLoadWaivers201Entries(t *testing.T) {
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	var b strings.Builder
	b.WriteString("version: 1\nwaivers:\n")
	for i := 0; i < 201; i++ {
		fmt.Fprintf(&b, "  - id: w-%d\n", i)
		b.WriteString("    rule: FR-001\n")
		fmt.Fprintf(&b, "    address: aws_s3_bucket.b%d\n", i)
		b.WriteString("    reason: \"long enough reason text\"\n")
		b.WriteString("    owner: \"@sec\"\n")
		b.WriteString("    expires: \"2026-12-01\"\n")
	}
	path := filepath.Join(t.TempDir(), "w.yml")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadWaivers(path, now)
	if err == nil {
		t.Fatal("expected maxItems error")
	}
	if !strings.Contains(err.Error(), "maxItems") && !strings.Contains(err.Error(), "200") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadWaivers64KiB(t *testing.T) {
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "w.yml")
	// Header + one huge reason past 64 KiB.
	raw := "version: 1\nwaivers:\n  - id: big\n    rule: FR-001\n    address: aws_s3_bucket.assets\n    reason: \"" +
		strings.Repeat("x", maxWaiversFileBytes) + "\"\n    owner: \"@sec\"\n    expires: \"2026-12-01\"\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadWaivers(path, now)
	if err == nil || !strings.Contains(err.Error(), "64 KiB") {
		t.Fatalf("err=%v", err)
	}
}

func TestLegacyMitigationsMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mitigations.yaml")
	raw := `schema_version: mitigation/v1
entries:
  - rule_id: FR-001
    address: aws_s3_bucket.assets
    status: accepted
    reason: "old"
`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	err := checkLegacyMitigations(path, 0)
	if err == nil || !strings.Contains(err.Error(), "mitigations.yaml is no longer supported") {
		t.Fatalf("err=%v", err)
	}
	err = checkLegacyMitigations(path, 1)
	if err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("err=%v", err)
	}
	empty := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(empty, []byte("schema_version: mitigation/v1\nentries: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkLegacyMitigations(empty, 0); err != nil {
		t.Fatal(err)
	}
	if err := checkLegacyMitigations(filepath.Join(dir, "missing.yaml"), 0); err != nil {
		t.Fatal(err)
	}
}

func TestWirePayloadWaiversNoSecrets(t *testing.T) {
	doc := client.DFD{
		SchemaVersion: "dfd/v1",
		Elements: []client.Element{{
			ID: "e1111111111111111", Name: "assets", Type: "store", Kind: "object_store",
			Provenance: "iac",
			Evidence:   client.Evidence{Addresses: []string{"aws_s3_bucket.assets"}},
		}},
	}
	entries := []waiverEntry{{
		ID: "pub-s3", Rule: "FR-001", Address: "aws_s3_bucket.assets",
		Reason: "CDN origin; WAF reviewed thoroughly.", Owner: "@security-eng", Expires: "2026-12-01",
	}}
	accepted, err := resolveWaivers(doc, entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted) != 1 || accepted[0].TargetID != "e1111111111111111" {
		t.Fatal(accepted)
	}
	idMap := client.IDMap{ToRedacted: map[string]string{"e1111111111111111": "eaaaaaaaaaaaaaaaa"}}
	accepted[0].TargetID = idMap.RemapAcceptedTarget(accepted[0].TargetID)
	body, err := json.Marshal(apiv1.ScanRequest{
		DFD:                 json.RawMessage(`{}`),
		AcceptedMitigations: accepted,
		Repo:                "deadbeef",
		Commit:              "abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, forbidden := range []string{`"reason"`, `"owner"`, "CDN origin", "@security-eng", "aws_s3_bucket.assets"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("payload contains %q: %s", forbidden, s)
		}
	}
	if !strings.Contains(s, `"id":"pub-s3"`) || !strings.Contains(s, `"expires":"2026-12-01"`) {
		t.Fatalf("missing id/expires: %s", s)
	}
	if !strings.Contains(s, `"target_id":"eaaaaaaaaaaaaaaaa"`) {
		t.Fatalf("target_id not remapped: %s", s)
	}
	if strings.Contains(s, `"status"`) {
		t.Fatalf("status must be omitted on waiver wire entries: %s", s)
	}
}

func TestWaiversSummaryOutcomes(t *testing.T) {
	got := render.WaiversSummary(nil, false)
	if !strings.Contains(got, "server did not report waiver outcomes") {
		t.Fatal(got)
	}
	w := &apiv1.Waivers{
		Applied:      []string{"a"},
		NewInPR:      []string{"b"},
		ExpiringSoon: []string{"c"},
		Expired:      []string{"d"},
		Stale:        []apiv1.WaiverStale{{ID: "e", Reason: "no matching finding"}},
	}
	got = render.WaiversSummary(w, true)
	for _, want := range []string{
		"**Applied** (1): a",
		"**New in this PR:** b",
		"CODEOWNERS",
		"**Expiring soon**",
		"**Expired**",
		"`e`: no matching finding",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %s", want, got)
		}
	}
	if render.WaiversSummary(&apiv1.Waivers{}, true) != "" {
		t.Fatal("empty outcomes should omit section")
	}
}

func TestWaiverErrorMessageVerbatim(t *testing.T) {
	msg := `waiver "x": expires beyond 90 days for high-severity finding`
	body := []byte(`{"error":"invalid_waiver","message":` + jsonQuote(msg) + `}`)
	if got := waiverErrorMessage(body); got != msg {
		t.Fatalf("got %q", got)
	}
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
