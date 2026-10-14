package main

import (
	"bytes"
	"encoding/json"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
)

func TestMarshalFindingsFileAddresses(t *testing.T) {
	doc := client.DFD{
		Elements: []client.Element{{
			ID:   "e0123456789abcdef0",
			Type: "process", Kind: "virtual_machine",
			Evidence: client.Evidence{Addresses: []string{"aws_instance.bastion"}},
		}},
	}
	findings := apiv1.Findings{
		SchemaVersion: "finding/v1",
		Findings: []apiv1.Finding{{
			RuleID: "FR-034", Target: "e0123456789abcdef0",
			Status: "mitigated", Severity: "high",
			Stride: []string{"elevation_of_privilege"},
		}},
	}
	raw, err := marshalFindingsFile(findings, doc)
	if err != nil {
		t.Fatal(err)
	}
	var got findingsFile
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != "finding/v1" {
		t.Fatalf("schema_version=%q want finding/v1", got.SchemaVersion)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings len=%d", len(got.Findings))
	}
	f := got.Findings[0]
	if f.Status != "mitigated" || f.RuleID != "FR-034" {
		t.Fatalf("finding=%+v", f.Finding)
	}
	if len(f.Addresses) != 1 || f.Addresses[0] != "aws_instance.bastion" {
		t.Fatalf("addresses=%v want [aws_instance.bastion]", f.Addresses)
	}

	// Example shape for mitigated entry (addresses local-only).
	if !bytes.Contains(raw, []byte(`"addresses": [`)) || !bytes.Contains(raw, []byte(`"aws_instance.bastion"`)) {
		t.Fatalf("missing addresses block in:\n%s", raw)
	}
}

func TestMarshalFindingsFileUnknownTargetOmitsAddresses(t *testing.T) {
	findings := apiv1.Findings{
		SchemaVersion: "finding/v1",
		Findings: []apiv1.Finding{{
			RuleID: "FR-034", Target: "e0123456789abcdef0",
			Status: "open", Severity: "high", Stride: []string{"elevation_of_privilege"},
		}},
	}
	raw, err := marshalFindingsFile(findings, client.DFD{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"addresses"`)) {
		t.Fatalf("addresses present for unknown target:\n%s", raw)
	}
}

func TestFindingsFileEnrichmentDoesNotChangeRequestBody(t *testing.T) {
	doc := client.DFD{
		SchemaVersion: "dfd/v1",
		Elements: []client.Element{{
			ID: "e0123456789abcdef0", Type: "process", Kind: "virtual_machine",
			Evidence: client.Evidence{Addresses: []string{"aws_instance.bastion"}},
		}},
	}
	rawDFD, err := client.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	findings := apiv1.Findings{
		SchemaVersion: "finding/v1",
		Findings: []apiv1.Finding{{
			RuleID: "FR-034", Target: "e0123456789abcdef0",
			Status: "mitigated", Severity: "high",
			Stride: []string{"elevation_of_privilege"},
		}},
	}

	buildReq := func() []byte {
		body, err := json.Marshal(apiv1.ScanRequest{
			DFD:             rawDFD,
			Repo:            "owner/repo",
			Commit:          "abc1234",
			IsDefaultBranch: true,
			ClientVersion:   "0.0.0-test",
		})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}

	before := buildReq()
	fileBody, err := marshalFindingsFile(findings, doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(fileBody, []byte(`"addresses"`)) {
		t.Fatal("expected addresses in findings file")
	}
	after := buildReq()
	if !bytes.Equal(before, after) {
		t.Fatalf("ScanRequest body changed after findings enrichment\nbefore=%s\nafter=%s", before, after)
	}
	// Wire findings marshal (API) must stay without addresses.
	wire, err := apiv1.MarshalFindings(findings)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte(`"addresses"`)) {
		t.Fatalf("wire findings gained addresses:\n%s", wire)
	}
}

func TestFindingsFileMinusAddressesMatchesMarshalFindings(t *testing.T) {
	doc := client.DFD{
		Elements: []client.Element{{
			ID: "e0123456789abcdef0", Type: "process", Kind: "virtual_machine",
			Evidence: client.Evidence{Addresses: []string{"aws_instance.bastion", "aws_subnet.public"}},
		}},
	}
	findings := apiv1.Findings{
		SchemaVersion: "finding/v1",
		Findings: []apiv1.Finding{
			{
				RuleID: "FR-034", Target: "e0123456789abcdef0",
				Status: "mitigated", Severity: "high",
				Stride:   []string{"elevation_of_privilege"},
				Evidence: []string{"fact-a"},
				NewRule:  true,
			},
			{
				RuleID: "FR-017", Target: "e0123456789abcdef1",
				Status: "open", Severity: "medium",
				Stride: []string{"information_disclosure"},
			},
		},
	}

	want, err := apiv1.MarshalFindings(findings)
	if err != nil {
		t.Fatal(err)
	}
	gotFile, err := marshalFindingsFile(findings, doc)
	if err != nil {
		t.Fatal(err)
	}
	stripped, err := stripFindingsFileAddresses(gotFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stripped, want) {
		t.Fatalf("findings.json minus addresses != MarshalFindings\nwant:\n%s\ngot:\n%s", want, stripped)
	}
}

func stripFindingsFileAddresses(raw []byte) ([]byte, error) {
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Findings      []struct {
			apiv1.Finding
			Addresses []string `json:"addresses,omitempty"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := apiv1.Findings{
		SchemaVersion: doc.SchemaVersion,
		Findings:      make([]apiv1.Finding, len(doc.Findings)),
	}
	for i := range doc.Findings {
		out.Findings[i] = doc.Findings[i].Finding
	}
	return apiv1.MarshalFindings(out)
}
