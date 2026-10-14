package main

import (
	"encoding/json"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
)

// findingFileEntry is the local findings.json row. It copies the API finding
// and may add Terraform addresses from the plaintext DFD (never on the wire).
type findingFileEntry struct {
	apiv1.Finding
	Addresses []string `json:"addresses,omitempty"`
}

type findingsFile struct {
	SchemaVersion string             `json:"schema_version"`
	Findings      []findingFileEntry `json:"findings"`
}

// marshalFindingsFile builds the local findings.json body. schema_version is
// taken from the API response (finding/v1). addresses come from the local
// plaintext doc (element Evidence.Addresses, or for a flow target the To then
// From element addresses). Unknown targets omit the field. All statuses.
func marshalFindingsFile(f apiv1.Findings, doc client.DFD) ([]byte, error) {
	byID := make(map[string]client.Element, len(doc.Elements))
	for _, el := range doc.Elements {
		byID[el.ID] = el
	}
	flows := make(map[string]client.Flow, len(doc.Flows))
	for _, fl := range doc.Flows {
		flows[fl.ID] = fl
	}

	out := findingsFile{
		SchemaVersion: f.SchemaVersion,
		Findings:      make([]findingFileEntry, 0, len(f.Findings)),
	}
	if f.Findings == nil {
		out.Findings = []findingFileEntry{}
	}
	for _, hit := range f.Findings {
		entry := findingFileEntry{Finding: hit}
		if addrs := addressesForTarget(hit.Target, byID, flows); len(addrs) > 0 {
			entry.Addresses = addrs
		}
		out.Findings = append(out.Findings, entry)
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func addressesForTarget(target string, byID map[string]client.Element, flows map[string]client.Flow) []string {
	if el, ok := byID[target]; ok {
		return copyStrings(el.Evidence.Addresses)
	}
	if fl, ok := flows[target]; ok {
		if el, ok := byID[fl.To]; ok && len(el.Evidence.Addresses) > 0 {
			return copyStrings(el.Evidence.Addresses)
		}
		if el, ok := byID[fl.From]; ok && len(el.Evidence.Addresses) > 0 {
			return copyStrings(el.Evidence.Addresses)
		}
	}
	return nil
}

func copyStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
