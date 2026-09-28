package render

import (
	"encoding/json"
	"slices"
	"strings"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
)

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// SARIF encodes open findings as SARIF 2.1.0 for github/codeql-action/upload-sarif.
// Locations come from CauseAddress looked up in locs. GitHub Code Scanning
// rejects results with zero locations, so unknown causes fall back to line 1
// of the cause address string as a URI (still one physicalLocation).
func SARIF(doc client.DFD, findings apiv1.Findings, texts map[string]apiv1.RuleText, locs map[string]client.SourceLocation) ([]byte, error) {
	byID := indexElements(doc)
	flows := indexFlows(doc)

	var open []apiv1.Finding
	for _, f := range findings.Findings {
		if f.Status == "open" {
			open = append(open, f)
		}
	}
	slices.SortFunc(open, func(a, b apiv1.Finding) int {
		if a.RuleID != b.RuleID {
			return strings.Compare(a.RuleID, b.RuleID)
		}
		return strings.Compare(a.Target, b.Target)
	})

	rules := sarifRules(open, texts)
	results := make([]sarifResult, 0, len(open))
	for _, f := range open {
		rule := texts[f.RuleID]
		msg := rule.Title
		if msg == "" {
			msg = f.RuleID
		}
		r := sarifResult{
			RuleID: f.RuleID,
			Level:  sarifLevel(f.Severity),
			Message: sarifMessage{Text: msg},
		}
		cause := CauseAddress(f, rule, byID, flows)
		phys := sarifPhysical{
			ArtifactLocation: sarifArtifact{URI: "fray.yaml"},
			Region:           &sarifRegion{StartLine: 1},
		}
		if loc, ok := client.LookupLocation(locs, cause); ok && loc.Path != "" {
			phys.ArtifactLocation.URI = loc.Path
			if loc.Line > 0 {
				phys.Region = &sarifRegion{StartLine: loc.Line}
			}
		}
		r.Locations = []sarifLocation{{PhysicalLocation: phys}}
		results = append(results, r)
	}

	docSARIF := sarifDocument{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:  "Fray",
				Rules: rules,
			}},
			Results: results,
		}},
	}
	raw, err := json.MarshalIndent(docSARIF, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}

func sarifRules(open []apiv1.Finding, texts map[string]apiv1.RuleText) []sarifReportingDescriptor {
	seen := map[string]bool{}
	var ids []string
	for _, f := range open {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		ids = append(ids, f.RuleID)
	}
	slices.Sort(ids)
	out := make([]sarifReportingDescriptor, 0, len(ids))
	for _, id := range ids {
		rule := texts[id]
		name := rule.Title
		if name == "" {
			name = id
		}
		out = append(out, sarifReportingDescriptor{
			ID:               id,
			Name:             name,
			ShortDescription: sarifMessage{Text: name},
		})
	}
	return out
}

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string                      `json:"name"`
	Rules []sarifReportingDescriptor  `json:"rules,omitempty"`
}

type sarifReportingDescriptor struct {
	ID               string       `json:"id"`
	Name             string       `json:"name,omitempty"`
	ShortDescription sarifMessage `json:"shortDescription,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}
