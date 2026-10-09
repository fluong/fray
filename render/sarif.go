package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
	"github.com/fluong/fray/version"
)

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// partialFingerprintKey is the stable identity namespace for Code Scanning.
const partialFingerprintKey = "fray/v1"

// SARIF encodes open and waived findings as SARIF 2.1.0 for
// github/codeql-action/upload-sarif. Mitigated, unverified, and legacy accepted
// findings are omitted (mitigated disappear as fixed in Code Scanning).
//
// Waived findings include suppressions (kind external, status accepted) so
// Code Scanning shows them as dismissed. Justification carries waiver id and
// expires only — never reason or owner.
//
// Locations come from CauseAddress looked up in locs. When changedInputs names
// module arguments for a finding's cause, the primary region spans those
// attribute lines (and relatedLocations lists each attribute) so Code Scanning
// attributes the alert to the PR diff, not the module header.
//
// partialFingerprints["fray/v1"] is sha256 hex of "<rule_id>|<cause address>"
// (or "<rule_id>|<DFD id>" when no Terraform address), stable across line moves.
//
// properties.security-severity follows GitHub's CVSS-style scale so the Code
// Scanning "check run failure" threshold (default High or higher) aligns with
// Fray's high-severity gate: high→7.5, medium→5.0, low→3.0, critical→9.0.
// Rule properties.tags always includes "security" so security-severity counts.
//
// waivers indexes local-id Accepted rows (id + expires) for suppression text.
// helpUri is omitted: public docs have no per-rule anchors yet.
func SARIF(doc client.DFD, findings apiv1.Findings, texts map[string]apiv1.RuleText, locs map[string]client.SourceLocation, changedInputs map[string][]string, waivers []apiv1.Accepted) ([]byte, error) {
	byID := indexElements(doc)
	flows := indexFlows(doc)
	waiverByKey := indexWaiverRefs(waivers)

	var include []apiv1.Finding
	for _, f := range findings.Findings {
		switch f.Status {
		case "open", "waived":
			include = append(include, f)
		}
	}
	slices.SortFunc(include, func(a, b apiv1.Finding) int {
		if a.RuleID != b.RuleID {
			return strings.Compare(a.RuleID, b.RuleID)
		}
		if a.Target != b.Target {
			return strings.Compare(a.Target, b.Target)
		}
		return strings.Compare(a.Status, b.Status)
	})

	rules := sarifRules(include, texts)
	results := make([]sarifResult, 0, len(include))
	for _, f := range include {
		rule := texts[f.RuleID]
		msg := rule.Title
		if msg == "" {
			msg = f.RuleID
		}
		sev := sarifSecuritySeverity(f.Severity)
		cause := CauseAddress(f, rule, byID, flows)
		r := sarifResult{
			RuleID: f.RuleID,
			Level:  sarifLevel(f.Severity),
			Message: sarifMessage{Text: msg},
			Properties: &sarifProperties{
				SecuritySeverity: sev,
			},
			PartialFingerprints: map[string]string{
				partialFingerprintKey: Fingerprint(f.RuleID, cause, f.Target),
			},
		}
		if f.Status == "waived" {
			r.Suppressions = []sarifSuppression{{
				Kind:          "external",
				Status:        "accepted",
				Justification: waiverJustification(f, waiverByKey),
			}}
		}
		phys := sarifPhysical{
			ArtifactLocation: sarifArtifact{URI: "fray.yaml"},
			Region:           &sarifRegion{StartLine: 1},
		}
		var related []sarifLocation
		if mc, ok := client.LookupModuleCause(locs, cause); ok {
			inputs := changedInputs[mc.Call]
			if len(inputs) > 0 {
				if region, ok := client.ModuleInputRegion(locs, mc.Call, inputs); ok && region.Path != "" {
					phys.ArtifactLocation.URI = region.Path
					phys.Region = sarifRegionFromLoc(region)
					for _, loc := range client.ModuleInputLocations(locs, mc.Call, inputs) {
						related = append(related, sarifLocation{
							PhysicalLocation: sarifPhysical{
								ArtifactLocation: sarifArtifact{URI: loc.Path},
								Region:           sarifRegionFromLoc(loc),
							},
						})
					}
				} else if mc.Location.Path != "" {
					phys.ArtifactLocation.URI = mc.Location.Path
					if mc.Location.Line > 0 {
						phys.Region = sarifRegionFromLoc(mc.Location)
					}
				}
			} else if mc.Location.Path != "" {
				phys.ArtifactLocation.URI = mc.Location.Path
				if mc.Location.Line > 0 {
					phys.Region = sarifRegionFromLoc(mc.Location)
				}
			}
		} else {
			field := ""
			if len(rule.Pass) > 0 {
				field = rule.Pass[0].Field
			}
			if loc, ok := client.LookupCauseLocation(locs, cause, field); ok && loc.Path != "" {
				phys.ArtifactLocation.URI = loc.Path
				if loc.Line > 0 {
					phys.Region = sarifRegionFromLoc(loc)
				}
			}
		}
		r.Locations = []sarifLocation{{PhysicalLocation: phys}}
		if len(related) > 0 {
			r.RelatedLocations = related
		}
		results = append(results, r)
	}

	docSARIF := sarifDocument{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:            "Fray",
				Version:         version.Version,
				SemanticVersion: version.Version,
				InformationURI:  version.InformationURI,
				Rules:           rules,
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

// Fingerprint returns the fray/v1 partialFingerprint value: sha256 hex of
// "<rule_id>|<cause Terraform address>", or "<rule_id>|<DFD id>" when cause is empty.
func Fingerprint(ruleID, causeAddress, targetID string) string {
	right := causeAddress
	if right == "" {
		right = targetID
	}
	sum := sha256.Sum256([]byte(ruleID + "|" + right))
	return hex.EncodeToString(sum[:])
}

func indexWaiverRefs(waivers []apiv1.Accepted) map[string]apiv1.Accepted {
	out := make(map[string]apiv1.Accepted, len(waivers))
	for _, w := range waivers {
		if w.RuleID == "" || w.TargetID == "" || w.ID == "" {
			continue
		}
		out[w.RuleID+"\x00"+w.TargetID] = w
	}
	return out
}

func waiverJustification(f apiv1.Finding, byKey map[string]apiv1.Accepted) string {
	if w, ok := byKey[f.RuleID+"\x00"+f.Target]; ok {
		return fmt.Sprintf("Waived via .fray/waivers.yml (id %s, until %s)", w.ID, w.Expires)
	}
	return "Waived via .fray/waivers.yml"
}

func sarifRegionFromLoc(loc client.SourceLocation) *sarifRegion {
	r := &sarifRegion{StartLine: loc.Line}
	if loc.EndLine > loc.Line {
		r.EndLine = loc.EndLine
	}
	return r
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}

// sarifSecuritySeverity maps Fray severity to GitHub Code Scanning's
// properties.security-severity (CVSS-style 0.0–10.0 string).
func sarifSecuritySeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "9.0"
	case "high":
		return "7.5"
	case "medium":
		return "5.0"
	case "low":
		return "3.0"
	default:
		return "5.0"
	}
}

func sarifRules(include []apiv1.Finding, texts map[string]apiv1.RuleText) []sarifReportingDescriptor {
	seen := map[string]bool{}
	var ids []string
	severityByRule := map[string]string{}
	for _, f := range include {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			ids = append(ids, f.RuleID)
			severityByRule[f.RuleID] = f.Severity
		}
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
			Properties: &sarifProperties{
				SecuritySeverity: sarifSecuritySeverity(severityByRule[id]),
				Tags:             []string{"security"},
			},
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
	Name            string                     `json:"name"`
	Version         string                     `json:"version,omitempty"`
	SemanticVersion string                     `json:"semanticVersion,omitempty"`
	InformationURI  string                     `json:"informationUri,omitempty"`
	Rules           []sarifReportingDescriptor `json:"rules,omitempty"`
}

type sarifReportingDescriptor struct {
	ID               string           `json:"id"`
	Name             string           `json:"name,omitempty"`
	ShortDescription sarifMessage     `json:"shortDescription,omitempty"`
	HelpURI          string           `json:"helpUri,omitempty"`
	Properties       *sarifProperties `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID              string              `json:"ruleId"`
	Level               string              `json:"level"`
	Message             sarifMessage        `json:"message"`
	Locations           []sarifLocation     `json:"locations,omitempty"`
	RelatedLocations    []sarifLocation     `json:"relatedLocations,omitempty"`
	PartialFingerprints map[string]string   `json:"partialFingerprints,omitempty"`
	Suppressions        []sarifSuppression  `json:"suppressions,omitempty"`
	Properties          *sarifProperties    `json:"properties,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

type sarifProperties struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
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
	EndLine   int `json:"endLine,omitempty"`
}
