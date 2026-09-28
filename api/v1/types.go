// Package v1 is the Fray scan API wire contract.
package v1

import "encoding/json"

// Finding is one rule hit on one target element or flow.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Target   string   `json:"target"`
	Status   string   `json:"status"`
	Severity string   `json:"severity"`
	Stride   []string `json:"stride"`
}

// Findings is the findings.json document shape.
type Findings struct {
	SchemaVersion string    `json:"schema_version"`
	Findings      []Finding `json:"findings"`
}

// Accepted is a customer disposition for one exact finding (rule + target id).
type Accepted struct {
	RuleID   string `json:"rule_id"`
	TargetID string `json:"target_id"`
	Status   string `json:"status"`
}

// Condition is a when/pass predicate shipped in rule_texts so clients can
// name the failing attribute without shipping rule YAML.
type Condition struct {
	Op    string     `json:"op"`
	Field string     `json:"field"`
	Value any        `json:"value"`
	Cond  *Condition `json:"cond"`
}

// RuleRemediation is a provider-specific fix string.
type RuleRemediation struct {
	Provider    string `json:"provider"`
	Resource    string `json:"resource"`
	Text        string `json:"text"`
	Explanation string `json:"explanation"`
}

// RuleText is the display fields a client needs to render reports.
// It carries no Terraform addresses.
type RuleText struct {
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Threat       string            `json:"threat"`
	Explanation  string            `json:"explanation"`
	Group        string            `json:"group"`
	GroupTitle   string            `json:"group_title"`
	Before       string            `json:"before"`
	Mitigation   string            `json:"mitigation"`
	Remediations []RuleRemediation `json:"remediations"`
	When         []Condition       `json:"when"`
	Pass         []Condition       `json:"pass"`
	Target       string            `json:"target"`
	Severity     string            `json:"severity"`
	Stride       []string          `json:"stride"`
}

// GateReason identifies a finding that caused the gate to block.
type GateReason struct {
	RuleID   string `json:"rule_id"`
	TargetID string `json:"target_id"`
}

// ScanRequest is the POST /v1/scans body.
// Branch names are never sent: the client sets IsDefaultBranch after comparing
// locally; the server verifies against the OIDC ref when present.
type ScanRequest struct {
	DFD                 json.RawMessage `json:"dfd"`
	AcceptedMitigations []Accepted      `json:"accepted_mitigations"`
	Repo                string          `json:"repo"`
	Commit              string          `json:"commit"`
	IsDefaultBranch     bool            `json:"is_default_branch"`
	BaseCommit          string          `json:"base_commit,omitempty"`
}

// ScanResponse is the POST /v1/scans response.
type ScanResponse struct {
	ScanID   string   `json:"scan_id"`
	Findings Findings `json:"findings"`
	Diff     struct {
		New            []Finding `json:"new"`
		Resolved       []Finding `json:"resolved"`
		UnchangedCount int       `json:"unchanged_count"`
	} `json:"diff"`
	Gate struct {
		Blocked bool         `json:"blocked"`
		Reasons []GateReason `json:"reasons"`
	} `json:"gate"`
	Baseline struct {
		Source   string    `json:"source"`
		Commit   *string   `json:"commit"`
		ScanID   *string   `json:"scan_id"`
		Findings *Findings `json:"findings,omitempty"`
	} `json:"baseline"`
	RuleTexts map[string]RuleText `json:"rule_texts"`
}

// MarshalFindings encodes findings as indented JSON with a trailing newline.
func MarshalFindings(findings Findings) ([]byte, error) {
	if findings.Findings == nil {
		findings.Findings = []Finding{}
	}
	raw, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
