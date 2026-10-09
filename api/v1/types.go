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
	// Evidence is optional rule-specific facts (e.g. inbound writers for FR-027).
	Evidence []string `json:"evidence,omitempty"`
}

// Findings is the findings.json document shape.
type Findings struct {
	SchemaVersion string    `json:"schema_version"`
	Findings      []Finding `json:"findings"`
}

// Accepted is a customer disposition for one exact finding (rule + target id).
// Waivers (accepted_mitigations v2) send ID and Expires; Status is omitted.
// Reason, owner, and address never appear on the wire.
type Accepted struct {
	RuleID   string `json:"rule_id"`
	TargetID string `json:"target_id"`
	Status   string `json:"status,omitempty"`
	ID       string `json:"id,omitempty"`
	Expires  string `json:"expires,omitempty"` // YYYY-MM-DD
}

// WaiverStale is a waiver that did not mark a finding waived.
type WaiverStale struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// Waivers is the server-reported overlay outcome on a scan response.
type Waivers struct {
	Applied      []string      `json:"applied"`
	Expired      []string      `json:"expired"`
	Stale        []WaiverStale `json:"stale"`
	ExpiringSoon []string      `json:"expiring_soon"`
	NewInPR      []string      `json:"new_in_pr"`
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
	WhyHere      string            `json:"why_here,omitempty"`
	FixHere      string            `json:"fix_here,omitempty"`
	ContextWhen  []Condition       `json:"context_when,omitempty"`
	// CoversAttributes are DFD fields this rule speaks for (restates_rule).
	CoversAttributes []string `json:"covers_attributes,omitempty"`
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

// FindingEnrichment is optional AI prose under one rule finding.
// WhyHere and FixHere may contain {element_id} placeholders filled locally with names.
// When FixHere is set, the PR comment uses it in place of the rule's generic fix line.
type FindingEnrichment struct {
	RuleID  string `json:"rule_id"`
	Target  string `json:"target"`
	WhyHere string `json:"why_here,omitempty"`
	FixHere string `json:"fix_here,omitempty"`
}

// AdvisoryObservation is one AI-generated note. Text and Suggestion may use
// {element_id} placeholders; ElementIDs lists every element involved.
type AdvisoryObservation struct {
	Stride     string   `json:"stride"`
	ElementIDs []string `json:"element_ids"`
	Text       string   `json:"text"`
	Suggestion string   `json:"suggestion"`
}

// Advisory is AI analysis attached to a scan. It never affects the gate.
// When the LLM is skipped, Note is "AI analysis unavailable for this run".
type Advisory struct {
	Observations []AdvisoryObservation `json:"observations,omitempty"`
	Note         string                `json:"note,omitempty"`
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
		Mode    string       `json:"mode,omitempty"` // "none", "diff", or "absolute"
		Reasons []GateReason `json:"reasons"`
	} `json:"gate"`
	Baseline struct {
		Source     string    `json:"source"`
		Comparable *bool     `json:"comparable,omitempty"`
		Note       string    `json:"note,omitempty"`
		Commit     *string   `json:"commit"`
		ScanID     *string   `json:"scan_id"`
		Findings   *Findings `json:"findings,omitempty"`
	} `json:"baseline"`
	RuleTexts   map[string]RuleText `json:"rule_texts"`
	Advisory    *Advisory           `json:"advisory,omitempty"`
	Enrichments []FindingEnrichment `json:"enrichments,omitempty"`
	// Waivers is omitted by older servers; clients treat a missing object as
	// "server did not report waiver outcomes".
	Waivers *Waivers `json:"waivers,omitempty"`
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
