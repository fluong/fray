package render

// findingKey identifies a finding for baseline comparison.
type findingKey struct {
	rule   string
	target string
}

// MitigationEntry is one accepted/mitigated disposition from mitigations.yaml.
type MitigationEntry struct {
	RuleID  string
	Address string
	Status  string
	Reason  string
	Revisit string
}
