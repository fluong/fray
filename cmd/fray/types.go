package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type options struct {
	Plan, Source, Config, Waivers, Mitigations, Out string
	Repo, Commit, Declared, Branch, DefaultBranch, Remote string
	BaseCommit, BaseSource, APIKey, OIDCToken             string
	PayloadOut                                            string
	DryRun, ShowPayload, FailOnUnenrolled                 bool
	// ExternalPlan is set when the Action plan-file input supplied the plan
	// (not terraform show in this job). Enables validation, mismatch warning,
	// and the empty-DFD guard before any API call.
	ExternalPlan bool
}

type mitigationFile struct {
	Entries []mitigationEntry `yaml:"entries"`
}

type mitigationEntry struct {
	RuleID  string `yaml:"rule_id"`
	Address string `yaml:"address"`
	Status  string `yaml:"status"`
	Reason  string `yaml:"reason"`
	Revisit string `yaml:"revisit"`
}

func loadMitigations(path string) ([]mitigationEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file mitigationFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, err
	}
	return file.Entries, nil
}
