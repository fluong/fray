package render

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
)

// FR-029 pass shape: any[ public==false, all[ public==true, network_restricted==true ] ]
func fr029PassWithConds() []apiv1.Condition {
	return []apiv1.Condition{{
		Op: "any",
		Conds: []apiv1.Condition{
			{Op: "equals", Field: "attributes.public", Value: false},
			{
				Op: "all",
				Conds: []apiv1.Condition{
					{Op: "equals", Field: "attributes.public", Value: true},
					{Op: "equals", Field: "attributes.network_restricted", Value: true},
				},
			},
		},
	}}
}

func fr029RuleWithConds() apiv1.RuleText {
	return apiv1.RuleText{
		ID:               "FR-029",
		Title:            "Relational database is not directly reachable from the internet",
		Pass:             fr029PassWithConds(),
		CoversAttributes: []string{"public", "network_restricted"},
	}
}

func fr029RuleWithoutConds() apiv1.RuleText {
	return apiv1.RuleText{
		ID:               "FR-029",
		Title:            "Relational database is not directly reachable from the internet",
		Pass:             []apiv1.Condition{{Op: "any"}},
		CoversAttributes: []string{"public", "network_restricted"},
	}
}

func fr029RuleWithoutCondsOrCovers() apiv1.RuleText {
	return apiv1.RuleText{
		ID:    "FR-029",
		Title: "Relational database is not directly reachable from the internet",
		Pass:  []apiv1.Condition{{Op: "any"}},
	}
}

func dbElement(attrs map[string]any) (map[string]client.Element, map[string]client.Flow) {
	el := client.Element{
		ID:         "db1",
		Name:       "main",
		Kind:       "relational_db",
		Attributes: attrs,
		Evidence:   client.Evidence{Addresses: []string{"aws_db_instance.main"}},
		Causes:     map[string]string{},
	}
	for k := range attrs {
		el.Causes[k] = "aws_db_instance.main"
	}
	if _, ok := attrs["network_restricted"]; !ok {
		// cause may still exist for the address even when attr absent
	}
	el.Causes["network_restricted"] = "aws_db_instance.main"
	el.Causes["public"] = "aws_db_instance.main"
	return map[string]client.Element{"db1": el}, nil
}

func TestNestedConditionNaming(t *testing.T) {
	type want struct {
		PassState string   `json:"pass_state"`
		Failed    string   `json:"failed_attribute"`
		Missing   []string `json:"missing_fields"`
		Primary   string   `json:"primary_pass_field"`
	}
	cases := []struct {
		name   string
		golden string
		rule   apiv1.RuleText
		attrs  map[string]any
	}{
		{
			name:   "a_open_names_network_restricted",
			golden: "fr029-a-open.json",
			rule:   fr029RuleWithConds(),
			attrs:  map[string]any{"public": true, "network_restricted": false},
		},
		{
			name:   "b_unverified_missing_network_restricted",
			golden: "fr029-b-unverified.json",
			rule:   fr029RuleWithConds(),
			attrs:  map[string]any{"public": true},
		},
		{
			name:   "c_mitigated_private",
			golden: "fr029-c-mitigated-private.json",
			rule:   fr029RuleWithConds(),
			attrs:  map[string]any{"public": false},
		},
		{
			name:   "d_mitigated_restricted",
			golden: "fr029-d-mitigated-restricted.json",
			rule:   fr029RuleWithConds(),
			attrs:  map[string]any{"public": true, "network_restricted": true},
		},
		{
			name:   "e_old_server_with_covers",
			golden: "fr029-e-old-server-covers.json",
			rule:   fr029RuleWithoutConds(),
			attrs:  map[string]any{"public": true, "network_restricted": false},
		},
		{
			name:   "e_old_server_without_covers",
			golden: "fr029-e-old-server-omit.json",
			rule:   fr029RuleWithoutCondsOrCovers(),
			attrs:  map[string]any{"public": true, "network_restricted": false},
		},
	}
	dir := filepath.Join("..", "testdata", "golden", "nested-conds")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			byID, flows := dbElement(tc.attrs)
			el, flow := target("db1", byID, flows)
			state, _, _ := evalCond(tc.rule.Pass[0], el, flow, byID, 0)
			var passState string
			switch state {
			case triTrue:
				passState = "mitigated"
			case triFalse:
				passState = "open"
			default:
				passState = "unverified"
			}
			failed, _ := failedAttribute(tc.rule, "db1", byID, flows)
			missing := missingFields(tc.rule, "db1", byID, flows)
			if missing == nil {
				missing = []string{}
			}
			// Mitigated: never name a failed attribute.
			if passState == "mitigated" {
				failed = ""
			}
			got := want{
				PassState: passState,
				Failed:    failed,
				Missing:   missing,
				Primary:   primaryPassField(tc.rule),
			}
			raw, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, '\n')
			path := filepath.Join(dir, tc.golden)
			if os.Getenv("UPDATE") != "" {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			wantRaw, err := os.ReadFile(path)
			if err != nil {
				_ = os.WriteFile("/tmp/"+tc.golden, raw, 0o644)
				t.Fatalf("missing golden %s (wrote /tmp/%s): %v", path, tc.golden, err)
			}
			if string(raw) != string(wantRaw) {
				_ = os.WriteFile("/tmp/"+tc.golden, raw, 0o644)
				t.Fatalf("golden drift %s; wrote /tmp/%s\ngot:\n%s\nwant:\n%s", tc.golden, tc.golden, raw, wantRaw)
			}
		})
	}
}

func TestSARIFFR029PrimaryAndCause(t *testing.T) {
	byID, _ := dbElement(map[string]any{"public": true, "network_restricted": false})
	doc := client.DFD{Elements: []client.Element{byID["db1"]}}
	findings := apiv1.Findings{Findings: []apiv1.Finding{
		{RuleID: "FR-029", Target: "db1", Status: "open", Severity: "high"},
	}}
	texts := map[string]apiv1.RuleText{"FR-029": fr029RuleWithConds()}
	raw, err := SARIF(doc, findings, texts, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "testdata", "golden", "nested-conds", "fr029-a-open.sarif")
	if os.Getenv("UPDATE") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		_ = os.WriteFile("/tmp/fr029-a-open.sarif", raw, 0o644)
		t.Fatalf("missing golden (wrote /tmp/fr029-a-open.sarif): %v", err)
	}
	if string(raw) != string(want) {
		_ = os.WriteFile("/tmp/fr029-a-open.sarif", raw, 0o644)
		t.Fatalf("FR-029 SARIF drifted; wrote /tmp/fr029-a-open.sarif")
	}
	// Cause must point at network_restricted's address (same resource here).
	cause := CauseAddress(findings.Findings[0], texts["FR-029"], byID, nil)
	if cause != "aws_db_instance.main" {
		t.Fatalf("cause %q", cause)
	}
	failed, actual := failedAttribute(texts["FR-029"], "db1", byID, nil)
	if failed != "attributes.network_restricted" || actual != "false" {
		t.Fatalf("failedAttribute = %q/%q", failed, actual)
	}
	if primaryPassField(texts["FR-029"]) != "attributes.public" {
		t.Fatalf("primary %q", primaryPassField(texts["FR-029"]))
	}
}
