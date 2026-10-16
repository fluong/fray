package render

import (
	"strings"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
)

// TestPRCommentFR034ASGOpen shows the FR-034 open finding text for an Auto
// Scaling group exactly as a user would see it in the PR comment. The element
// name must read as a group — never "instance".
func TestPRCommentFR034ASGOpen(t *testing.T) {
	const asgName = "web Auto Scaling group"
	doc := client.DFD{
		Elements: []client.Element{{
			ID: "e0asgfr034web0001", Name: asgName, Type: "process",
			Kind: "virtual_machine", Provider: "aws", Provenance: "iac",
			Evidence: client.Evidence{Addresses: []string{"aws_autoscaling_group.web"}},
			Attributes: map[string]any{
				"public_ip":        true,
				"admin_ports_open": true,
			},
		}},
	}
	base := apiv1.Findings{SchemaVersion: "finding/v1"}
	cur := apiv1.Findings{Findings: []apiv1.Finding{{
		RuleID: "FR-034", Target: "e0asgfr034web0001", Status: "open",
		Severity: "high", Stride: []string{"elevation_of_privilege"},
	}}}
	texts := map[string]apiv1.RuleText{
		"FR-034": {
			ID:          "FR-034",
			Title:       "Admin ports are not open to the internet",
			Threat:      "SSH or RDP is reachable from the internet on this instance",
			GroupTitle:  "SSH or RDP is reachable from the internet on {element}",
			Explanation: "{element} has a public IP and its security groups allow SSH or RDP from the internet.",
			Mitigation:  "Remove the public IP, or restrict security group ingress so SSH and RDP are not open to the internet.",
			Severity:    "high",
			Stride:      []string{"elevation_of_privilege"},
		},
	}
	got := PRComment(doc, cur, base, texts, nil, nil, "", nil, nil, nil, true, nil)

	wantTitle := "**SSH or RDP is reachable from the internet on web Auto Scaling group**"
	if !strings.Contains(got, wantTitle) {
		t.Fatalf("missing ASG title:\n%s", got)
	}
	if !strings.Contains(got, "web Auto Scaling group has a public IP") {
		t.Fatalf("missing ASG explanation:\n%s", got)
	}
	if strings.Contains(got, "web instance") || strings.Contains(got, "this instance") {
		t.Fatalf("ASG must not render as instance:\n%s", got)
	}
	t.Logf("rendered FR-034 ASG finding:\n%s", got)
}
