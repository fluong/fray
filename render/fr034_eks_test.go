package render

import (
	"strings"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
)

// TestPRCommentFR034EKSNodeGroupOpen shows the FR-034 open finding text for an
// EKS managed node group exactly as a user would see it in the PR comment. The
// element name must read as a node group — never "instance".
func TestPRCommentFR034EKSNodeGroupOpen(t *testing.T) {
	const ngName = "workers EKS node group"
	doc := client.DFD{
		Elements: []client.Element{{
			ID: "e0eksfr034wrk0001", Name: ngName, Type: "process",
			Kind: "virtual_machine", Provider: "aws", Provenance: "iac",
			Evidence: client.Evidence{Addresses: []string{"aws_eks_node_group.workers"}},
			Attributes: map[string]any{
				"public_ip":        true,
				"admin_ports_open": true,
			},
		}},
	}
	base := apiv1.Findings{SchemaVersion: "finding/v1"}
	cur := apiv1.Findings{Findings: []apiv1.Finding{{
		RuleID: "FR-034", Target: "e0eksfr034wrk0001", Status: "open",
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

	wantTitle := "**SSH or RDP is reachable from the internet on workers EKS node group**"
	if !strings.Contains(got, wantTitle) {
		t.Fatalf("missing EKS node group title:\n%s", got)
	}
	if !strings.Contains(got, "workers EKS node group has a public IP") {
		t.Fatalf("missing EKS node group explanation:\n%s", got)
	}
	if strings.Contains(got, "workers instance") || strings.Contains(got, "this instance") {
		t.Fatalf("EKS node group must not render as instance:\n%s", got)
	}
	t.Logf("rendered FR-034 EKS node group finding:\n%s", got)
}
