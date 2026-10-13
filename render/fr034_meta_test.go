package render

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
	"github.com/fluong/fray/client"
)

func fr034RuleTexts() map[string]apiv1.RuleText {
	return map[string]apiv1.RuleText{
		"FR-034": {
			ID:          "FR-034",
			Title:       "Admin ports are not open to the internet",
			GroupTitle:  "SSH or RDP is reachable from the internet on {element}",
			Explanation: "{element} has a public IP and its security groups allow SSH or RDP from the internet.",
			Mitigation:  "Remove the public IP, or restrict security group ingress so SSH and RDP are not open to the internet.",
			Severity:    "high",
			Stride:      []string{"elevation_of_privilege"},
			Pass: []apiv1.Condition{{
				Op: "equals", Field: "attributes.public_ip", Value: false,
			}},
		},
	}
}

func metaLineFromComment(comment string) string {
	for _, line := range strings.Split(comment, "\n") {
		if strings.HasPrefix(line, "`") && strings.Contains(line, " · ") {
			return line
		}
	}
	return ""
}

func fr034ComputeFixture(t *testing.T) (locs map[string]client.SourceLocation, asgLine, instLine int) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "infra")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Line numbers: blank line 1, ASG starts line 2, instance starts line 8.
	tf := `
resource "aws_autoscaling_group" "web" {
  name     = "web"
  max_size = 1
  min_size = 1
}

resource "aws_instance" "bastion" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tf), 0o644); err != nil {
		t.Fatal(err)
	}
	locs, err := client.ResourceLocations(dir)
	if err != nil {
		t.Fatal(err)
	}
	asgLoc, ok := client.LookupLocation(locs, "aws_autoscaling_group.web")
	if !ok {
		t.Fatal("missing ASG location")
	}
	instLoc, ok := client.LookupLocation(locs, "aws_instance.bastion")
	if !ok {
		t.Fatal("missing instance location")
	}
	return locs, asgLoc.Line, instLoc.Line
}

func TestPRCommentFR034MetaLineNoDuplicateAddress(t *testing.T) {
	texts := fr034RuleTexts()
	base := apiv1.Findings{SchemaVersion: "finding/v1"}

	asgDoc := client.DFD{Elements: []client.Element{{
		ID: "e-asg", Name: "web Auto Scaling group", Type: "process",
		Kind: "virtual_machine", Provider: "aws", Provenance: "iac",
		Evidence: client.Evidence{Addresses: []string{"aws_autoscaling_group.web"}},
		Attributes: map[string]any{"public_ip": true, "admin_ports_open": true},
	}}}
	asgCur := apiv1.Findings{Findings: []apiv1.Finding{{
		RuleID: "FR-034", Target: "e-asg", Status: "open", Severity: "high",
		Stride: []string{"elevation_of_privilege"},
	}}}
	instDoc := client.DFD{Elements: []client.Element{{
		ID: "e-inst", Name: "bastion", Type: "process",
		Kind: "virtual_machine", Provider: "aws", Provenance: "iac",
		Evidence: client.Evidence{Addresses: []string{"aws_instance.bastion"}},
		Attributes: map[string]any{"public_ip": true, "admin_ports_open": true},
	}}}
	instCur := apiv1.Findings{Findings: []apiv1.Finding{{
		RuleID: "FR-034", Target: "e-inst", Status: "open", Severity: "high",
		Stride: []string{"elevation_of_privilege"},
	}}}

	// Without config: second slot omitted (no address repeat).
	asgNoLoc := metaLineFromComment(PRComment(asgDoc, asgCur, base, texts, nil, nil, "", nil, nil, nil, true, nil))
	instNoLoc := metaLineFromComment(PRComment(instDoc, instCur, base, texts, nil, nil, "", nil, nil, nil, true, nil))
	wantASGNo := "`aws_autoscaling_group.web` · high · elevation of privilege"
	wantInstNo := "`aws_instance.bastion` · high · elevation of privilege"
	if asgNoLoc != wantASGNo {
		t.Fatalf("ASG no-locs meta:\n got %q\nwant %q", asgNoLoc, wantASGNo)
	}
	if instNoLoc != wantInstNo {
		t.Fatalf("instance no-locs meta:\n got %q\nwant %q", instNoLoc, wantInstNo)
	}
	if strings.Count(asgNoLoc, "aws_autoscaling_group.web") != 1 {
		t.Fatalf("ASG address repeated: %q", asgNoLoc)
	}
	if strings.Count(instNoLoc, "aws_instance.bastion") != 1 {
		t.Fatalf("instance address repeated: %q", instNoLoc)
	}

	// With config dir: second slot is file:line.
	locs, asgLine, instLine := fr034ComputeFixture(t)
	asgWith := metaLineFromComment(PRComment(asgDoc, asgCur, base, texts, locs, nil, "", nil, nil, nil, true, nil))
	instWith := metaLineFromComment(PRComment(instDoc, instCur, base, texts, locs, nil, "", nil, nil, nil, true, nil))
	wantASGWith := "`aws_autoscaling_group.web` · infra/main.tf:" + strconv.Itoa(asgLine) + " · high · elevation of privilege"
	wantInstWith := "`aws_instance.bastion` · infra/main.tf:" + strconv.Itoa(instLine) + " · high · elevation of privilege"
	if asgWith != wantASGWith {
		t.Fatalf("ASG with-locs meta:\n got %q\nwant %q", asgWith, wantASGWith)
	}
	if instWith != wantInstWith {
		t.Fatalf("instance with-locs meta:\n got %q\nwant %q", instWith, wantInstWith)
	}
	t.Logf("ASG no-locs:    %s", asgNoLoc)
	t.Logf("ASG with-locs:  %s", asgWith)
	t.Logf("inst with-locs: %s", instWith)
	t.Logf("inst no-locs:   %s", instNoLoc)

	// SARIF physical location for the same ASG finding points at the HCL file.
	raw, err := SARIF(asgDoc, asgCur, texts, locs, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) == 0 || len(doc.Runs[0].Results) == 0 || len(doc.Runs[0].Results[0].Locations) == 0 {
		t.Fatalf("SARIF missing result location: %s", raw)
	}
	phys := doc.Runs[0].Results[0].Locations[0].PhysicalLocation
	if phys.ArtifactLocation.URI != "infra/main.tf" {
		t.Fatalf("SARIF uri=%q want infra/main.tf", phys.ArtifactLocation.URI)
	}
	if phys.Region == nil || phys.Region.StartLine != asgLine {
		t.Fatalf("SARIF startLine=%v want %d", phys.Region, asgLine)
	}
}
