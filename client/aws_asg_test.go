package client

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
)

func TestASGPublicIPAndAdmin(t *testing.T) {
	cases := []struct {
		name         string
		build        func() (planResource, []planResource, configIndex)
		wantPublic   bool
		wantPublicOK bool
		wantAdmin    bool
		wantAdminOK  bool
	}{
		{
			name: "template public + world SSH → both true",
			build: func() (planResource, []planResource, configIndex) {
				return asgLTFixture(t, asgOpts{
					version:             "$Latest",
					tmplAssociatePublic: boolPtr(true),
					subnetPublic:        []bool{false},
					tmplWorldSSH:        true,
					tmplActions:         []string{"no-op"},
				})
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "template private + all private subnets → false/false",
			build: func() (planResource, []planResource, configIndex) {
				return asgLTFixture(t, asgOpts{
					version:             "$Latest",
					tmplAssociatePublic: boolPtr(false),
					subnetPublic:        []bool{false, false},
					tmplWorldSSH:        false,
					tmplActions:         []string{"no-op"},
				})
			},
			wantPublic: false, wantPublicOK: true,
			wantAdmin: false, wantAdminOK: true,
		},
		{
			name: "unset associate + one public subnet of three → public true",
			build: func() (planResource, []planResource, configIndex) {
				return asgLTFixture(t, asgOpts{
					version:      "$Latest",
					subnetPublic: []bool{false, true, false},
					tmplWorldSSH: false,
					tmplActions:  []string{"no-op"},
				})
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: false, wantAdminOK: true,
		},
		{
			name: "unset associate + all private subnets → public false",
			build: func() (planResource, []planResource, configIndex) {
				return asgLTFixture(t, asgOpts{
					version:      "$Latest",
					subnetPublic: []bool{false, false},
					tmplWorldSSH: false,
					tmplActions:  []string{"no-op"},
				})
			},
			wantPublic: false, wantPublicOK: true,
			wantAdmin: false, wantAdminOK: true,
		},
		{
			name: "subnet not in plan → omit public",
			build: func() (planResource, []planResource, configIndex) {
				asg, resources, idx := asgLTFixture(t, asgOpts{
					version:             "$Latest",
					tmplAssociatePublic: nil,
					subnetPublic:        []bool{false},
					tmplWorldSSH:        false,
					tmplActions:         []string{"no-op"},
				})
				// Point vpc_zone_identifier at a missing subnet.
				set := idx.resources[asg.address]
				set.refs["vpc_zone_identifier"] = []string{"aws_subnet.missing.id", "aws_subnet.missing"}
				idx.resources[asg.address] = set
				return asg, resources, idx
			},
			wantPublic: false, wantPublicOK: false,
			wantAdmin: false, wantAdminOK: true,
		},
		{
			name: "$Latest used",
			build: func() (planResource, []planResource, configIndex) {
				return asgLTFixture(t, asgOpts{
					version:             "$Latest",
					tmplAssociatePublic: boolPtr(true),
					subnetPublic:        []bool{false},
					tmplWorldSSH:        true,
					tmplActions:         []string{"update"},
				})
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "$Default with update_default_version=true used",
			build: func() (planResource, []planResource, configIndex) {
				return asgLTFixture(t, asgOpts{
					version:              "$Default",
					updateDefaultVersion: boolPtr(true),
					tmplAssociatePublic:  boolPtr(true),
					subnetPublic:         []bool{false},
					tmplWorldSSH:         true,
					tmplActions:          []string{"update"},
				})
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "$Default without update_default_version on update → omit",
			build: func() (planResource, []planResource, configIndex) {
				return asgLTFixture(t, asgOpts{
					version:             "$Default",
					tmplAssociatePublic: boolPtr(true),
					subnetPublic:        []bool{false},
					tmplWorldSSH:        true,
					tmplActions:         []string{"update"},
				})
			},
			wantPublic: false, wantPublicOK: false,
			wantAdmin: false, wantAdminOK: false,
		},
		{
			name: "omitted version on template created in plan → used",
			build: func() (planResource, []planResource, configIndex) {
				return asgLTFixture(t, asgOpts{
					omitVersion:         true,
					tmplAssociatePublic: boolPtr(true),
					subnetPublic:        []bool{false},
					tmplWorldSSH:        true,
					tmplActions:         []string{"create"},
				})
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "pinned version → omit",
			build: func() (planResource, []planResource, configIndex) {
				return asgLTFixture(t, asgOpts{
					version:             "3",
					tmplAssociatePublic: boolPtr(true),
					subnetPublic:        []bool{false},
					tmplWorldSSH:        true,
					tmplActions:         []string{"create"},
				})
			},
			wantPublic: false, wantPublicOK: false,
			wantAdmin: false, wantAdminOK: false,
		},
		{
			name: "mixed policy agree → both true",
			build: func() (planResource, []planResource, configIndex) {
				return asgMixedFixture(t, mixedOpts{agree: true, secondUnknown: false})
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "mixed policy disagree public IP → omit public",
			build: func() (planResource, []planResource, configIndex) {
				return asgMixedFixture(t, mixedOpts{disagreePublic: true})
			},
			wantPublic: false, wantPublicOK: false,
			wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "mixed policy unknown override version → omit",
			build: func() (planResource, []planResource, configIndex) {
				return asgMixedFixture(t, mixedOpts{secondUnknown: true})
			},
			wantPublic: false, wantPublicOK: false,
			wantAdmin: false, wantAdminOK: false,
		},
		{
			name: "launch configuration public + world SSH → both true",
			build: func() (planResource, []planResource, configIndex) {
				return asgLCFixture(t, true, true)
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "launch configuration private + closed SG → false/false",
			build: func() (planResource, []planResource, configIndex) {
				return asgLCFixture(t, false, false)
			},
			wantPublic: false, wantPublicOK: true,
			wantAdmin: false, wantAdminOK: true,
		},
		{
			name: "module-created ASG (autoscaling module shape)",
			build: func() (planResource, []planResource, configIndex) {
				return asgModuleFixture(t)
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: true, wantAdminOK: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asg, resources, idx := tc.build()
			got, known := asgPublicIP(asg, resources, nil, idx)
			if known != tc.wantPublicOK || (known && got != tc.wantPublic) {
				t.Fatalf("public_ip=(%v,%v) want (%v,%v)", got, known, tc.wantPublic, tc.wantPublicOK)
			}
			gotA, knownA := asgAdminPortsOpen(asg, resources, nil, idx)
			if knownA != tc.wantAdminOK || (knownA && gotA != tc.wantAdmin) {
				t.Fatalf("admin_ports_open=(%v,%v) want (%v,%v)", gotA, knownA, tc.wantAdmin, tc.wantAdminOK)
			}
		})
	}
}

func TestASGElementNameAndKind(t *testing.T) {
	asg, resources, idx := asgLTFixture(t, asgOpts{
		version:             "$Latest",
		tmplAssociatePublic: boolPtr(true),
		subnetPublic:        []bool{false},
		tmplWorldSSH:        true,
		tmplActions:         []string{"no-op"},
	})
	el := awsASGElement(asg, resources, nil, idx)
	if el.Kind != "virtual_machine" || el.Type != "process" || el.Provenance != "iac" {
		t.Fatalf("meta: kind=%s type=%s provenance=%s", el.Kind, el.Type, el.Provenance)
	}
	if el.Name != "web Auto Scaling group" {
		t.Fatalf("name=%q want %q", el.Name, "web Auto Scaling group")
	}
	if strings.Contains(el.Name, "instance") {
		t.Fatalf("ASG name must not contain instance: %q", el.Name)
	}
}

func TestASGNoLeak(t *testing.T) {
	plan := asgNoLeakPlanJSON(t)
	cfg := []byte("schema_version: fray-config/v1\n")
	src := Source{Repo: "probe/asg", Commit: "abcdef1234567", Tool: "terraform", Fidelity: "plan"}
	doc, _, err := Parse(plan, cfg, "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	assertASGNoLeak(t, raw)
	for _, el := range doc.Elements {
		if el.Kind == "virtual_machine" && strings.Contains(strings.ToLower(el.Name), "instance") {
			t.Fatalf("ASG rendered as instance: %q", el.Name)
		}
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	wire, _, err := Redact(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	rawDFD, err := Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(apiv1.ScanRequest{
		DFD: rawDFD, Repo: wire.Source.Repo, Commit: "abcdef1234567", IsDefaultBranch: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertASGNoLeak(t, body)
}

func TestAWSWebAppPlanUnchangedWithASG(t *testing.T) {
	plan, err := os.ReadFile("testdata/aws-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "", Source{
		Repo: "example/aws-web-app", Commit: "4530a865f29ba14931379f361b177a992edeab51",
		Tool: "terraform", Fidelity: "plan",
	}, filepath.Join("..", "testdata", "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) > 0 {
		t.Fatalf("warnings: %s", strings.Join(warnings, "\n"))
	}
	got, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "testdata", "golden", "aws-web-app-fixture.dfd.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("demo DFD changed (%d vs %d bytes)", len(got), len(want))
	}
}

// --- fixtures ---

type asgOpts struct {
	version              string
	omitVersion          bool
	updateDefaultVersion *bool
	tmplAssociatePublic  *bool
	subnetPublic         []bool
	tmplWorldSSH         bool
	tmplActions          []string
}

func asgLTFixture(t *testing.T, o asgOpts) (planResource, []planResource, configIndex) {
	t.Helper()
	ltBlock := map[string]any{"id": "lt-0asgdistinct0011"}
	if !o.omitVersion {
		ltBlock["version"] = o.version
	}
	asg := planResource{
		typ: "aws_autoscaling_group", address: "aws_autoscaling_group.web",
		values: map[string]any{
			"name":            "web",
			"launch_template": []any{ltBlock},
		},
	}

	var resources []planResource
	resources = append(resources, asg)
	var subnetRefs []string
	for i, pub := range o.subnetPublic {
		addr := fmt.Sprintf("aws_subnet.z%d", i)
		id := fmt.Sprintf("subnet-0asgz%d0011", i)
		sn := planResource{
			typ: "aws_subnet", address: addr,
			values: map[string]any{"map_public_ip_on_launch": pub, "id": id},
		}
		resources = append(resources, sn)
		subnetRefs = append(subnetRefs, addr+".id", addr)
	}

	sg := planResource{
		typ: "aws_security_group", address: "aws_security_group.asg_ssh",
		values: map[string]any{"ingress": []any{}},
	}
	if o.tmplWorldSSH {
		sg.values["ingress"] = []any{map[string]any{
			"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
			"cidr_blocks": []any{"0.0.0.0/0"},
		}}
	} else {
		sg.values["ingress"] = []any{map[string]any{
			"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
			"cidr_blocks": []any{"10.0.0.0/8"},
		}}
	}
	resources = append(resources, sg)

	nis := []any{}
	if o.tmplAssociatePublic != nil {
		nis = []any{map[string]any{"associate_public_ip_address": *o.tmplAssociatePublic}}
	}
	tmplVals := map[string]any{
		"id":                 "lt-0asgdistinct0011",
		"name":               "fray-asg-lt",
		"network_interfaces": nis,
	}
	if o.updateDefaultVersion != nil {
		tmplVals["update_default_version"] = *o.updateDefaultVersion
	}
	tmpl := planResource{
		typ: "aws_launch_template", address: "aws_launch_template.app",
		values: tmplVals, actions: o.tmplActions,
	}
	resources = append(resources, tmpl)

	idx := configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
	ltExpr := map[string]any{
		"id": map[string]any{"references": []any{"aws_launch_template.app.id", "aws_launch_template.app"}},
	}
	ltRefs := []string{"aws_launch_template.app.id", "aws_launch_template.app"}
	if o.omitVersion {
		// version absent
	} else {
		ltExpr["version"] = map[string]any{"constant_value": o.version}
	}
	idx.resources[asg.address] = exprSet{
		refs: map[string][]string{
			"launch_template":     ltRefs,
			"vpc_zone_identifier": subnetRefs,
		},
		raw: map[string]any{
			"launch_template":     []any{ltExpr},
			"vpc_zone_identifier": map[string]any{"references": stringSliceAny(subnetRefs)},
		},
	}
	idx.resources[tmpl.address] = exprSet{
		refs: map[string][]string{
			"network_interfaces": {"aws_security_group.asg_ssh.id", "aws_security_group.asg_ssh"},
		},
		raw: map[string]any{
			"network_interfaces": []any{map[string]any{
				"security_groups": map[string]any{
					"references": []any{"aws_security_group.asg_ssh.id", "aws_security_group.asg_ssh"},
				},
			}},
		},
	}
	for _, r := range resources {
		if r.typ == "aws_subnet" || r.typ == "aws_security_group" {
			if _, ok := idx.resources[r.address]; !ok {
				idx.resources[r.address] = exprSet{}
			}
		}
	}
	return asg, resources, idx
}

type mixedOpts struct {
	agree          bool
	disagreePublic bool
	secondUnknown  bool // pinned version on override
}

func asgMixedFixture(t *testing.T, o mixedOpts) (planResource, []planResource, configIndex) {
	t.Helper()
	assocA := true
	assocB := true
	if o.disagreePublic {
		assocB = false
	}
	verB := "$Latest"
	actionsB := []string{"no-op"}
	if o.secondUnknown {
		verB = "9"
		actionsB = []string{"update"}
	}

	asg := planResource{
		typ: "aws_autoscaling_group", address: "aws_autoscaling_group.web",
		values: map[string]any{
			"mixed_instances_policy": []any{map[string]any{
				"launch_template": []any{map[string]any{
					"launch_template_specification": []any{map[string]any{
						"launch_template_id": "lt-0mixeda0011",
						"version":            "$Latest",
					}},
					"override": []any{map[string]any{
						"launch_template_specification": []any{map[string]any{
							"launch_template_id": "lt-0mixedb0011",
							"version":            verB,
						}},
					}},
				}},
			}},
		},
	}
	subnet := planResource{
		typ: "aws_subnet", address: "aws_subnet.private",
		values: map[string]any{"map_public_ip_on_launch": false, "id": "subnet-0mixedpriv0011"},
	}
	sg := planResource{
		typ: "aws_security_group", address: "aws_security_group.asg_ssh",
		values: map[string]any{"ingress": []any{map[string]any{
			"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
			"cidr_blocks": []any{"0.0.0.0/0"},
		}}},
	}
	tmplA := planResource{
		typ: "aws_launch_template", address: "aws_launch_template.a",
		values: map[string]any{
			"id": "lt-0mixeda0011",
			"network_interfaces": []any{map[string]any{
				"associate_public_ip_address": assocA,
			}},
		},
		actions: []string{"no-op"},
	}
	tmplB := planResource{
		typ: "aws_launch_template", address: "aws_launch_template.b",
		values: map[string]any{
			"id": "lt-0mixedb0011",
			"network_interfaces": []any{map[string]any{
				"associate_public_ip_address": assocB,
			}},
		},
		actions: actionsB,
	}
	idx := configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
	idx.resources[asg.address] = exprSet{
		refs: map[string][]string{
			"mixed_instances_policy": {
				"aws_launch_template.a.id", "aws_launch_template.a",
				"aws_launch_template.b.id", "aws_launch_template.b",
			},
			"vpc_zone_identifier": {"aws_subnet.private.id", "aws_subnet.private"},
		},
		raw: map[string]any{"mixed_instances_policy": []any{}},
	}
	for _, tmpl := range []planResource{tmplA, tmplB} {
		idx.resources[tmpl.address] = exprSet{
			refs: map[string][]string{
				"network_interfaces": {"aws_security_group.asg_ssh.id", "aws_security_group.asg_ssh"},
			},
			raw: map[string]any{
				"network_interfaces": []any{map[string]any{
					"security_groups": map[string]any{
						"references": []any{"aws_security_group.asg_ssh.id", "aws_security_group.asg_ssh"},
					},
				}},
			},
		}
	}
	idx.resources[subnet.address] = exprSet{}
	idx.resources[sg.address] = exprSet{}
	_ = o.agree
	return asg, []planResource{asg, subnet, sg, tmplA, tmplB}, idx
}

func asgLCFixture(t *testing.T, public, worldSSH bool) (planResource, []planResource, configIndex) {
	t.Helper()
	asg := planResource{
		typ: "aws_autoscaling_group", address: "aws_autoscaling_group.web",
		values: map[string]any{"launch_configuration": "fray-asg-lc"},
	}
	subnet := planResource{
		typ: "aws_subnet", address: "aws_subnet.private",
		values: map[string]any{"map_public_ip_on_launch": false, "id": "subnet-0lcpriv0011"},
	}
	cidr := "10.0.0.0/8"
	if worldSSH {
		cidr = "0.0.0.0/0"
	}
	sg := planResource{
		typ: "aws_security_group", address: "aws_security_group.asg_ssh",
		values: map[string]any{"ingress": []any{map[string]any{
			"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
			"cidr_blocks": []any{cidr},
		}}},
	}
	lc := planResource{
		typ: "aws_launch_configuration", address: "aws_launch_configuration.app",
		values: map[string]any{
			"name":                        "fray-asg-lc",
			"associate_public_ip_address": public,
		},
	}
	idx := configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
	idx.resources[asg.address] = exprSet{
		refs: map[string][]string{
			"launch_configuration": {"aws_launch_configuration.app.name", "aws_launch_configuration.app"},
			"vpc_zone_identifier":  {"aws_subnet.private.id", "aws_subnet.private"},
		},
		raw: map[string]any{
			"launch_configuration": map[string]any{
				"references": []any{"aws_launch_configuration.app.name", "aws_launch_configuration.app"},
			},
		},
	}
	idx.resources[lc.address] = exprSet{
		refs: map[string][]string{
			"security_groups": {"aws_security_group.asg_ssh.id", "aws_security_group.asg_ssh"},
		},
		raw: map[string]any{
			"security_groups": map[string]any{
				"references": []any{"aws_security_group.asg_ssh.id", "aws_security_group.asg_ssh"},
			},
		},
	}
	idx.resources[subnet.address] = exprSet{}
	idx.resources[sg.address] = exprSet{}
	return asg, []planResource{asg, subnet, sg, lc}, idx
}

func asgModuleFixture(t *testing.T) (planResource, []planResource, configIndex) {
	t.Helper()
	// terraform-aws-modules/autoscaling shape: module.asg.aws_autoscaling_group.this[0]
	// with a sibling launch template in the same module.
	asg := planResource{
		typ: "aws_autoscaling_group", address: "module.asg.aws_autoscaling_group.this[0]",
		values: map[string]any{
			"name": "module-asg",
			"launch_template": []any{map[string]any{
				"id":      "lt-0modasg0011",
				"version": "$Latest",
			}},
		},
	}
	subnet := planResource{
		typ: "aws_subnet", address: "aws_subnet.private",
		values: map[string]any{"map_public_ip_on_launch": false, "id": "subnet-0modasg0011"},
	}
	sg := planResource{
		typ: "aws_security_group", address: "module.asg.aws_security_group.this[0]",
		values: map[string]any{"ingress": []any{map[string]any{
			"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
			"cidr_blocks": []any{"0.0.0.0/0"},
		}}},
	}
	tmpl := planResource{
		typ: "aws_launch_template", address: "module.asg.aws_launch_template.this[0]",
		values: map[string]any{
			"id": "lt-0modasg0011",
			"network_interfaces": []any{map[string]any{
				"associate_public_ip_address": true,
			}},
		},
		actions: []string{"no-op"},
	}
	idx := configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
	// configIndex keys are resourceKey (index stripped).
	asgKey, _ := resourceKey(asg.address)
	tmplKey, _ := resourceKey(tmpl.address)
	sgKey, _ := resourceKey(sg.address)
	idx.resources[asgKey] = exprSet{
		refs: map[string][]string{
			"launch_template": {
				"module.asg.aws_launch_template.this[0].id",
				"module.asg.aws_launch_template.this[0]",
			},
			"vpc_zone_identifier": {"aws_subnet.private.id", "aws_subnet.private"},
		},
		raw: map[string]any{
			"launch_template": []any{map[string]any{
				"id": map[string]any{"references": []any{
					"module.asg.aws_launch_template.this[0].id",
					"module.asg.aws_launch_template.this[0]",
				}},
				"version": map[string]any{"constant_value": "$Latest"},
			}},
		},
	}
	idx.resources[tmplKey] = exprSet{
		refs: map[string][]string{
			"network_interfaces": {
				"module.asg.aws_security_group.this[0].id",
				"module.asg.aws_security_group.this[0]",
			},
		},
		raw: map[string]any{
			"network_interfaces": []any{map[string]any{
				"security_groups": map[string]any{"references": []any{
					"module.asg.aws_security_group.this[0].id",
					"module.asg.aws_security_group.this[0]",
				}},
			}},
		},
	}
	idx.resources[sgKey] = exprSet{}
	idx.resources[subnet.address] = exprSet{}
	return asg, []planResource{asg, subnet, sg, tmpl}, idx
}

func asgNoLeakPlanJSON(t *testing.T) []byte {
	t.Helper()
	root := map[string]any{
		"resource_changes": []any{
			map[string]any{
				"address": "aws_autoscaling_group.web", "mode": "managed", "type": "aws_autoscaling_group",
				"change": map[string]any{
					"actions": []any{"create"},
					"after": map[string]any{
						"name": "fray-asg-leak-name-zz9",
						"launch_template": []any{map[string]any{
							"id": "lt-0asgleakytmpl0011", "version": "$Latest",
						}},
					},
				},
			},
			map[string]any{
				"address": "aws_launch_template.app", "mode": "managed", "type": "aws_launch_template",
				"change": map[string]any{
					"actions": []any{"create"},
					"after": map[string]any{
						"id":   "lt-0asgleakytmpl0011",
						"name": "fray-asg-lt-leak-zz9",
						"network_interfaces": []any{map[string]any{
							"associate_public_ip_address": true,
						}},
					},
				},
			},
			map[string]any{
				"address": "aws_subnet.private", "mode": "managed", "type": "aws_subnet",
				"change": map[string]any{"after": map[string]any{
					"map_public_ip_on_launch": false,
					"id":                      "subnet-0asgleaksub0011",
				}},
			},
			map[string]any{
				"address": "aws_security_group.asg_ssh", "mode": "managed", "type": "aws_security_group",
				"change": map[string]any{"after": map[string]any{
					"id": "sg-0asgleaksg0011",
					"ingress": []any{map[string]any{
						"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
						"cidr_blocks": []any{"198.51.100.64/26", "0.0.0.0/0"},
					}},
				}},
			},
		},
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{
						"address": "aws_autoscaling_group.web", "type": "aws_autoscaling_group", "name": "web",
						"expressions": map[string]any{
							"vpc_zone_identifier": map[string]any{
								"references": []any{"aws_subnet.private.id", "aws_subnet.private"},
							},
							"launch_template": []any{map[string]any{
								"id": map[string]any{"references": []any{"aws_launch_template.app.id", "aws_launch_template.app"}},
								"version": map[string]any{"constant_value": "$Latest"},
							}},
						},
					},
					map[string]any{
						"address": "aws_launch_template.app", "type": "aws_launch_template", "name": "app",
						"expressions": map[string]any{
							"network_interfaces": []any{map[string]any{
								"associate_public_ip_address": map[string]any{"constant_value": true},
								"security_groups": map[string]any{
									"references": []any{"aws_security_group.asg_ssh.id", "aws_security_group.asg_ssh"},
								},
							}},
						},
					},
					map[string]any{
						"address": "aws_subnet.private", "type": "aws_subnet", "name": "private",
						"expressions": map[string]any{},
					},
					map[string]any{
						"address": "aws_security_group.asg_ssh", "type": "aws_security_group", "name": "asg_ssh",
						"expressions": map[string]any{},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var asgLeakNeedles = []string{
	"lt-0asgleakytmpl0011",
	"fray-asg-lt-leak-zz9",
	"fray-asg-leak-name-zz9",
	"198.51.100.64/26",
	"sg-0asgleaksg0011",
	"subnet-0asgleaksub0011",
}

func assertASGNoLeak(t *testing.T, body []byte) {
	t.Helper()
	for _, n := range asgLeakNeedles {
		if bytes.Contains(body, []byte(n)) {
			t.Errorf("FAIL: leak needle %q PRESENT", n)
		}
	}
}

func stringSliceAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
