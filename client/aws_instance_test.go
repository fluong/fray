package client

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apiv1 "github.com/fluong/fray/api/v1"
)

func TestInstancePublicIPTable(t *testing.T) {
	cases := []struct {
		name      string
		build     func() (planResource, []planResource, configIndex)
		wantVal   bool
		wantKnown bool
	}{
		{
			name: "explicit true",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := rootInstanceBare(t)
				inst.values["associate_public_ip_address"] = true
				return inst, resources, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "explicit false + no IPv6 → false",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := rootInstanceBare(t)
				inst.values["associate_public_ip_address"] = false
				inst.values["ipv6_address_count"] = float64(0)
				return inst, resources, idx
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "unset + public subnet → true",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := rootInstanceWithSubnet(t, true)
				return inst, resources, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "unset + private subnet → false",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := rootInstanceWithSubnet(t, false)
				inst.values["ipv6_address_count"] = float64(0)
				return inst, resources, idx
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "subnet not in plan → omit",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := rootInstanceBare(t)
				idx.resources[inst.address] = exprSet{refs: map[string][]string{
					"subnet_id": {"aws_subnet.missing.id", "aws_subnet.missing"},
				}}
				return inst, resources, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "EIP instance ref → true",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := rootInstanceBare(t)
				inst.values["associate_public_ip_address"] = false
				inst.values["ipv6_address_count"] = float64(0)
				eip := planResource{
					typ: "aws_eip", address: "aws_eip.bastion",
					values: map[string]any{"public_ip": "203.0.113.50", "allocation_id": "eipalloc-0aabbccddeeff0011"},
				}
				idx.resources[eip.address] = exprSet{refs: map[string][]string{
					"instance": {"aws_instance.bastion.id", "aws_instance.bastion"},
				}}
				return inst, append(resources, eip), idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "EIP association → true",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := rootInstanceBare(t)
				inst.values["associate_public_ip_address"] = false
				inst.values["ipv6_address_count"] = float64(0)
				assoc := planResource{
					typ: "aws_eip_association", address: "aws_eip_association.bastion",
					values: map[string]any{"allocation_id": "eipalloc-0aabbccddeeff0011"},
				}
				idx.resources[assoc.address] = exprSet{refs: map[string][]string{
					"instance_id": {"aws_instance.bastion.id", "aws_instance.bastion"},
				}}
				return inst, append(resources, assoc), idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "explicit false + IPv6 count 1 → omit",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := rootInstanceBare(t)
				inst.values["associate_public_ip_address"] = false
				inst.values["ipv6_address_count"] = float64(1)
				return inst, resources, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "subnet assign_ipv6 → omit",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := rootInstanceWithSubnet(t, false)
				inst.values["associate_public_ip_address"] = false
				for i := range resources {
					if resources[i].typ == "aws_subnet" {
						resources[i].values["assign_ipv6_address_on_creation"] = true
					}
				}
				return inst, resources, idx
			},
			wantVal: false, wantKnown: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst, resources, idx := tc.build()
			got, known := instancePublicIP(inst, resources, idx)
			if known != tc.wantKnown || (known && got != tc.wantVal) {
				t.Fatalf("public_ip=(%v,%v) want (%v,%v)", got, known, tc.wantVal, tc.wantKnown)
			}
		})
	}
}

func TestInstanceAdminPortsOpenTable(t *testing.T) {
	cases := []struct {
		name      string
		build     func() (planResource, []planResource, configIndex)
		wantVal   bool
		wantKnown bool
	}{
		{
			name: "world 22 → true",
			build: func() (planResource, []planResource, configIndex) {
				return instanceWithSGIngress(t, map[string]any{
					"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/0"},
				})
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "world 3389 → true",
			build: func() (planResource, []planResource, configIndex) {
				return instanceWithSGIngress(t, map[string]any{
					"from_port": float64(3389), "to_port": float64(3389), "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/0"},
				})
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "::/0 on 22 → true",
			build: func() (planResource, []planResource, configIndex) {
				return instanceWithSGIngress(t, map[string]any{
					"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
					"ipv6_cidr_blocks": []any{"::/0"},
				})
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "range 0–65535 → true",
			build: func() (planResource, []planResource, configIndex) {
				return instanceWithSGIngress(t, map[string]any{
					"from_port": float64(0), "to_port": float64(65535), "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/0"},
				})
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "protocol -1 → true",
			build: func() (planResource, []planResource, configIndex) {
				return instanceWithSGIngress(t, map[string]any{
					"from_port": float64(0), "to_port": float64(0), "protocol": "-1",
					"cidr_blocks": []any{"0.0.0.0/0"},
				})
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "udp 3389 world → false",
			build: func() (planResource, []planResource, configIndex) {
				return instanceWithSGIngress(t, map[string]any{
					"from_port": float64(3389), "to_port": float64(3389), "protocol": "udp",
					"cidr_blocks": []any{"0.0.0.0/0"},
				})
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "office /24 only → false",
			build: func() (planResource, []planResource, configIndex) {
				return instanceWithSGIngress(t, map[string]any{
					"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
					"cidr_blocks": []any{"203.0.113.0/24"},
				})
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "SG peer only → false",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := rootInstanceWithSG(t)
				resources[1].values = map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
						"security_groups": []any{"sg-office"},
					}},
				}
				peer := planResource{typ: "aws_security_group", address: "aws_security_group.office", values: map[string]any{}}
				return inst, append(resources, peer), idx
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "one world + one unknown → true",
			build: func() (planResource, []planResource, configIndex) {
				inst := planResource{
					typ: "aws_instance", address: "aws_instance.bastion",
					values: map[string]any{},
				}
				sgOpen := planResource{
					typ: "aws_security_group", address: "aws_security_group.open",
					values: map[string]any{
						"ingress": []any{map[string]any{
							"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
							"cidr_blocks": []any{"0.0.0.0/0"},
						}},
					},
				}
				sgUnk := planResource{
					typ: "aws_security_group", address: "aws_security_group.unk",
					values: map[string]any{
						"ingress": []any{map[string]any{
							"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
							"cidr_blocks": nil,
						}},
					},
					afterUnknown: map[string]any{
						"ingress": []any{map[string]any{"cidr_blocks": true}},
					},
				}
				idx := configIndex{
					resources: map[string]exprSet{
						inst.address: {refs: map[string][]string{
							"vpc_security_group_ids": {
								"aws_security_group.open.id", "aws_security_group.open",
								"aws_security_group.unk.id", "aws_security_group.unk",
							},
						}},
					},
					calls: map[string]exprSet{},
				}
				return inst, []planResource{inst, sgOpen, sgUnk}, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "one restricted + one unknown → omit",
			build: func() (planResource, []planResource, configIndex) {
				inst := planResource{
					typ: "aws_instance", address: "aws_instance.bastion",
					values: map[string]any{},
				}
				sgOK := planResource{
					typ: "aws_security_group", address: "aws_security_group.ok",
					values: map[string]any{
						"ingress": []any{map[string]any{
							"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
							"cidr_blocks": []any{"10.0.0.0/8"},
						}},
					},
				}
				sgUnk := planResource{
					typ: "aws_security_group", address: "aws_security_group.unk",
					values: map[string]any{
						"ingress": []any{map[string]any{
							"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
							"cidr_blocks": nil,
						}},
					},
					afterUnknown: map[string]any{
						"ingress": []any{map[string]any{"cidr_blocks": true}},
					},
				}
				idx := configIndex{
					resources: map[string]exprSet{
						inst.address: {refs: map[string][]string{
							"vpc_security_group_ids": {
								"aws_security_group.ok.id", "aws_security_group.ok",
								"aws_security_group.unk.id", "aws_security_group.unk",
							},
						}},
					},
					calls: map[string]exprSet{},
				}
				return inst, []planResource{inst, sgOK, sgUnk}, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "no SGs → omit",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := rootInstanceBare(t)
				return inst, resources, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "SG via module output → resolved",
			build: func() (planResource, []planResource, configIndex) {
				inst := planResource{
					typ: "aws_instance", address: "aws_instance.bastion",
					values: map[string]any{},
				}
				sg := planResource{
					typ: "aws_security_group", address: "module.sg.aws_security_group.this",
					values: map[string]any{
						"ingress": []any{map[string]any{
							"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
							"cidr_blocks": []any{"0.0.0.0/0"},
						}},
					},
				}
				idx := configIndex{
					resources: map[string]exprSet{
						inst.address: {refs: map[string][]string{
							"vpc_security_group_ids": {"module.sg.sg_id", "module.sg"},
						}},
					},
					calls: map[string]exprSet{},
					outputs: map[string]exprSet{
						"module.sg": {refs: map[string][]string{
							"sg_id": {"aws_security_group.this.id", "aws_security_group.this"},
						}},
					},
				}
				return inst, []planResource{inst, sg}, idx
			},
			wantVal: true, wantKnown: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst, resources, idx := tc.build()
			got, known := instanceAdminPortsOpen(inst, resources, idx)
			if known != tc.wantKnown || (known && got != tc.wantVal) {
				t.Fatalf("admin_ports_open=(%v,%v) want (%v,%v)", got, known, tc.wantVal, tc.wantKnown)
			}
		})
	}
}

func TestInstanceHasNoFlows(t *testing.T) {
	// Public ALB + ECS + RDS from the demo fixture, plus a reachable instance.
	plan, err := os.ReadFile("testdata/aws-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	plan = injectBastionInstance(t, plan)
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "", Source{
		Repo:     "example/aws-web-app",
		Commit:   "4530a865f29ba14931379f361b177a992edeab51",
		Tool:     "terraform",
		Fidelity: "plan",
	}, filepath.Join("..", "testdata", "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "aws_instance") {
			t.Fatalf("unexpected warning about instance: %s", w)
		}
	}
	inst := findKind(doc, "virtual_machine")
	if inst == nil {
		t.Fatal("missing virtual_machine element")
	}
	if inst.Attributes["public_ip"] != true || inst.Attributes["admin_ports_open"] != true {
		t.Fatalf("bastion attrs=%#v want public_ip=true admin_ports_open=true", inst.Attributes)
	}
	// Existing graph still has ALB / ECS / RDS.
	if findKind(doc, "load_balancer") == nil || findKind(doc, "container_service") == nil || findKind(doc, "relational_db") == nil {
		t.Fatal("demo elements missing after inject")
	}
	for _, f := range doc.Flows {
		if f.From == inst.ID || f.To == inst.ID {
			t.Fatalf("flow involves instance: from=%s to=%s", f.From, f.To)
		}
	}
	instKey := inst.canonicalKey()
	for _, b := range doc.TrustBoundaries {
		for _, id := range append(append([]string{}, b.Inside...), b.Outside...) {
			if id == inst.ID || id == instKey {
				t.Fatalf("boundary %s involves instance: inside=%v outside=%v", b.Kind, b.Inside, b.Outside)
			}
		}
	}
}

func injectBastionInstance(t *testing.T, plan []byte) []byte {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(plan, &root); err != nil {
		t.Fatal(err)
	}
	changes, _ := root["resource_changes"].([]any)
	changes = append(changes,
		map[string]any{
			"address": "aws_instance.bastion", "mode": "managed", "type": "aws_instance",
			"change": map[string]any{"after": map[string]any{
				"associate_public_ip_address": true,
				"ipv6_address_count":          float64(0),
			}},
		},
		map[string]any{
			"address": "aws_security_group.bastion", "mode": "managed", "type": "aws_security_group",
			"change": map[string]any{"after": map[string]any{
				"ingress": []any{map[string]any{
					"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/0"}, "ipv6_cidr_blocks": []any{},
					"prefix_list_ids": []any{}, "security_groups": []any{}, "self": false,
				}},
			}},
		},
	)
	root["resource_changes"] = changes

	cfg, _ := root["configuration"].(map[string]any)
	rm, _ := cfg["root_module"].(map[string]any)
	resources, _ := rm["resources"].([]any)
	resources = append(resources,
		map[string]any{
			"address": "aws_instance.bastion", "type": "aws_instance", "name": "bastion", "mode": "managed",
			"expressions": map[string]any{
				"vpc_security_group_ids": map[string]any{
					"references": []any{"aws_security_group.bastion.id", "aws_security_group.bastion"},
				},
			},
		},
		map[string]any{
			"address": "aws_security_group.bastion", "type": "aws_security_group", "name": "bastion", "mode": "managed",
			"expressions": map[string]any{},
		},
	)
	rm["resources"] = resources
	cfg["root_module"] = rm
	root["configuration"] = cfg

	out, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestInstanceFR034ShapedDFD(t *testing.T) {
	cases := []struct {
		name         string
		publicSubnet bool
		wantPublic   bool
		wantAdmin    bool
	}{
		{name: "public + open → both true", publicSubnet: true, wantPublic: true, wantAdmin: true},
		{name: "private + open → public false admin true", publicSubnet: false, wantPublic: false, wantAdmin: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := instancePlanJSON(t, tc.publicSubnet, true)
			doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml", Source{
				Repo: "probe/ec2", Commit: "abcdef1234567", Tool: "terraform", Fidelity: "plan",
			}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range warnings {
				if strings.Contains(w, "no mapping for") && strings.Contains(w, "aws_instance") {
					t.Fatalf("unexpected warning: %s", w)
				}
			}
			el := findKind(doc, "virtual_machine")
			if el == nil {
				t.Fatal("missing virtual_machine element")
			}
			if el.Type != "process" || el.Provenance != "iac" {
				t.Fatalf("element meta: type=%s provenance=%s", el.Type, el.Provenance)
			}
			if got := el.Attributes["public_ip"]; got != tc.wantPublic {
				t.Fatalf("public_ip=%v want %v (attrs=%#v)", got, tc.wantPublic, el.Attributes)
			}
			if got := el.Attributes["admin_ports_open"]; got != tc.wantAdmin {
				t.Fatalf("admin_ports_open=%v want %v (attrs=%#v)", got, tc.wantAdmin, el.Attributes)
			}
			for _, f := range doc.Flows {
				if f.From == el.ID || f.To == el.ID {
					t.Fatalf("unexpected flow involving instance: %+v", f)
				}
			}
		})
	}
}

func TestInstanceNoLeakInDFDAndScanRequest(t *testing.T) {
	plan := instanceNoLeakPlanJSON(t)
	cfg := []byte("schema_version: fray-config/v1\n")
	src := Source{Repo: "probe/ec2", Commit: "abcdef1234567", Tool: "terraform", Fidelity: "plan"}
	doc, _, err := Parse(plan, cfg, "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	assertInstanceNoLeak(t, raw)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	for _, redact := range []bool{true, false} {
		t.Run(map[bool]string{true: "redaction_on", false: "redaction_off"}[redact], func(t *testing.T) {
			wire := doc
			repo := doc.Source.Repo
			if redact {
				var idMap IDMap
				var err error
				wire, idMap, err = Redact(doc, key)
				if err != nil {
					t.Fatal(err)
				}
				repo = wire.Source.Repo
				_ = idMap
			}
			rawDFD, err := Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(apiv1.ScanRequest{
				DFD: rawDFD, Repo: repo, Commit: "abcdef1234567", IsDefaultBranch: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			assertInstanceNoLeak(t, body)
		})
	}
}

func TestAWSWebAppPlanUnchangedWithInstances(t *testing.T) {
	// Regression: demo fixture has no aws_instance; golden must stay byte-identical.
	plan, err := os.ReadFile("testdata/aws-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "", Source{
		Repo:     "example/aws-web-app",
		Commit:   "4530a865f29ba14931379f361b177a992edeab51",
		Tool:     "terraform",
		Fidelity: "plan",
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

// --- builders ---

func rootInstanceBare(t *testing.T) (planResource, []planResource, configIndex) {
	t.Helper()
	inst := planResource{
		typ: "aws_instance", address: "aws_instance.bastion",
		values: map[string]any{},
	}
	idx := configIndex{
		resources: map[string]exprSet{},
		calls:     map[string]exprSet{},
	}
	return inst, []planResource{inst}, idx
}

func rootInstanceWithSubnet(t *testing.T, mapPublic bool) (planResource, []planResource, configIndex) {
	t.Helper()
	inst, resources, idx := rootInstanceBare(t)
	subnet := planResource{
		typ: "aws_subnet", address: "aws_subnet.public",
		values: map[string]any{
			"map_public_ip_on_launch": mapPublic,
			"id":                      "subnet-0aabbccddeeff0011",
		},
	}
	idx.resources[inst.address] = exprSet{refs: map[string][]string{
		"subnet_id": {"aws_subnet.public.id", "aws_subnet.public"},
	}}
	return inst, append(resources, subnet), idx
}

func rootInstanceWithSG(t *testing.T) (planResource, []planResource, configIndex) {
	t.Helper()
	inst, resources, idx := rootInstanceBare(t)
	sg := planResource{
		typ: "aws_security_group", address: "aws_security_group.bastion",
		values: map[string]any{"ingress": []any{}},
	}
	idx.resources[inst.address] = exprSet{refs: map[string][]string{
		"vpc_security_group_ids": {"aws_security_group.bastion.id", "aws_security_group.bastion"},
	}}
	return inst, append(resources, sg), idx
}

func instanceWithSGIngress(t *testing.T, ingress map[string]any) (planResource, []planResource, configIndex) {
	t.Helper()
	inst, resources, idx := rootInstanceWithSG(t)
	resources[1].values = map[string]any{"ingress": []any{ingress}}
	return inst, resources, idx
}

func instancePlanJSON(t *testing.T, mapPublic, worldSSH bool) []byte {
	t.Helper()
	cidr := "10.0.0.0/8"
	if worldSSH {
		cidr = "0.0.0.0/0"
	}
	root := map[string]any{
		"resource_changes": []any{
			map[string]any{
				"address": "aws_instance.bastion", "mode": "managed", "type": "aws_instance",
				"change": map[string]any{"after": map[string]any{
					"ipv6_address_count": float64(0),
				}},
			},
			map[string]any{
				"address": "aws_subnet.public", "mode": "managed", "type": "aws_subnet",
				"change": map[string]any{"after": map[string]any{
					"map_public_ip_on_launch": mapPublic,
				}},
			},
			map[string]any{
				"address": "aws_security_group.bastion", "mode": "managed", "type": "aws_security_group",
				"change": map[string]any{"after": map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
						"cidr_blocks": []any{cidr}, "ipv6_cidr_blocks": []any{}, "prefix_list_ids": []any{},
						"security_groups": []any{}, "self": false,
					}},
				}},
			},
		},
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{
						"address": "aws_instance.bastion", "type": "aws_instance", "name": "bastion",
						"expressions": map[string]any{
							"subnet_id": map[string]any{
								"references": []any{"aws_subnet.public.id", "aws_subnet.public"},
							},
							"vpc_security_group_ids": map[string]any{
								"references": []any{"aws_security_group.bastion.id", "aws_security_group.bastion"},
							},
						},
					},
					map[string]any{
						"address": "aws_subnet.public", "type": "aws_subnet", "name": "public",
						"expressions": map[string]any{},
					},
					map[string]any{
						"address": "aws_security_group.bastion", "type": "aws_security_group", "name": "bastion",
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

func instanceNoLeakPlanJSON(t *testing.T) []byte {
	t.Helper()
	root := map[string]any{
		"resource_changes": []any{
			map[string]any{
				"address": "aws_instance.bastion", "mode": "managed", "type": "aws_instance",
				"change": map[string]any{"after": map[string]any{
					"associate_public_ip_address": true,
					"ipv6_address_count":          float64(0),
					"id":                          "i-0aabbccddeeff0011",
				}},
			},
			map[string]any{
				"address": "aws_subnet.public", "mode": "managed", "type": "aws_subnet",
				"change": map[string]any{"after": map[string]any{
					"map_public_ip_on_launch": true,
					"id":                      "subnet-0leakysubnet0011",
				}},
			},
			map[string]any{
				"address": "aws_security_group.bastion", "mode": "managed", "type": "aws_security_group",
				"change": map[string]any{"after": map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
						"cidr_blocks": []any{"198.51.100.0/24", "0.0.0.0/0"},
						"ipv6_cidr_blocks": []any{}, "prefix_list_ids": []any{},
						"security_groups": []any{}, "self": false,
					}},
				}},
			},
			map[string]any{
				"address": "aws_eip.bastion", "mode": "managed", "type": "aws_eip",
				"change": map[string]any{"after": map[string]any{
					"public_ip":     "203.0.113.77",
					"allocation_id": "eipalloc-0leakyalloc0011",
				}},
			},
		},
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": []any{
					map[string]any{
						"address": "aws_instance.bastion", "type": "aws_instance", "name": "bastion",
						"expressions": map[string]any{
							"subnet_id": map[string]any{
								"references": []any{"aws_subnet.public.id", "aws_subnet.public"},
							},
							"vpc_security_group_ids": map[string]any{
								"references": []any{"aws_security_group.bastion.id", "aws_security_group.bastion"},
							},
						},
					},
					map[string]any{
						"address": "aws_subnet.public", "type": "aws_subnet", "name": "public",
						"expressions": map[string]any{},
					},
					map[string]any{
						"address": "aws_security_group.bastion", "type": "aws_security_group", "name": "bastion",
						"expressions": map[string]any{},
					},
					map[string]any{
						"address": "aws_eip.bastion", "type": "aws_eip", "name": "bastion",
						"expressions": map[string]any{
							"instance": map[string]any{
								"references": []any{"aws_instance.bastion.id", "aws_instance.bastion"},
							},
						},
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

var instanceLeakNeedles = []string{
	"198.51.100.0/24",
	"203.0.113.77",
	"eipalloc-0leakyalloc0011",
	"subnet-0leakysubnet0011",
	"i-0aabbccddeeff0011",
}

func assertInstanceNoLeak(t *testing.T, body []byte) {
	t.Helper()
	for _, n := range instanceLeakNeedles {
		if bytes.Contains(body, []byte(n)) {
			t.Errorf("FAIL: leak needle %q PRESENT", n)
		}
	}
}
