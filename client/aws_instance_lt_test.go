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

func TestInstanceLaunchTemplateMerge(t *testing.T) {
	cases := []struct {
		name         string
		build        func() (planResource, []planResource, configIndex)
		wantPublic   bool
		wantPublicOK bool
		wantAdmin    bool
		wantAdminOK  bool
		checkPublic  bool
		checkAdmin   bool
	}{
		{
			name: "template public IP + world SSH on private subnet → both true",
			build: func() (planResource, []planResource, configIndex) {
				return ltFixture(t, ltOpts{
					version:             "$Latest",
					tmplAssociatePublic: boolPtr(true),
					subnetMapPublic:     false,
					tmplWorldSSH:        true,
					tmplActions:         []string{"no-op"},
				})
			},
			checkPublic: true, wantPublic: true, wantPublicOK: true,
			checkAdmin: true, wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "instance overrides template associate false + own SGs",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := ltFixture(t, ltOpts{
					version:             "$Latest",
					tmplAssociatePublic: boolPtr(true),
					subnetMapPublic:     false,
					tmplWorldSSH:        true,
					tmplActions:         []string{"no-op"},
				})
				inst.values["associate_public_ip_address"] = false
				inst.values["ipv6_address_count"] = float64(0)
				// Own closed SG wins over template world SSH.
				own := planResource{
					typ: "aws_security_group", address: "aws_security_group.own",
					values: map[string]any{"ingress": []any{map[string]any{
						"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
						"cidr_blocks": []any{"10.0.0.0/8"},
					}}},
				}
				set := idx.resources[inst.address]
				if set.refs == nil {
					set.refs = map[string][]string{}
				}
				set.refs["vpc_security_group_ids"] = []string{"aws_security_group.own.id", "aws_security_group.own"}
				idx.resources[inst.address] = set
				return inst, append(resources, own), idx
			},
			checkPublic: true, wantPublic: false, wantPublicOK: true,
			checkAdmin: true, wantAdmin: false, wantAdminOK: true,
		},
		{
			name: "$Latest used",
			build: func() (planResource, []planResource, configIndex) {
				return ltFixture(t, ltOpts{
					version:             "$Latest",
					tmplAssociatePublic: boolPtr(true),
					subnetMapPublic:     false,
					tmplWorldSSH:        true,
					tmplActions:         []string{"update"},
				})
			},
			checkPublic: true, wantPublic: true, wantPublicOK: true,
			checkAdmin: true, wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "$Default with update_default_version=true used",
			build: func() (planResource, []planResource, configIndex) {
				return ltFixture(t, ltOpts{
					version:              "$Default",
					updateDefaultVersion: boolPtr(true),
					tmplAssociatePublic:  boolPtr(true),
					subnetMapPublic:      false,
					tmplWorldSSH:         true,
					tmplActions:          []string{"update"},
				})
			},
			checkPublic: true, wantPublic: true, wantPublicOK: true,
			checkAdmin: true, wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "$Default without update_default_version on updated template → omit",
			build: func() (planResource, []planResource, configIndex) {
				return ltFixture(t, ltOpts{
					version:             "$Default",
					tmplAssociatePublic: boolPtr(true),
					subnetMapPublic:     false,
					tmplWorldSSH:        true,
					tmplActions:         []string{"update"},
				})
			},
			checkPublic: true, wantPublic: false, wantPublicOK: false,
			checkAdmin: true, wantAdmin: false, wantAdminOK: false,
		},
		{
			name: "omitted version on template created in plan → used",
			build: func() (planResource, []planResource, configIndex) {
				return ltFixture(t, ltOpts{
					omitVersion:         true,
					tmplAssociatePublic: boolPtr(true),
					subnetMapPublic:     false,
					tmplWorldSSH:        true,
					tmplActions:         []string{"create"},
				})
			},
			checkPublic: true, wantPublic: true, wantPublicOK: true,
			checkAdmin: true, wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "pinned version → omit",
			build: func() (planResource, []planResource, configIndex) {
				return ltFixture(t, ltOpts{
					version:             "2",
					tmplAssociatePublic: boolPtr(true),
					subnetMapPublic:     false,
					tmplWorldSSH:        true,
					tmplActions:         []string{"create"},
				})
			},
			checkPublic: true, wantPublic: false, wantPublicOK: false,
			checkAdmin: true, wantAdmin: false, wantAdminOK: false,
		},
		{
			name: "template not in plan → omit",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := rootInstanceWithSubnet(t, false)
				inst.values["ipv6_address_count"] = float64(0)
				set := idx.resources[inst.address]
				if set.refs == nil {
					set.refs = map[string][]string{}
				}
				if set.raw == nil {
					set.raw = map[string]any{}
				}
				set.refs["launch_template"] = []string{"aws_launch_template.missing.id", "aws_launch_template.missing"}
				set.raw["launch_template"] = []any{map[string]any{
					"id": map[string]any{
						"references": []any{"aws_launch_template.missing.id", "aws_launch_template.missing"},
					},
					"version": map[string]any{"constant_value": "$Latest"},
				}}
				idx.resources[inst.address] = set
				return inst, resources, idx
			},
			checkPublic: true, wantPublic: false, wantPublicOK: false,
			checkAdmin: true, wantAdmin: false, wantAdminOK: false,
		},
		{
			name: "template NI associate conflict → omit public_ip",
			build: func() (planResource, []planResource, configIndex) {
				inst, resources, idx := ltFixture(t, ltOpts{
					version:         "$Latest",
					subnetMapPublic: false,
					tmplWorldSSH:    true,
					tmplActions:     []string{"no-op"},
					niConflict:      true,
				})
				return inst, resources, idx
			},
			checkPublic: true, wantPublic: false, wantPublicOK: false,
			checkAdmin: true, wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "module template",
			build: func() (planResource, []planResource, configIndex) {
				return ltModuleFixture(t)
			},
			checkPublic: true, wantPublic: true, wantPublicOK: true,
			checkAdmin: true, wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "latest_version reference used",
			build: func() (planResource, []planResource, configIndex) {
				return ltFixture(t, ltOpts{
					versionRef:          "latest_version",
					tmplAssociatePublic: boolPtr(true),
					subnetMapPublic:     false,
					tmplWorldSSH:        true,
					tmplActions:         []string{"update"},
				})
			},
			checkPublic: true, wantPublic: true, wantPublicOK: true,
			checkAdmin: true, wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "default_version ref without update_default_version on update → omit",
			build: func() (planResource, []planResource, configIndex) {
				return ltFixture(t, ltOpts{
					versionRef:          "default_version",
					tmplAssociatePublic: boolPtr(true),
					subnetMapPublic:     false,
					tmplWorldSSH:        true,
					tmplActions:         []string{"update"},
				})
			},
			checkPublic: true, wantPublic: false, wantPublicOK: false,
			checkAdmin: true, wantAdmin: false, wantAdminOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst, resources, idx := tc.build()
			if tc.checkPublic {
				got, known := instancePublicIP(inst, resources, nil, idx)
				if known != tc.wantPublicOK || (known && got != tc.wantPublic) {
					t.Fatalf("public_ip=(%v,%v) want (%v,%v)", got, known, tc.wantPublic, tc.wantPublicOK)
				}
			}
			if tc.checkAdmin {
				got, known := instanceAdminPortsOpen(inst, resources, nil, idx)
				if known != tc.wantAdminOK || (known && got != tc.wantAdmin) {
					t.Fatalf("admin_ports_open=(%v,%v) want (%v,%v)", got, known, tc.wantAdmin, tc.wantAdminOK)
				}
			}
		})
	}
}

func TestInstanceLaunchTemplateNoLeak(t *testing.T) {
	plan := instanceLTNoLeakPlanJSON(t)
	cfg := []byte("schema_version: fray-config/v1\n")
	src := Source{Repo: "probe/ec2-lt", Commit: "abcdef1234567", Tool: "terraform", Fidelity: "plan"}
	doc, _, err := Parse(plan, cfg, "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	assertInstanceLTNoLeak(t, raw)

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
			assertInstanceLTNoLeak(t, body)
		})
	}
}

func TestInstanceLaunchTemplateIgnoredType(t *testing.T) {
	plan := instanceLTNoLeakPlanJSON(t)
	doc, warnings, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "fray.yaml", Source{
		Repo: "probe/ec2-lt", Commit: "abcdef1234567", Tool: "terraform", Fidelity: "plan",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "aws_launch_template") {
			t.Fatalf("launch template must be ignored, got warning: %s", w)
		}
	}
	for _, el := range doc.Elements {
		for _, addr := range el.Evidence.Addresses {
			if strings.Contains(addr, "aws_launch_template") {
				t.Fatalf("launch template leaked into element evidence: %s", addr)
			}
		}
	}
}

func TestAWSWebAppPlanUnchangedWithLaunchTemplate(t *testing.T) {
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

// --- launch template fixtures ---

type ltOpts struct {
	version              string
	versionRef           string // "latest_version" or "default_version"
	omitVersion          bool
	updateDefaultVersion *bool
	tmplAssociatePublic  *bool
	subnetMapPublic      bool
	tmplWorldSSH         bool
	tmplActions          []string
	niConflict           bool
	useName              bool
}

func ltFixture(t *testing.T, o ltOpts) (planResource, []planResource, configIndex) {
	t.Helper()
	inst := planResource{
		typ: "aws_instance", address: "aws_instance.bastion",
		values: map[string]any{
			"ipv6_address_count": float64(0),
			"launch_template": []any{map[string]any{
				"id": "lt-0tmpldistinct0011",
			}},
		},
	}
	if !o.omitVersion && o.versionRef == "" {
		asList(inst.values["launch_template"])[0].(map[string]any)["version"] = o.version
	}

	subnet := planResource{
		typ: "aws_subnet", address: "aws_subnet.private",
		values: map[string]any{
			"map_public_ip_on_launch": o.subnetMapPublic,
			"id":                      "subnet-0privatedist0011",
		},
	}
	sg := planResource{
		typ: "aws_security_group", address: "aws_security_group.lt_ssh",
		values: map[string]any{"ingress": []any{}},
	}
	if o.tmplWorldSSH {
		sg.values["ingress"] = []any{map[string]any{
			"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
			"cidr_blocks": []any{"0.0.0.0/0"},
		}}
	}

	nis := []any{}
	if o.niConflict {
		nis = []any{
			map[string]any{"associate_public_ip_address": true},
			map[string]any{"associate_public_ip_address": false},
		}
	} else if o.tmplAssociatePublic != nil {
		nis = []any{map[string]any{
			"associate_public_ip_address": *o.tmplAssociatePublic,
			"subnet_id":                   "subnet-0privatedist0011",
			"security_groups":             []any{"sg-0ltworldssh0011"},
		}}
	}

	tmplVals := map[string]any{
		"id":                 "lt-0tmpldistinct0011",
		"name":               "fray-lt-distinct-name",
		"network_interfaces": nis,
	}
	if o.updateDefaultVersion != nil {
		tmplVals["update_default_version"] = *o.updateDefaultVersion
	}
	tmpl := planResource{
		typ: "aws_launch_template", address: "aws_launch_template.app",
		values:  tmplVals,
		actions: o.tmplActions,
	}

	idx := configIndex{
		resources: map[string]exprSet{},
		calls:     map[string]exprSet{},
	}

	ltBlock := map[string]any{}
	ltRefs := []string{}
	if o.useName {
		ltBlock["name"] = map[string]any{
			"references": []any{"aws_launch_template.app.name", "aws_launch_template.app"},
		}
		ltRefs = append(ltRefs, "aws_launch_template.app.name", "aws_launch_template.app")
	} else {
		ltBlock["id"] = map[string]any{
			"references": []any{"aws_launch_template.app.id", "aws_launch_template.app"},
		}
		ltRefs = append(ltRefs, "aws_launch_template.app.id", "aws_launch_template.app")
	}
	if o.omitVersion {
		// version key absent
	} else if o.versionRef != "" {
		attr := "aws_launch_template.app." + o.versionRef
		ltBlock["version"] = map[string]any{
			"references": []any{attr, "aws_launch_template.app"},
		}
		ltRefs = append(ltRefs, attr, "aws_launch_template.app")
	} else {
		ltBlock["version"] = map[string]any{"constant_value": o.version}
	}

	idx.resources[inst.address] = exprSet{
		refs: map[string][]string{
			"subnet_id":       {"aws_subnet.private.id", "aws_subnet.private"},
			"launch_template": ltRefs,
		},
		raw: map[string]any{
			"subnet_id": map[string]any{
				"references": []any{"aws_subnet.private.id", "aws_subnet.private"},
			},
			"launch_template": []any{ltBlock},
		},
	}
	idx.resources[tmpl.address] = exprSet{
		refs: map[string][]string{
			"network_interfaces": {
				"aws_subnet.private.id", "aws_subnet.private",
				"aws_security_group.lt_ssh.id", "aws_security_group.lt_ssh",
			},
		},
		raw: map[string]any{
			"network_interfaces": []any{map[string]any{
				"subnet_id": map[string]any{
					"references": []any{"aws_subnet.private.id", "aws_subnet.private"},
				},
				"security_groups": map[string]any{
					"references": []any{"aws_security_group.lt_ssh.id", "aws_security_group.lt_ssh"},
				},
			}},
		},
	}
	idx.resources[subnet.address] = exprSet{}
	idx.resources[sg.address] = exprSet{}

	return inst, []planResource{inst, subnet, sg, tmpl}, idx
}

func ltModuleFixture(t *testing.T) (planResource, []planResource, configIndex) {
	t.Helper()
	inst := planResource{
		typ: "aws_instance", address: "aws_instance.bastion",
		values: map[string]any{
			"ipv6_address_count": float64(0),
			"launch_template": []any{map[string]any{
				"id":      "lt-0moduletmpl0011",
				"version": "$Latest",
			}},
		},
	}
	subnet := planResource{
		typ: "aws_subnet", address: "aws_subnet.private",
		values: map[string]any{"map_public_ip_on_launch": false, "id": "subnet-0modpriv0011"},
	}
	sg := planResource{
		typ: "aws_security_group", address: "module.web.aws_security_group.lt_ssh",
		values: map[string]any{"ingress": []any{map[string]any{
			"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
			"cidr_blocks": []any{"0.0.0.0/0"},
		}}},
	}
	tmpl := planResource{
		typ: "aws_launch_template", address: "module.web.aws_launch_template.app",
		values: map[string]any{
			"id": "lt-0moduletmpl0011",
			"network_interfaces": []any{map[string]any{
				"associate_public_ip_address": true,
			}},
		},
		actions: []string{"no-op"},
	}
	idx := configIndex{
		resources: map[string]exprSet{},
		calls:     map[string]exprSet{},
	}
	idx.resources[inst.address] = exprSet{
		refs: map[string][]string{
			"subnet_id": {"aws_subnet.private.id", "aws_subnet.private"},
			"launch_template": {
				"module.web.aws_launch_template.app.id",
				"module.web.aws_launch_template.app",
			},
		},
		raw: map[string]any{
			"launch_template": []any{map[string]any{
				"id": map[string]any{"references": []any{
					"module.web.aws_launch_template.app.id",
					"module.web.aws_launch_template.app",
				}},
				"version": map[string]any{"constant_value": "$Latest"},
			}},
		},
	}
	idx.resources[tmpl.address] = exprSet{
		refs: map[string][]string{
			"network_interfaces": {
				"module.web.aws_security_group.lt_ssh.id",
				"module.web.aws_security_group.lt_ssh",
			},
		},
		raw: map[string]any{
			"network_interfaces": []any{map[string]any{
				"security_groups": map[string]any{"references": []any{
					"module.web.aws_security_group.lt_ssh.id",
					"module.web.aws_security_group.lt_ssh",
				}},
			}},
		},
	}
	idx.resources[subnet.address] = exprSet{}
	idx.resources[sg.address] = exprSet{}
	return inst, []planResource{inst, subnet, sg, tmpl}, idx
}

func instanceLTNoLeakPlanJSON(t *testing.T) []byte {
	t.Helper()
	root := map[string]any{
		"resource_changes": []any{
			map[string]any{
				"address": "aws_instance.bastion", "mode": "managed", "type": "aws_instance",
				"change": map[string]any{
					"actions": []any{"create"},
					"after": map[string]any{
						"ipv6_address_count": float64(0),
						"id":                 "i-0ltleakinst0011",
						"launch_template": []any{map[string]any{
							"id":      "lt-0leakytmpl0011",
							"version": "$Latest",
						}},
					},
				},
			},
			map[string]any{
				"address": "aws_launch_template.app", "mode": "managed", "type": "aws_launch_template",
				"change": map[string]any{
					"actions": []any{"create"},
					"after": map[string]any{
						"id":   "lt-0leakytmpl0011",
						"name": "fray-lt-leak-name-zz9",
						"network_interfaces": []any{map[string]any{
							"associate_public_ip_address": true,
							"security_groups":             []any{"sg-0leakysg0011"},
						}},
					},
				},
			},
			map[string]any{
				"address": "aws_subnet.private", "mode": "managed", "type": "aws_subnet",
				"change": map[string]any{"after": map[string]any{
					"map_public_ip_on_launch": false,
					"id":                      "subnet-0ltleaksub0011",
				}},
			},
			map[string]any{
				"address": "aws_security_group.lt_ssh", "mode": "managed", "type": "aws_security_group",
				"change": map[string]any{"after": map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
						"cidr_blocks":      []any{"203.0.113.0/24", "0.0.0.0/0"},
						"ipv6_cidr_blocks": []any{},
						"prefix_list_ids":  []any{},
						"security_groups":  []any{},
						"self":             false,
					}},
					"id": "sg-0leakysg0011",
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
								"references": []any{"aws_subnet.private.id", "aws_subnet.private"},
							},
							"launch_template": []any{map[string]any{
								"id": map[string]any{
									"references": []any{"aws_launch_template.app.id", "aws_launch_template.app"},
								},
								"version": map[string]any{"constant_value": "$Latest"},
							}},
						},
					},
					map[string]any{
						"address": "aws_launch_template.app", "type": "aws_launch_template", "name": "app",
						"expressions": map[string]any{
							"name": map[string]any{"constant_value": "fray-lt-leak-name-zz9"},
							"network_interfaces": []any{map[string]any{
								"associate_public_ip_address": map[string]any{"constant_value": true},
								"security_groups": map[string]any{
									"references": []any{"aws_security_group.lt_ssh.id", "aws_security_group.lt_ssh"},
								},
							}},
						},
					},
					map[string]any{
						"address": "aws_subnet.private", "type": "aws_subnet", "name": "private",
						"expressions": map[string]any{},
					},
					map[string]any{
						"address": "aws_security_group.lt_ssh", "type": "aws_security_group", "name": "lt_ssh",
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

var instanceLTLeakNeedles = []string{
	"lt-0leakytmpl0011",
	"fray-lt-leak-name-zz9",
	"203.0.113.0/24",
	"sg-0leakysg0011",
	"subnet-0ltleaksub0011",
	"i-0ltleakinst0011",
}

func assertInstanceLTNoLeak(t *testing.T, body []byte) {
	t.Helper()
	for _, n := range instanceLTLeakNeedles {
		if bytes.Contains(body, []byte(n)) {
			t.Errorf("FAIL: leak needle %q PRESENT", n)
		}
	}
}
