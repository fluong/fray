package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyCIDR(t *testing.T) {
	cases := []struct {
		cidr string
		want networkSourceClass
	}{
		{"0.0.0.0/0", netSrcWorld},
		{"::/0", netSrcWorld},
		{"0.0.0.0/1", netSrcWorld},
		{"128.0.0.0/1", netSrcWorld},
		{"8.0.0.0/8", netSrcWorld},
		{"10.0.0.0/8", netSrcRestricted},
		{"172.16.0.0/12", netSrcRestricted},
		{"192.168.1.0/24", netSrcRestricted},
		{"100.64.0.0/10", netSrcRestricted},
		{"fc00::/7", netSrcRestricted},
		{"203.0.113.5/32", netSrcRestricted}, // public office /32
		{"8.8.8.0/24", netSrcRestricted},     // public /24 ≥ /16
		{"not-a-cidr", netSrcUnknown},
	}
	for _, tc := range cases {
		if got := classifyCIDR(tc.cidr); got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.cidr, got, tc.want)
		}
	}
}

func TestDBNetworkRestrictedTable(t *testing.T) {
	cases := []struct {
		name      string
		build     func() (planResource, []planResource, configIndex)
		wantVal   bool
		wantKnown bool
	}{
		{
			name: "inline SG peer (demo shape)",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "module.db.aws_db_instance.this[0]",
					values: map[string]any{"identifier": "app", "engine": "postgres", "port": float64(5432)},
				}
				sg := planResource{
					typ: "aws_security_group", address: "aws_security_group.db",
					values: map[string]any{
						"ingress": []any{map[string]any{
							"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
							"cidr_blocks": []any{}, "ipv6_cidr_blocks": []any{}, "prefix_list_ids": []any{},
						}},
					},
				}
				idx := configIndex{
					resources: map[string]exprSet{},
					calls: map[string]exprSet{
						"module.db": {refs: map[string][]string{
							"vpc_security_group_ids": {"aws_security_group.db.id", "aws_security_group.db"},
						}},
					},
				}
				idx.resources["aws_security_group.db"] = exprSet{refs: map[string][]string{
					"ingress": {"aws_security_group.tasks.id", "aws_security_group.tasks"},
				}}
				return db, []planResource{db, sg}, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "inline world 0.0.0.0/0 on DB port",
			build: func() (planResource, []planResource, configIndex) {
				return rootDBWithInlineSG(t, map[string]any{
					"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/0"},
				}, nil)
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "vpc_security_group_ingress_rule world",
			build: func() (planResource, []planResource, configIndex) {
				db, resources, idx := rootDBBare(t)
				rule := planResource{
					typ: "aws_vpc_security_group_ingress_rule", address: "aws_vpc_security_group_ingress_rule.open",
					values: map[string]any{
						"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
						"cidr_ipv4": "0.0.0.0/0",
					},
				}
				idx.resources[rule.address] = exprSet{refs: map[string][]string{
					"security_group_id": {"aws_security_group.db.id", "aws_security_group.db"},
				}}
				return db, append(resources, rule), idx
			},
			wantVal: false, wantKnown: true,
		},
		{
			// Module for_each plans set unused optional source fields to null while
			// still listing each.value.* refs. Before f1e2ed1 those nulls poisoned
			// classification to unknown (absent); after → world → restricted=false.
			name: "vpc rule null optionals + ip_protocol world",
			build: func() (planResource, []planResource, configIndex) {
				db, resources, idx := rootDBBare(t)
				rule := planResource{
					typ: "aws_vpc_security_group_ingress_rule", address: "aws_vpc_security_group_ingress_rule.open",
					values: map[string]any{
						"from_port": float64(5432), "to_port": float64(5432), "ip_protocol": "tcp",
						"cidr_ipv4": "0.0.0.0/0", "cidr_ipv6": nil,
						"prefix_list_id": nil, "referenced_security_group_id": nil,
						"security_group_id": nil,
					},
				}
				idx.resources[rule.address] = exprSet{refs: map[string][]string{
					"security_group_id":            {"aws_security_group.db.id", "aws_security_group.db"},
					"cidr_ipv4":                    {"each.value.cidr_ipv4", "each.value"},
					"cidr_ipv6":                    {"each.value.cidr_ipv6", "each.value"},
					"prefix_list_id":               {"each.value.prefix_list_id", "each.value"},
					"referenced_security_group_id": {"each.value.referenced_security_group_id", "each.value"},
				}}
				return db, append(resources, rule), idx
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "vpc rule cidr null + peer SG unknown-after-apply → absent",
			build: func() (planResource, []planResource, configIndex) {
				db, resources, idx := rootDBBare(t)
				rule := planResource{
					typ: "aws_vpc_security_group_ingress_rule", address: "aws_vpc_security_group_ingress_rule.peer",
					values: map[string]any{
						"from_port": float64(5432), "to_port": float64(5432), "ip_protocol": "tcp",
						"cidr_ipv4": nil, "referenced_security_group_id": nil,
					},
				}
				idx.resources[rule.address] = exprSet{refs: map[string][]string{
					"security_group_id":            {"aws_security_group.db.id", "aws_security_group.db"},
					"referenced_security_group_id": {"aws_security_group.tasks.id", "aws_security_group.tasks"},
				}}
				return db, append(resources, rule), idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "vpc rule cidr null + prefix_list_id unknown-after-apply → absent",
			build: func() (planResource, []planResource, configIndex) {
				db, resources, idx := rootDBBare(t)
				pl := planResource{
					typ: "aws_ec2_managed_prefix_list", address: "aws_ec2_managed_prefix_list.priv",
					values: map[string]any{
						"id":    "pl-priv",
						"entry": []any{map[string]any{"cidr": "10.0.0.0/8"}},
					},
				}
				rule := planResource{
					typ: "aws_vpc_security_group_ingress_rule", address: "aws_vpc_security_group_ingress_rule.pl",
					values: map[string]any{
						"from_port": float64(5432), "to_port": float64(5432), "ip_protocol": "tcp",
						"cidr_ipv4": nil, "prefix_list_id": nil,
					},
				}
				idx.resources[rule.address] = exprSet{refs: map[string][]string{
					"security_group_id": {"aws_security_group.db.id", "aws_security_group.db"},
					"prefix_list_id":    {"aws_ec2_managed_prefix_list.priv.id", "aws_ec2_managed_prefix_list.priv"},
				}}
				return db, append(resources, rule, pl), idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "vpc rule all sources null → absent (degenerate)",
			build: func() (planResource, []planResource, configIndex) {
				db, resources, idx := rootDBBare(t)
				rule := planResource{
					typ: "aws_vpc_security_group_ingress_rule", address: "aws_vpc_security_group_ingress_rule.empty",
					values: map[string]any{
						"from_port": float64(5432), "to_port": float64(5432), "ip_protocol": "tcp",
						"cidr_ipv4": nil, "cidr_ipv6": nil,
						"prefix_list_id": nil, "referenced_security_group_id": nil,
					},
				}
				idx.resources[rule.address] = exprSet{refs: map[string][]string{
					"security_group_id":            {"aws_security_group.db.id", "aws_security_group.db"},
					"cidr_ipv4":                    {"each.value.cidr_ipv4", "each.value"},
					"referenced_security_group_id": {"each.value.referenced_security_group_id", "each.value"},
					"prefix_list_id":               {"each.value.prefix_list_id", "each.value"},
				}}
				return db, append(resources, rule), idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "::/0 world",
			build: func() (planResource, []planResource, configIndex) {
				return rootDBWithInlineSG(t, map[string]any{
					"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
					"ipv6_cidr_blocks": []any{"::/0"},
				}, nil)
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "port range 0-65535 world",
			build: func() (planResource, []planResource, configIndex) {
				return rootDBWithInlineSG(t, map[string]any{
					"from_port": float64(0), "to_port": float64(65535), "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/0"},
				}, nil)
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "protocol -1 world",
			build: func() (planResource, []planResource, configIndex) {
				return rootDBWithInlineSG(t, map[string]any{
					"from_port": float64(0), "to_port": float64(0), "protocol": "-1",
					"cidr_blocks": []any{"0.0.0.0/0"},
				}, nil)
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "unknown CIDR from variable",
			build: func() (planResource, []planResource, configIndex) {
				db, resources, idx := rootDBBare(t)
				sg := &resources[1]
				sg.values = map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
						"cidr_blocks": []any{nil},
					}},
				}
				return db, resources, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "data source SG association",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.main",
					values: map[string]any{"identifier": "app", "engine": "postgres", "port": float64(5432)},
				}
				idx := configIndex{
					resources: map[string]exprSet{
						"aws_db_instance.main": {refs: map[string][]string{
							"vpc_security_group_ids": {"data.aws_security_group.shared.id", "data.aws_security_group.shared"},
						}},
					},
					calls: map[string]exprSet{},
				}
				return db, []planResource{db}, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "0.0.0.0/1 world",
			build: func() (planResource, []planResource, configIndex) {
				return rootDBWithInlineSG(t, map[string]any{
					"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/1"},
				}, nil)
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "128.0.0.0/1 world",
			build: func() (planResource, []planResource, configIndex) {
				return rootDBWithInlineSG(t, map[string]any{
					"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
					"cidr_blocks": []any{"128.0.0.0/1"},
				}, nil)
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "public /8 world",
			build: func() (planResource, []planResource, configIndex) {
				return rootDBWithInlineSG(t, map[string]any{
					"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
					"cidr_blocks": []any{"8.0.0.0/8"},
				}, nil)
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "office /32 restricted",
			build: func() (planResource, []planResource, configIndex) {
				return rootDBWithInlineSG(t, map[string]any{
					"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
					"cidr_blocks": []any{"203.0.113.10/32"},
				}, nil)
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "managed prefix list all private",
			build: func() (planResource, []planResource, configIndex) {
				db, resources, idx := rootDBBare(t)
				pl := planResource{
					typ: "aws_ec2_managed_prefix_list", address: "aws_ec2_managed_prefix_list.private",
					values: map[string]any{
						"id": "pl-private",
						"entry": []any{
							map[string]any{"cidr": "10.0.0.0/8"},
							map[string]any{"cidr": "192.168.0.0/16"},
						},
					},
				}
				sg := &resources[1]
				sg.values = map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
						"prefix_list_ids": []any{"pl-private"},
					}},
				}
				return db, append(resources, pl), idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "unknown prefix list",
			build: func() (planResource, []planResource, configIndex) {
				return rootDBWithInlineSG(t, map[string]any{
					"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
					"prefix_list_ids": []any{"pl-unknown"},
				}, nil)
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "root-level SG association",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.main",
					values: map[string]any{"identifier": "app", "engine": "postgres", "port": float64(5432)},
				}
				sg := planResource{
					typ: "aws_security_group", address: "aws_security_group.db",
					values: map[string]any{
						"ingress": []any{map[string]any{
							"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
							"cidr_blocks": []any{"10.0.0.0/8"},
						}},
					},
				}
				idx := configIndex{
					resources: map[string]exprSet{
						"aws_db_instance.main": {refs: map[string][]string{
							"vpc_security_group_ids": {"aws_security_group.db.id"},
						}},
					},
					calls: map[string]exprSet{},
				}
				return db, []planResource{db, sg}, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "aws_security_group_rule world-open",
			build: func() (planResource, []planResource, configIndex) {
				db, resources, idx := rootDBBare(t)
				rule := planResource{
					typ: "aws_security_group_rule", address: "aws_security_group_rule.open",
					values: map[string]any{
						"type": "ingress", "protocol": "tcp",
						"from_port": float64(5432), "to_port": float64(5432),
						"cidr_blocks": []any{"0.0.0.0/0"},
					},
				}
				idx.resources[rule.address] = exprSet{refs: map[string][]string{
					"security_group_id": {"aws_security_group.db.id", "aws_security_group.db"},
				}}
				return db, append(resources, rule), idx
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "unknown port + port-specific world → absent",
			build: func() (planResource, []planResource, configIndex) {
				db, resources, idx := rootDBWithInlineSG(t, map[string]any{
					"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/0"},
				}, nil)
				db.values = map[string]any{"identifier": "app", "engine": "custom-engine"} // no default port
				return db, resources, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "unknown port + protocol -1 world → false",
			build: func() (planResource, []planResource, configIndex) {
				db, resources, idx := rootDBWithInlineSG(t, map[string]any{
					"from_port": float64(0), "to_port": float64(0), "protocol": "-1",
					"cidr_blocks": []any{"0.0.0.0/0"},
				}, nil)
				db.values = map[string]any{"identifier": "app", "engine": "custom-engine"}
				return db, resources, idx
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "world on non-DB port only → restricted",
			build: func() (planResource, []planResource, configIndex) {
				return rootDBWithInlineSG(t, map[string]any{
					"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/0"},
				}, map[string][]string{
					"ingress": {"aws_security_group.tasks.id"},
				})
			},
			// Empty peer list in values + world on 22 only: the world rule does not cover 5432.
			// Config refs add SG peer → restricted. If only world-on-22 with no other source,
			// classifySGIngress returns restricted (non-covering world ignored).
			wantVal: true, wantKnown: true,
		},
		{
			name: "unresolvable association → absent",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.main",
					values: map[string]any{"identifier": "app", "engine": "postgres"},
				}
				return db, []planResource{db}, configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "two SGs one world-open → false",
			build: func() (planResource, []planResource, configIndex) {
				db := planResource{
					typ: "aws_db_instance", address: "aws_db_instance.main",
					values: map[string]any{"identifier": "app", "engine": "postgres", "port": float64(5432)},
				}
				sgOK := planResource{
					typ: "aws_security_group", address: "aws_security_group.ok",
					values: map[string]any{"ingress": []any{map[string]any{
						"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
						"cidr_blocks": []any{"10.0.0.0/8"},
					}}},
				}
				sgOpen := planResource{
					typ: "aws_security_group", address: "aws_security_group.open",
					values: map[string]any{"ingress": []any{map[string]any{
						"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
						"cidr_blocks": []any{"0.0.0.0/0"},
					}}},
				}
				idx := configIndex{
					resources: map[string]exprSet{
						"aws_db_instance.main": {refs: map[string][]string{
							"vpc_security_group_ids": {
								"aws_security_group.ok.id", "aws_security_group.ok",
								"aws_security_group.open.id", "aws_security_group.open",
							},
						}},
					},
					calls: map[string]exprSet{},
				}
				return db, []planResource{db, sgOK, sgOpen}, idx
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "egress-only SG → true",
			build: func() (planResource, []planResource, configIndex) {
				db, resources, idx := rootDBBare(t)
				resources[1].values = map[string]any{
					"ingress": []any{},
					"egress": []any{map[string]any{
						"from_port": float64(0), "to_port": float64(0), "protocol": "-1",
						"cidr_blocks": []any{"0.0.0.0/0"},
					}},
				}
				return db, resources, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "0.0.0.0/1 + 128.0.0.0/1 world pair",
			build: func() (planResource, []planResource, configIndex) {
				return rootDBWithInlineSG(t, map[string]any{
					"from_port": float64(5432), "to_port": float64(5432), "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/1", "128.0.0.0/1"},
				}, nil)
			},
			wantVal: false, wantKnown: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, resources, idx := tc.build()
			got, known := dbNetworkRestricted(db, resources, idx)
			if known != tc.wantKnown || (known && got != tc.wantVal) {
				t.Fatalf("got (%v,%v) want (%v,%v)", got, known, tc.wantVal, tc.wantKnown)
			}
		})
	}
}

func TestDBNetworkRestrictedDemoPlan(t *testing.T) {
	plan, err := os.ReadFile("testdata/aws-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, _, err := Parse(plan, []byte("schema_version: fray-config/v1\n"), "", Source{
		Repo: "example/aws-web-app", Commit: "x", Tool: "terraform", Fidelity: "plan",
	}, filepath.Join("..", "testdata", "aws-web-app"))
	if err != nil {
		t.Fatal(err)
	}
	var db *Element
	for i := range doc.Elements {
		if doc.Elements[i].Kind == "relational_db" {
			db = &doc.Elements[i]
			break
		}
	}
	if db == nil {
		t.Fatal("no relational_db")
	}
	if db.Attributes["network_restricted"] != true {
		t.Fatalf("network_restricted=%#v want true", db.Attributes["network_restricted"])
	}
}

func rootDBBare(t *testing.T) (planResource, []planResource, configIndex) {
	t.Helper()
	db := planResource{
		typ: "aws_db_instance", address: "aws_db_instance.main",
		values: map[string]any{"identifier": "app", "engine": "postgres", "port": float64(5432)},
	}
	sg := planResource{
		typ: "aws_security_group", address: "aws_security_group.db",
		values: map[string]any{"ingress": []any{}},
	}
	idx := configIndex{
		resources: map[string]exprSet{
			"aws_db_instance.main": {refs: map[string][]string{
				"vpc_security_group_ids": {"aws_security_group.db.id", "aws_security_group.db"},
			}},
		},
		calls: map[string]exprSet{},
	}
	return db, []planResource{db, sg}, idx
}

func rootDBWithInlineSG(t *testing.T, ingress map[string]any, sgIngressRefs map[string][]string) (planResource, []planResource, configIndex) {
	t.Helper()
	db, resources, idx := rootDBBare(t)
	resources[1].values = map[string]any{"ingress": []any{ingress}}
	if sgIngressRefs != nil {
		idx.resources["aws_security_group.db"] = exprSet{refs: sgIngressRefs}
	}
	return db, resources, idx
}
