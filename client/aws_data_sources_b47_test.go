package client

import (
	"encoding/json"
	"testing"
)

// B-47: data sources resolved via loadDataResources (RC then prior_state).

func TestB47DataSubnetPublicIP(t *testing.T) {
	cases := []struct {
		name string
		plan func() []byte
	}{
		{"rc_only", func() []byte { return dataSubnetPlan(t, true, false) }},
		{"prior_state_only", func() []byte { return dataSubnetPlan(t, false, true) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, err := Parse(tc.plan(), []byte("schema_version: fray-config/v1\n"), "", Source{
				Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan",
			}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			el := findKind(doc, "virtual_machine")
			if el == nil {
				t.Fatal("missing virtual_machine")
			}
			got, ok := el.Attributes["public_ip"].(bool)
			if !ok || !got {
				t.Fatalf("public_ip=(%v,%v) want true", got, ok)
			}
		})
	}
}

func TestB47DataLaunchTemplateAssociatePublicFalse(t *testing.T) {
	cases := []struct {
		name string
		plan func() []byte
	}{
		{"rc_only", func() []byte { return dataLTPlan(t, true, false) }},
		{"prior_state_only", func() []byte { return dataLTPlan(t, false, true) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, err := Parse(tc.plan(), []byte("schema_version: fray-config/v1\n"), "", Source{
				Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan",
			}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			el := findKind(doc, "virtual_machine")
			if el == nil {
				t.Fatal("missing virtual_machine")
			}
			got, ok := el.Attributes["public_ip"].(bool)
			if !ok || got {
				t.Fatalf("public_ip=(%v,%v) want false", got, ok)
			}
		})
	}
}

func TestB47DataSGAdminPortsAsymmetric(t *testing.T) {
	t.Run("no_in_plan_rules_omit", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			plan func() []byte
		}{
			{"rc_only", func() []byte { return dataSGPlan(t, true, false, false) }},
			{"prior_state_only", func() []byte { return dataSGPlan(t, false, true, false) }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				doc, _, err := Parse(tc.plan(), []byte("schema_version: fray-config/v1\n"), "", Source{
					Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan",
				}, t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				el := findKind(doc, "virtual_machine")
				if el == nil {
					t.Fatal("missing virtual_machine")
				}
				if _, ok := el.Attributes["admin_ports_open"]; ok {
					t.Fatalf("admin_ports_open present (%#v); want omitted", el.Attributes["admin_ports_open"])
				}
			})
		}
	})
	t.Run("in_plan_world_22_true", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			plan func() []byte
		}{
			{"rc_only", func() []byte { return dataSGPlan(t, true, false, true) }},
			{"prior_state_only", func() []byte { return dataSGPlan(t, false, true, true) }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				doc, _, err := Parse(tc.plan(), []byte("schema_version: fray-config/v1\n"), "", Source{
					Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan",
				}, t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				el := findKind(doc, "virtual_machine")
				if el == nil {
					t.Fatal("missing virtual_machine")
				}
				got, ok := el.Attributes["admin_ports_open"].(bool)
				if !ok || !got {
					t.Fatalf("admin_ports_open=(%v,%v) want true", got, ok)
				}
			})
		}
	})
}

func TestB47DataParamGroupTLSOmitted(t *testing.T) {
	for _, tc := range []struct {
		name string
		plan func() []byte
	}{
		{"rc_only", func() []byte { return dataParamGroupPlan(t, true, false) }},
		{"prior_state_only", func() []byte { return dataParamGroupPlan(t, false, true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, err := Parse(tc.plan(), []byte("schema_version: fray-config/v1\n"), "", Source{
				Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan",
			}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			el := findKind(doc, "relational_db")
			if el == nil {
				t.Fatal("missing relational_db")
			}
			if _, ok := el.Attributes["tls_enforced"]; ok {
				t.Fatalf("tls_enforced present (%#v); want omitted for data param group", el.Attributes["tls_enforced"])
			}
		})
	}
}

func TestB47DataEKSClusterLinkageOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		plan func() []byte
	}{
		{"rc_only", func() []byte { return dataEKSClusterPlan(t, true, false) }},
		{"prior_state_only", func() []byte { return dataEKSClusterPlan(t, false, true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, err := Parse(tc.plan(), []byte("schema_version: fray-config/v1\n"), "", Source{
				Repo: "a/b", Commit: "abcdef1", Tool: "terraform", Fidelity: "plan",
			}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			el := findKind(doc, "virtual_machine")
			if el == nil {
				t.Fatal("missing virtual_machine")
			}
			// Public IP from managed public subnet still known.
			got, ok := el.Attributes["public_ip"].(bool)
			if !ok || !got {
				t.Fatalf("public_ip=(%v,%v) want true", got, ok)
			}
			// Data cluster must not invent admin_ports_open=false.
			if _, ok := el.Attributes["admin_ports_open"]; ok {
				t.Fatalf("admin_ports_open present (%#v); want omitted (data cluster, no in-plan SG rules)", el.Attributes["admin_ports_open"])
			}
		})
	}
}

func dataSubnetPlan(t *testing.T, inRC, inPrior bool) []byte {
	t.Helper()
	dataValues := map[string]any{
		"map_public_ip_on_launch": true,
		"id":                      "subnet-0datapublic0011",
	}
	return marshalDataPlan(t, planParts{
		managedRC: []any{
			map[string]any{
				"address": "aws_instance.bastion", "mode": "managed", "type": "aws_instance",
				"change": map[string]any{"after": map[string]any{"ipv6_address_count": float64(0)}},
			},
		},
		dataAddr: "data.aws_subnet.public", dataType: "aws_subnet", dataName: "public",
		dataValues: dataValues, dataInRC: inRC, dataInPrior: inPrior,
		configResources: []any{
			map[string]any{
				"address": "aws_instance.bastion", "type": "aws_instance", "name": "bastion", "mode": "managed",
				"expressions": map[string]any{
					"subnet_id": map[string]any{"references": []any{"data.aws_subnet.public.id", "data.aws_subnet.public"}},
				},
			},
			map[string]any{
				"address": "data.aws_subnet.public", "type": "aws_subnet", "name": "public", "mode": "data",
				"expressions": map[string]any{},
			},
		},
	})
}

func dataLTPlan(t *testing.T, inRC, inPrior bool) []byte {
	t.Helper()
	dataValues := map[string]any{
		"id":              "lt-0datatemplate0011",
		"latest_version":  float64(1),
		"default_version": float64(1),
		"network_interfaces": []any{map[string]any{
			"associate_public_ip_address": false,
		}},
	}
	return marshalDataPlan(t, planParts{
		managedRC: []any{
			map[string]any{
				"address": "aws_instance.bastion", "mode": "managed", "type": "aws_instance",
				"change": map[string]any{"after": map[string]any{
					"ipv6_address_count": float64(0),
					"launch_template": []any{map[string]any{
						"id": "lt-0datatemplate0011", "version": "$Latest",
					}},
				}},
			},
			map[string]any{
				"address": "aws_subnet.private", "mode": "managed", "type": "aws_subnet",
				"change": map[string]any{"after": map[string]any{
					"map_public_ip_on_launch": false,
					"id":                      "subnet-0private0011",
				}},
			},
		},
		dataAddr: "data.aws_launch_template.app", dataType: "aws_launch_template", dataName: "app",
		dataValues: dataValues, dataInRC: inRC, dataInPrior: inPrior,
		configResources: []any{
			map[string]any{
				"address": "aws_instance.bastion", "type": "aws_instance", "name": "bastion", "mode": "managed",
				"expressions": map[string]any{
					"subnet_id": map[string]any{"references": []any{"aws_subnet.private.id", "aws_subnet.private"}},
					"launch_template": []any{map[string]any{
						"id":      map[string]any{"references": []any{"data.aws_launch_template.app.id", "data.aws_launch_template.app"}},
						"version": map[string]any{"constant_value": "$Latest"},
					}},
				},
			},
			map[string]any{
				"address": "aws_subnet.private", "type": "aws_subnet", "name": "private", "mode": "managed",
				"expressions": map[string]any{},
			},
			map[string]any{
				"address": "data.aws_launch_template.app", "type": "aws_launch_template", "name": "app", "mode": "data",
				"expressions": map[string]any{},
			},
		},
	})
}

func dataSGPlan(t *testing.T, inRC, inPrior, withWorldRule bool) []byte {
	t.Helper()
	dataValues := map[string]any{"id": "sg-0datashared0011"}
	managed := []any{
		map[string]any{
			"address": "aws_instance.bastion", "mode": "managed", "type": "aws_instance",
			"change": map[string]any{"after": map[string]any{
				"associate_public_ip_address": true,
				"ipv6_address_count":          float64(0),
			}},
		},
	}
	cfg := []any{
		map[string]any{
			"address": "aws_instance.bastion", "type": "aws_instance", "name": "bastion", "mode": "managed",
			"expressions": map[string]any{
				"vpc_security_group_ids": map[string]any{
					"references": []any{"data.aws_security_group.shared.id", "data.aws_security_group.shared"},
				},
			},
		},
		map[string]any{
			"address": "data.aws_security_group.shared", "type": "aws_security_group", "name": "shared", "mode": "data",
			"expressions": map[string]any{},
		},
	}
	if withWorldRule {
		managed = append(managed, map[string]any{
			"address": "aws_vpc_security_group_ingress_rule.ssh", "mode": "managed", "type": "aws_vpc_security_group_ingress_rule",
			"change": map[string]any{"after": map[string]any{
				"from_port": float64(22), "to_port": float64(22), "ip_protocol": "tcp",
				"cidr_ipv4": "0.0.0.0/0", "security_group_id": "sg-0datashared0011",
			}},
		})
		cfg = append(cfg, map[string]any{
			"address": "aws_vpc_security_group_ingress_rule.ssh", "type": "aws_vpc_security_group_ingress_rule",
			"name": "ssh", "mode": "managed",
			"expressions": map[string]any{
				"security_group_id": map[string]any{
					"references": []any{"data.aws_security_group.shared.id", "data.aws_security_group.shared"},
				},
			},
		})
	}
	return marshalDataPlan(t, planParts{
		managedRC: managed,
		dataAddr:  "data.aws_security_group.shared", dataType: "aws_security_group", dataName: "shared",
		dataValues: dataValues, dataInRC: inRC, dataInPrior: inPrior,
		configResources: cfg,
	})
}

func dataParamGroupPlan(t *testing.T, inRC, inPrior bool) []byte {
	t.Helper()
	dataValues := map[string]any{"id": "pg-0data0011", "name": "shared-pg"}
	return marshalDataPlan(t, planParts{
		managedRC: []any{
			map[string]any{
				"address": "aws_db_instance.app", "mode": "managed", "type": "aws_db_instance",
				"change": map[string]any{"after": map[string]any{
					"identifier":           "app",
					"engine":               "postgres",
					"engine_version":       "14.10",
					"parameter_group_name": "shared-pg",
					"storage_encrypted":    true,
				}},
			},
		},
		dataAddr: "data.aws_db_parameter_group.shared", dataType: "aws_db_parameter_group", dataName: "shared",
		dataValues: dataValues, dataInRC: inRC, dataInPrior: inPrior,
		configResources: []any{
			map[string]any{
				"address": "aws_db_instance.app", "type": "aws_db_instance", "name": "app", "mode": "managed",
				"expressions": map[string]any{
					"parameter_group_name": map[string]any{
						"references": []any{"data.aws_db_parameter_group.shared.name", "data.aws_db_parameter_group.shared"},
					},
				},
			},
			map[string]any{
				"address": "data.aws_db_parameter_group.shared", "type": "aws_db_parameter_group", "name": "shared", "mode": "data",
				"expressions": map[string]any{},
			},
		},
	})
}

func dataEKSClusterPlan(t *testing.T, inRC, inPrior bool) []byte {
	t.Helper()
	dataValues := map[string]any{
		"name": "fray-eks",
		"arn":  "arn:aws:eks:us-east-1:111122223333:cluster/fray-eks",
		"id":   "fray-eks",
		"vpc_config": []any{map[string]any{
			"cluster_security_group_id": "sg-0ngclustersg0011",
		}},
	}
	return marshalDataPlan(t, planParts{
		managedRC: []any{
			map[string]any{
				"address": "aws_eks_node_group.workers", "mode": "managed", "type": "aws_eks_node_group",
				"change": map[string]any{"after": map[string]any{
					"node_group_name": "workers",
					"cluster_name":    "fray-eks",
				}},
			},
			map[string]any{
				"address": "aws_subnet.public", "mode": "managed", "type": "aws_subnet",
				"change": map[string]any{"after": map[string]any{
					"map_public_ip_on_launch": true,
					"id":                      "subnet-0ngpublic0011",
				}},
			},
		},
		dataAddr: "data.aws_eks_cluster.this", dataType: "aws_eks_cluster", dataName: "this",
		dataValues: dataValues, dataInRC: inRC, dataInPrior: inPrior,
		configResources: []any{
			map[string]any{
				"address": "aws_eks_node_group.workers", "type": "aws_eks_node_group", "name": "workers", "mode": "managed",
				"expressions": map[string]any{
					"subnet_ids": map[string]any{
						"references": []any{"aws_subnet.public.id", "aws_subnet.public"},
					},
					"cluster_name": map[string]any{
						"references": []any{"data.aws_eks_cluster.this.name", "data.aws_eks_cluster.this"},
					},
				},
			},
			map[string]any{
				"address": "aws_subnet.public", "type": "aws_subnet", "name": "public", "mode": "managed",
				"expressions": map[string]any{},
			},
			map[string]any{
				"address": "data.aws_eks_cluster.this", "type": "aws_eks_cluster", "name": "this", "mode": "data",
				"expressions": map[string]any{},
			},
		},
	})
}

type planParts struct {
	managedRC       []any
	dataAddr        string
	dataType        string
	dataName        string
	dataValues      map[string]any
	dataInRC        bool
	dataInPrior     bool
	configResources []any
}

func marshalDataPlan(t *testing.T, p planParts) []byte {
	t.Helper()
	rc := append([]any{}, p.managedRC...)
	if p.dataInRC {
		rc = append(rc, map[string]any{
			"address": p.dataAddr, "mode": "data", "type": p.dataType,
			"change": map[string]any{"after": p.dataValues},
		})
	}
	root := map[string]any{
		"resource_changes": rc,
		"configuration": map[string]any{
			"root_module": map[string]any{"resources": p.configResources},
		},
	}
	if p.dataInPrior {
		root["prior_state"] = map[string]any{
			"values": map[string]any{
				"root_module": map[string]any{
					"resources": []any{
						map[string]any{
							"address": p.dataAddr, "mode": "data", "type": p.dataType,
							"name": p.dataName, "values": p.dataValues,
						},
					},
				},
			},
		}
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
