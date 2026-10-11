package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLBPublicTable(t *testing.T) {
	cases := []struct {
		name      string
		build     func() (planResource, []planResource, configIndex)
		wantVal   bool
		wantKnown bool
	}{
		{
			name: "internal true",
			build: func() (planResource, []planResource, configIndex) {
				lb, resources, idx := rootLBBare(t, true)
				return lb, resources, idx
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "cross-module SG world",
			build: func() (planResource, []planResource, configIndex) {
				lb := planResource{
					typ: "aws_lb", address: "module.alb.aws_lb.this[0]",
					values: map[string]any{"name": "alb", "internal": false},
				}
				sg := planResource{
					typ: "aws_security_group", address: "aws_security_group.alb",
					values: map[string]any{
						"ingress": []any{map[string]any{
							"from_port": float64(80), "to_port": float64(80), "protocol": "tcp",
							"cidr_blocks": []any{"0.0.0.0/0"},
						}},
					},
				}
				ln := planResource{
					typ: "aws_lb_listener", address: "module.alb.aws_lb_listener.http[0]",
					values: map[string]any{"port": float64(80), "protocol": "HTTP"},
				}
				// configIndex keys are resourceKey form (no instance index).
				idx := configIndex{
					resources: map[string]exprSet{
						"module.alb.aws_lb.this": {refs: map[string][]string{
							"security_groups": {"aws_security_group.alb.id", "aws_security_group.alb"},
						}},
						"module.alb.aws_lb_listener.http": {refs: map[string][]string{
							"load_balancer_arn": {"module.alb.aws_lb.this[0].arn", "module.alb.aws_lb.this[0]", "module.alb.aws_lb.this"},
						}},
					},
					calls: map[string]exprSet{},
				}
				return lb, []planResource{lb, sg, ln}, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "aws_security_group_rule world",
			build: func() (planResource, []planResource, configIndex) {
				lb, resources, idx := rootLBBare(t, false)
				rule := planResource{
					typ: "aws_security_group_rule", address: "aws_security_group_rule.open",
					values: map[string]any{
						"type": "ingress", "from_port": float64(80), "to_port": float64(80),
						"protocol": "tcp", "cidr_blocks": []any{"0.0.0.0/0"},
					},
				}
				idx.resources[rule.address] = exprSet{refs: map[string][]string{
					"security_group_id": {"aws_security_group.alb.id", "aws_security_group.alb"},
				}}
				return lb, append(resources, rule), idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "vpc_security_group_ingress_rule world",
			build: func() (planResource, []planResource, configIndex) {
				lb, resources, idx := rootLBBare(t, false)
				rule := planResource{
					typ: "aws_vpc_security_group_ingress_rule", address: "aws_vpc_security_group_ingress_rule.open",
					values: map[string]any{
						"from_port": float64(80), "to_port": float64(80), "protocol": "tcp",
						"cidr_ipv4": "0.0.0.0/0",
					},
				}
				idx.resources[rule.address] = exprSet{refs: map[string][]string{
					"security_group_id": {"aws_security_group.alb.id", "aws_security_group.alb"},
				}}
				return lb, append(resources, rule), idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "vpc rule demo shape (ip_protocol + null optionals)",
			build: func() (planResource, []planResource, configIndex) {
				lb, resources, idx := rootLBBare(t, false)
				rule := planResource{
					typ: "aws_vpc_security_group_ingress_rule", address: "aws_vpc_security_group_ingress_rule.http",
					values: map[string]any{
						"from_port": float64(80), "to_port": float64(80), "ip_protocol": "tcp",
						"cidr_ipv4": "0.0.0.0/0", "cidr_ipv6": nil,
						"prefix_list_id": nil, "referenced_security_group_id": nil,
						"security_group_id": nil,
					},
				}
				idx.resources[rule.address] = exprSet{refs: map[string][]string{
					"security_group_id":             {"aws_security_group.alb.id", "aws_security_group.alb"},
					"cidr_ipv4":                     {"each.value.cidr_ipv4", "each.value"},
					"cidr_ipv6":                     {"each.value.cidr_ipv6", "each.value"},
					"prefix_list_id":                {"each.value.prefix_list_id", "each.value"},
					"referenced_security_group_id":  {"each.value.referenced_security_group_id", "each.value"},
				}}
				return lb, append(resources, rule), idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "prefix list all-world",
			build: func() (planResource, []planResource, configIndex) {
				lb, resources, idx := rootLBBare(t, false)
				pl := planResource{
					typ: "aws_ec2_managed_prefix_list", address: "aws_ec2_managed_prefix_list.world",
					values: map[string]any{
						"id":    "pl-world",
						"entry": []any{map[string]any{"cidr": "0.0.0.0/0"}},
					},
				}
				resources[1].values = map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(80), "to_port": float64(80), "protocol": "tcp",
						"prefix_list_ids": []any{"pl-world"},
					}},
				}
				return lb, append(resources, pl), idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "prefix list all-private",
			build: func() (planResource, []planResource, configIndex) {
				lb, resources, idx := rootLBBare(t, false)
				pl := planResource{
					typ: "aws_ec2_managed_prefix_list", address: "aws_ec2_managed_prefix_list.priv",
					values: map[string]any{
						"id":    "pl-priv",
						"entry": []any{map[string]any{"cidr": "10.0.0.0/8"}},
					},
				}
				resources[1].values = map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(80), "to_port": float64(80), "protocol": "tcp",
						"prefix_list_ids": []any{"pl-priv"},
					}},
				}
				return lb, append(resources, pl), idx
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "unknown prefix list absent",
			build: func() (planResource, []planResource, configIndex) {
				lb, resources, idx := rootLBBare(t, false)
				resources[1].values = map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(80), "to_port": float64(80), "protocol": "tcp",
						"prefix_list_ids": []any{"pl-unknown"},
					}},
				}
				return lb, resources, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "data-source SG absent",
			build: func() (planResource, []planResource, configIndex) {
				lb := planResource{
					typ: "aws_lb", address: "aws_lb.main",
					values: map[string]any{"name": "alb", "internal": false},
				}
				ln := planResource{
					typ: "aws_lb_listener", address: "aws_lb_listener.http",
					values: map[string]any{"port": float64(80), "protocol": "HTTP"},
				}
				idx := configIndex{
					resources: map[string]exprSet{
						lb.address: {refs: map[string][]string{
							"security_groups": {"data.aws_security_group.alb.id", "data.aws_security_group.alb"},
						}},
						ln.address: {refs: map[string][]string{
							"load_balancer_arn": {lb.address + ".arn", lb.address},
						}},
					},
					calls: map[string]exprSet{},
				}
				return lb, []planResource{lb, ln}, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "private-only SG",
			build: func() (planResource, []planResource, configIndex) {
				lb, resources, idx := rootLBBare(t, false)
				resources[1].values = map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(80), "to_port": float64(80), "protocol": "tcp",
						"cidr_blocks": []any{"10.0.0.0/8"},
					}},
				}
				return lb, resources, idx
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "world on 22 only listener 443 → not public",
			build: func() (planResource, []planResource, configIndex) {
				lb, resources, idx := rootLBBare(t, false)
				resources[2].values = map[string]any{"port": float64(443), "protocol": "HTTPS"}
				resources[1].values = map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
						"cidr_blocks": []any{"0.0.0.0/0"},
					}},
				}
				return lb, resources, idx
			},
			wantVal: false, wantKnown: true,
		},
		{
			name: "world on all ports → public",
			build: func() (planResource, []planResource, configIndex) {
				lb, resources, idx := rootLBBare(t, false)
				resources[2].values = map[string]any{"port": float64(443), "protocol": "HTTPS"}
				resources[1].values = map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(0), "to_port": float64(65535), "protocol": "tcp",
						"cidr_blocks": []any{"0.0.0.0/0"},
					}},
				}
				return lb, resources, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "unknown listener port + port-specific world → absent (same as DB)",
			build: func() (planResource, []planResource, configIndex) {
				lb, resources, idx := rootLBBare(t, false)
				// Listener present but port not a number → listenerPortSet empty → portKnown=false.
				resources[2].values = map[string]any{"protocol": "HTTPS"}
				resources[1].values = map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(443), "to_port": float64(443), "protocol": "tcp",
						"cidr_blocks": []any{"0.0.0.0/0"},
					}},
				}
				return lb, resources, idx
			},
			wantVal: false, wantKnown: false,
		},
		{
			name: "unknown listener port + protocol -1 world → public (same as DB world)",
			build: func() (planResource, []planResource, configIndex) {
				lb, resources, idx := rootLBBare(t, false)
				resources[2].values = map[string]any{"protocol": "HTTPS"}
				resources[1].values = map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(0), "to_port": float64(0), "protocol": "-1",
						"cidr_blocks": []any{"0.0.0.0/0"},
					}},
				}
				return lb, resources, idx
			},
			wantVal: true, wantKnown: true,
		},
		{
			name: "slash8 world",
			build: func() (planResource, []planResource, configIndex) {
				lb, resources, idx := rootLBBare(t, false)
				resources[1].values = map[string]any{
					"ingress": []any{map[string]any{
						"from_port": float64(80), "to_port": float64(80), "protocol": "tcp",
						"cidr_blocks": []any{"8.0.0.0/8"},
					}},
				}
				return lb, resources, idx
			},
			wantVal: true, wantKnown: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lb, resources, idx := tc.build()
			got, known := lbPublic(lb, resources, idx)
			if known != tc.wantKnown || (known && got != tc.wantVal) {
				t.Fatalf("got (%v,%v) want (%v,%v)", got, known, tc.wantVal, tc.wantKnown)
			}
		})
	}
}

func TestLBPublicDemoPlan(t *testing.T) {
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
	var lb *Element
	for i := range doc.Elements {
		if doc.Elements[i].Kind == "load_balancer" {
			lb = &doc.Elements[i]
			break
		}
	}
	if lb == nil {
		t.Fatal("no load_balancer")
	}
	if lb.Attributes["public"] != true {
		t.Fatalf("public=%#v want true", lb.Attributes["public"])
	}
}

func rootLBBare(t *testing.T, internal bool) (planResource, []planResource, configIndex) {
	t.Helper()
	lb := planResource{
		typ: "aws_lb", address: "aws_lb.main",
		values: map[string]any{"name": "alb", "internal": internal},
	}
	sg := planResource{
		typ: "aws_security_group", address: "aws_security_group.alb",
		values: map[string]any{"ingress": []any{}},
	}
	ln := planResource{
		typ: "aws_lb_listener", address: "aws_lb_listener.http",
		values: map[string]any{"port": float64(80), "protocol": "HTTP"},
	}
	idx := configIndex{
		resources: map[string]exprSet{
			lb.address: {refs: map[string][]string{
				"security_groups": {"aws_security_group.alb.id", "aws_security_group.alb"},
			}},
			ln.address: {refs: map[string][]string{
				"load_balancer_arn": {lb.address + ".arn", lb.address},
			}},
		},
		calls: map[string]exprSet{},
	}
	return lb, []planResource{lb, sg, ln}, idx
}
