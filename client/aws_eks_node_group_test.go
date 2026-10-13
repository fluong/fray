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

func TestEKSNodeGroupPublicIPAndAdmin(t *testing.T) {
	cases := []struct {
		name         string
		build        func() (planResource, []planResource, configIndex)
		wantPublic   bool
		wantPublicOK bool
		wantAdmin    bool
		wantAdminOK  bool
	}{
		{
			name: "(a) remote_access key + empty source SGs → admin true",
			build: func() (planResource, []planResource, configIndex) {
				return ngRAFixture(t, ngRAOpts{
					ec2SSHKey:   "fray-ng-key",
					sourceSGs:   nil,
					subnetPublic: []bool{true},
				})
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "(b) remote_access with source SGs → restricted then (d) false",
			build: func() (planResource, []planResource, configIndex) {
				return ngRAFixture(t, ngRAOpts{
					ec2SSHKey:    "fray-ng-key",
					sourceSGs:    []string{"aws_security_group.bastion"},
					subnetPublic: []bool{false},
					withCluster:  true,
				})
			},
			wantPublic: false, wantPublicOK: true,
			wantAdmin: false, wantAdminOK: true,
		},
		{
			name: "(c) launch template world SSH → admin true",
			build: func() (planResource, []planResource, configIndex) {
				return ngLTFixture(t, ngLTOpts{
					version:             "$Latest",
					tmplAssociatePublic: boolPtr(true),
					subnetPublic:        []bool{false},
					tmplWorldSSH:        true,
					tmplActions:         []string{"no-op"},
					withCluster:         true,
				})
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "(c) launch template private SSH → admin false",
			build: func() (planResource, []planResource, configIndex) {
				return ngLTFixture(t, ngLTOpts{
					version:             "$Latest",
					tmplAssociatePublic: boolPtr(false),
					subnetPublic:        []bool{false},
					tmplWorldSSH:        false,
					tmplActions:         []string{"no-op"},
					withCluster:         true,
				})
			},
			wantPublic: false, wantPublicOK: true,
			wantAdmin: false, wantAdminOK: true,
		},
		{
			name: "(d) no remote_access + no extra cluster rules → admin false",
			build: func() (planResource, []planResource, configIndex) {
				return ngBareFixture(t, ngBareOpts{
					subnetPublic: []bool{false},
					withCluster:  true,
				})
			},
			wantPublic: false, wantPublicOK: true,
			wantAdmin: false, wantAdminOK: true,
		},
		{
			name: "(d) world-22 rule on cluster SG → admin true",
			build: func() (planResource, []planResource, configIndex) {
				return ngBareFixture(t, ngBareOpts{
					subnetPublic:       []bool{true},
					withCluster:        true,
					clusterWorldSSH:    true,
					clusterRuleUnknown: false,
				})
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "(d) unknown rule on cluster SG → omit admin",
			build: func() (planResource, []planResource, configIndex) {
				return ngBareFixture(t, ngBareOpts{
					subnetPublic:       []bool{false},
					withCluster:        true,
					clusterRuleUnknown: true,
				})
			},
			wantPublic: false, wantPublicOK: true,
			wantAdmin: false, wantAdminOK: false,
		},
		{
			name: "both remote_access and launch_template → omit both attrs",
			build: func() (planResource, []planResource, configIndex) {
				ng, resources, idx := ngLTFixture(t, ngLTOpts{
					version:             "$Latest",
					tmplAssociatePublic: boolPtr(true),
					subnetPublic:        []bool{true},
					tmplWorldSSH:        true,
					tmplActions:         []string{"no-op"},
					withCluster:         true,
				})
				ng.values["remote_access"] = []any{map[string]any{
					"ec2_ssh_key":               "fray-ng-key",
					"source_security_group_ids": []any{},
				}}
				set := idx.resources[ng.address]
				if set.raw == nil {
					set.raw = map[string]any{}
				}
				if set.refs == nil {
					set.refs = map[string][]string{}
				}
				set.raw["remote_access"] = []any{map[string]any{
					"ec2_ssh_key": map[string]any{"constant_value": "fray-ng-key"},
				}}
				idx.resources[ng.address] = set
				return ng, resources, idx
			},
			wantPublic: false, wantPublicOK: false,
			wantAdmin: false, wantAdminOK: false,
		},
		{
			name: "subnet public → public true",
			build: func() (planResource, []planResource, configIndex) {
				return ngBareFixture(t, ngBareOpts{
					subnetPublic: []bool{true},
					withCluster:  true,
				})
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: false, wantAdminOK: true,
		},
		{
			name: "subnet private → public false",
			build: func() (planResource, []planResource, configIndex) {
				return ngBareFixture(t, ngBareOpts{
					subnetPublic: []bool{false, false},
					withCluster:  true,
				})
			},
			wantPublic: false, wantPublicOK: true,
			wantAdmin: false, wantAdminOK: true,
		},
		{
			name: "subnet not in plan → omit public",
			build: func() (planResource, []planResource, configIndex) {
				ng, resources, idx := ngBareFixture(t, ngBareOpts{
					subnetPublic: []bool{false},
					withCluster:  true,
				})
				set := idx.resources[ng.address]
				set.refs["subnet_ids"] = []string{"aws_subnet.missing.id", "aws_subnet.missing"}
				idx.resources[ng.address] = set
				return ng, resources, idx
			},
			wantPublic: false, wantPublicOK: false,
			wantAdmin: false, wantAdminOK: true,
		},
		{
			name: "module eks_managed_node_group shape",
			build: func() (planResource, []planResource, configIndex) {
				return ngModuleFixture(t)
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "omitted LT version (= $Default) on create → usable",
			build: func() (planResource, []planResource, configIndex) {
				return ngLTFixture(t, ngLTOpts{
					omitVersion:         true,
					tmplAssociatePublic: boolPtr(true),
					subnetPublic:        []bool{false},
					tmplWorldSSH:        true,
					tmplActions:         []string{"create"},
					withCluster:         true,
				})
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: true, wantAdminOK: true,
		},
		// Launch template without security groups: EKS attaches the cluster SG → (d).
		{
			name: "LT without SGs + no cluster rules → (d) false",
			build: func() (planResource, []planResource, configIndex) {
				return ngLTFixture(t, ngLTOpts{
					version:             "$Latest",
					tmplAssociatePublic: boolPtr(false),
					subnetPublic:        []bool{false},
					tmplActions:         []string{"no-op"},
					tmplNoSGs:           true,
					withCluster:         true,
				})
			},
			wantPublic: false, wantPublicOK: true,
			wantAdmin: false, wantAdminOK: true,
		},
		{
			name: "LT without SGs + world-22 on cluster SG → (d) true",
			build: func() (planResource, []planResource, configIndex) {
				return ngLTFixture(t, ngLTOpts{
					version:             "$Latest",
					tmplAssociatePublic: boolPtr(true),
					subnetPublic:        []bool{false},
					tmplActions:         []string{"no-op"},
					tmplNoSGs:           true,
					withCluster:         true,
					clusterWorldSSH:     true,
				})
			},
			wantPublic: true, wantPublicOK: true,
			wantAdmin: true, wantAdminOK: true,
		},
		{
			name: "LT without SGs + unknown cluster rule → (d) omit",
			build: func() (planResource, []planResource, configIndex) {
				return ngLTFixture(t, ngLTOpts{
					version:             "$Latest",
					tmplAssociatePublic: boolPtr(false),
					subnetPublic:        []bool{false},
					tmplActions:         []string{"no-op"},
					tmplNoSGs:           true,
					withCluster:         true,
					clusterRuleUnknown:  true,
				})
			},
			wantPublic: false, wantPublicOK: true,
			wantAdmin: false, wantAdminOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ng, resources, idx := tc.build()
			el := awsEKSNodeGroupElement(ng, resources, idx)
			gotPub, pubOK := el.Attributes["public_ip"].(bool)
			if pubOK != tc.wantPublicOK {
				t.Fatalf("public_ip known=%v want %v (attrs=%v)", pubOK, tc.wantPublicOK, el.Attributes)
			}
			if pubOK && gotPub != tc.wantPublic {
				t.Fatalf("public_ip=%v want %v", gotPub, tc.wantPublic)
			}
			gotAdmin, adminOK := el.Attributes["admin_ports_open"].(bool)
			if adminOK != tc.wantAdminOK {
				t.Fatalf("admin_ports_open known=%v want %v (attrs=%v)", adminOK, tc.wantAdminOK, el.Attributes)
			}
			if adminOK && gotAdmin != tc.wantAdmin {
				t.Fatalf("admin_ports_open=%v want %v", gotAdmin, tc.wantAdmin)
			}
		})
	}
}

func TestEKSNodeGroupElementNameAndKind(t *testing.T) {
	ng, resources, idx := ngBareFixture(t, ngBareOpts{
		subnetPublic: []bool{false},
		withCluster:  true,
	})
	el := awsEKSNodeGroupElement(ng, resources, idx)
	if el.Kind != "virtual_machine" || el.Type != "process" || el.Provenance != "iac" {
		t.Fatalf("meta: kind=%s type=%s provenance=%s", el.Kind, el.Type, el.Provenance)
	}
	if el.Name != "workers EKS node group" {
		t.Fatalf("name=%q want %q", el.Name, "workers EKS node group")
	}
	if strings.Contains(el.Name, "instance") {
		t.Fatalf("node group name must not contain instance: %q", el.Name)
	}
}

func TestEKSNodeGroupNoLeak(t *testing.T) {
	plan := ngNoLeakPlanJSON(t)
	cfg := []byte("schema_version: fray-config/v1\n")
	src := Source{Repo: "probe/eks-ng", Commit: "abcdef1234567", Tool: "terraform", Fidelity: "plan"}
	doc, warnings, err := Parse(plan, cfg, "fray.yaml", src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "aws_eks_node_group") || strings.Contains(w, "aws_eks_cluster") {
			t.Fatalf("unexpected warning: %s", w)
		}
	}
	raw, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	assertNGNoLeak(t, raw)
	for _, el := range doc.Elements {
		if el.Kind == "virtual_machine" && strings.Contains(strings.ToLower(el.Name), "instance") {
			t.Fatalf("node group rendered as instance: %q", el.Name)
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
	assertNGNoLeak(t, body)
}

func TestAWSWebAppPlanUnchangedWithEKSNodeGroup(t *testing.T) {
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

type ngRAOpts struct {
	ec2SSHKey    string
	sourceSGs    []string // empty/nil → world open when key set
	subnetPublic []bool
	withCluster  bool
}

func ngRAFixture(t *testing.T, o ngRAOpts) (planResource, []planResource, configIndex) {
	t.Helper()
	ra := map[string]any{"ec2_ssh_key": o.ec2SSHKey}
	if o.sourceSGs != nil {
		ids := make([]any, len(o.sourceSGs))
		for i := range o.sourceSGs {
			ids[i] = "sg-0ngbastion0011"
		}
		ra["source_security_group_ids"] = ids
	} else {
		ra["source_security_group_ids"] = []any{}
	}
	ng := planResource{
		typ: "aws_eks_node_group", address: "aws_eks_node_group.workers",
		values: map[string]any{
			"node_group_name": "workers",
			"cluster_name":    "fray-eks",
			"remote_access":   []any{ra},
		},
	}
	resources := []planResource{ng}
	idx := configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}

	var subnetRefs []string
	for i, pub := range o.subnetPublic {
		addr := fmt.Sprintf("aws_subnet.z%d", i)
		sn := planResource{
			typ: "aws_subnet", address: addr,
			values: map[string]any{"map_public_ip_on_launch": pub, "id": fmt.Sprintf("subnet-0ngz%d0011", i)},
		}
		resources = append(resources, sn)
		subnetRefs = append(subnetRefs, addr+".id", addr)
		idx.resources[addr] = exprSet{}
	}

	raRaw := map[string]any{
		"ec2_ssh_key": map[string]any{"constant_value": o.ec2SSHKey},
	}
	if len(o.sourceSGs) > 0 {
		var refAnys []any
		for _, sgAddr := range o.sourceSGs {
			refAnys = append(refAnys, sgAddr+".id", sgAddr)
			sg := planResource{
				typ: "aws_security_group", address: sgAddr,
				values: map[string]any{"id": "sg-0ngbastion0011"},
			}
			resources = append(resources, sg)
			idx.resources[sgAddr] = exprSet{}
		}
		raRaw["source_security_group_ids"] = map[string]any{"references": refAnys}
	}

	ngRefs := map[string][]string{
		"subnet_ids":   subnetRefs,
		"cluster_name": {"aws_eks_cluster.this.name", "aws_eks_cluster.this"},
	}
	ngRaw := map[string]any{
		"subnet_ids":    map[string]any{"references": stringSliceAny(subnetRefs)},
		"cluster_name":  map[string]any{"references": []any{"aws_eks_cluster.this.name", "aws_eks_cluster.this"}},
		"remote_access": []any{raRaw},
	}
	if o.withCluster {
		cluster := planResource{
			typ: "aws_eks_cluster", address: "aws_eks_cluster.this",
			values: map[string]any{
				"name": "fray-eks",
				"vpc_config": []any{map[string]any{
					"cluster_security_group_id": "sg-0ngclustersg0011",
				}},
			},
		}
		resources = append(resources, cluster)
		idx.resources[cluster.address] = exprSet{}
	}
	idx.resources[ng.address] = exprSet{refs: ngRefs, raw: ngRaw}
	return ng, resources, idx
}

type ngLTOpts struct {
	version             string
	omitVersion         bool
	tmplAssociatePublic *bool
	subnetPublic        []bool
	tmplWorldSSH        bool
	tmplNoSGs           bool // no vpc_security_group_ids / NI security_groups → cluster SG (d)
	tmplActions         []string
	withCluster         bool
	clusterWorldSSH     bool
	clusterRuleUnknown  bool
}

func ngLTFixture(t *testing.T, o ngLTOpts) (planResource, []planResource, configIndex) {
	t.Helper()
	ltBlock := map[string]any{"id": "lt-0ngdistinct0011"}
	if !o.omitVersion {
		ltBlock["version"] = o.version
	}
	ng := planResource{
		typ: "aws_eks_node_group", address: "aws_eks_node_group.workers",
		values: map[string]any{
			"node_group_name": "workers",
			"cluster_name":    "fray-eks",
			"launch_template": []any{ltBlock},
		},
	}
	resources := []planResource{ng}
	idx := configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}

	var subnetRefs []string
	for i, pub := range o.subnetPublic {
		addr := fmt.Sprintf("aws_subnet.z%d", i)
		sn := planResource{
			typ: "aws_subnet", address: addr,
			values: map[string]any{"map_public_ip_on_launch": pub, "id": fmt.Sprintf("subnet-0ngltz%d0011", i)},
		}
		resources = append(resources, sn)
		subnetRefs = append(subnetRefs, addr+".id", addr)
		idx.resources[addr] = exprSet{}
	}

	nis := []any{}
	if o.tmplAssociatePublic != nil {
		nis = []any{map[string]any{"associate_public_ip_address": *o.tmplAssociatePublic}}
	}
	tmpl := planResource{
		typ: "aws_launch_template", address: "aws_launch_template.ng",
		values: map[string]any{
			"id":                 "lt-0ngdistinct0011",
			"name":               "fray-ng-lt",
			"network_interfaces": nis,
		},
		actions: o.tmplActions,
	}
	resources = append(resources, tmpl)

	ltExpr := map[string]any{
		"id": map[string]any{"references": []any{"aws_launch_template.ng.id", "aws_launch_template.ng"}},
	}
	if !o.omitVersion {
		ltExpr["version"] = map[string]any{"constant_value": o.version}
	}
	idx.resources[ng.address] = exprSet{
		refs: map[string][]string{
			"launch_template": {"aws_launch_template.ng.id", "aws_launch_template.ng"},
			"subnet_ids":      subnetRefs,
			"cluster_name":    {"aws_eks_cluster.this.name", "aws_eks_cluster.this"},
		},
		raw: map[string]any{
			"launch_template": []any{ltExpr},
			"subnet_ids":      map[string]any{"references": stringSliceAny(subnetRefs)},
			"cluster_name":    map[string]any{"references": []any{"aws_eks_cluster.this.name", "aws_eks_cluster.this"}},
		},
	}

	if o.tmplNoSGs {
		// NI may set associate_public_ip_address only — no security group attrs.
		niRaw := map[string]any{}
		if o.tmplAssociatePublic != nil {
			niRaw["associate_public_ip_address"] = map[string]any{"constant_value": *o.tmplAssociatePublic}
		}
		idx.resources[tmpl.address] = exprSet{
			refs: map[string][]string{},
			raw:  map[string]any{"network_interfaces": []any{niRaw}},
		}
	} else {
		cidr := "10.0.0.0/8"
		if o.tmplWorldSSH {
			cidr = "0.0.0.0/0"
		}
		sg := planResource{
			typ: "aws_security_group", address: "aws_security_group.ng_ssh",
			values: map[string]any{"ingress": []any{map[string]any{
				"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
				"cidr_blocks": []any{cidr},
			}}},
		}
		resources = append(resources, sg)
		idx.resources[sg.address] = exprSet{}
		idx.resources[tmpl.address] = exprSet{
			refs: map[string][]string{
				"network_interfaces": {"aws_security_group.ng_ssh.id", "aws_security_group.ng_ssh"},
			},
			raw: map[string]any{
				"network_interfaces": []any{map[string]any{
					"security_groups": map[string]any{
						"references": []any{"aws_security_group.ng_ssh.id", "aws_security_group.ng_ssh"},
					},
				}},
			},
		}
	}

	if o.withCluster {
		cluster := planResource{
			typ: "aws_eks_cluster", address: "aws_eks_cluster.this",
			values: map[string]any{
				"name": "fray-eks",
				"vpc_config": []any{map[string]any{
					"cluster_security_group_id": "sg-0ngclustersg0011",
				}},
			},
		}
		resources = append(resources, cluster)
		idx.resources[cluster.address] = exprSet{}

		if o.clusterWorldSSH || o.clusterRuleUnknown {
			ruleVals := map[string]any{
				"type":      "ingress",
				"from_port": float64(22),
				"to_port":   float64(22),
				"protocol":  "tcp",
			}
			rule := planResource{
				typ: "aws_security_group_rule", address: "aws_security_group_rule.cluster_ssh",
				values: ruleVals,
			}
			if o.clusterRuleUnknown {
				rule.afterUnknown = map[string]any{"cidr_blocks": true}
			} else {
				rule.values["cidr_blocks"] = []any{"0.0.0.0/0"}
			}
			resources = append(resources, rule)
			idx.resources[rule.address] = exprSet{
				refs: map[string][]string{
					"security_group_id": {
						"aws_eks_cluster.this.vpc_config[0].cluster_security_group_id",
						"aws_eks_cluster.this",
					},
				},
				raw: map[string]any{
					"security_group_id": map[string]any{"references": []any{
						"aws_eks_cluster.this.vpc_config[0].cluster_security_group_id",
						"aws_eks_cluster.this",
					}},
				},
			}
		}
	}
	return ng, resources, idx
}

type ngBareOpts struct {
	subnetPublic       []bool
	withCluster        bool
	clusterWorldSSH    bool
	clusterRuleUnknown bool
}

func ngBareFixture(t *testing.T, o ngBareOpts) (planResource, []planResource, configIndex) {
	t.Helper()
	ng := planResource{
		typ: "aws_eks_node_group", address: "aws_eks_node_group.workers",
		values: map[string]any{
			"node_group_name": "workers",
			"cluster_name":    "fray-eks",
		},
	}
	resources := []planResource{ng}
	idx := configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}

	var subnetRefs []string
	for i, pub := range o.subnetPublic {
		addr := fmt.Sprintf("aws_subnet.z%d", i)
		sn := planResource{
			typ: "aws_subnet", address: addr,
			values: map[string]any{"map_public_ip_on_launch": pub, "id": fmt.Sprintf("subnet-0ngbare%d0011", i)},
		}
		resources = append(resources, sn)
		subnetRefs = append(subnetRefs, addr+".id", addr)
		idx.resources[addr] = exprSet{}
	}

	idx.resources[ng.address] = exprSet{
		refs: map[string][]string{
			"subnet_ids":   subnetRefs,
			"cluster_name": {"aws_eks_cluster.this.name", "aws_eks_cluster.this"},
		},
		raw: map[string]any{
			"subnet_ids":   map[string]any{"references": stringSliceAny(subnetRefs)},
			"cluster_name": map[string]any{"references": []any{"aws_eks_cluster.this.name", "aws_eks_cluster.this"}},
		},
	}

	if o.withCluster {
		cluster := planResource{
			typ: "aws_eks_cluster", address: "aws_eks_cluster.this",
			values: map[string]any{
				"name": "fray-eks",
				"vpc_config": []any{map[string]any{
					"cluster_security_group_id": "sg-0ngclustersg0011",
				}},
			},
		}
		resources = append(resources, cluster)
		idx.resources[cluster.address] = exprSet{}

		if o.clusterWorldSSH || o.clusterRuleUnknown {
			ruleVals := map[string]any{
				"type":      "ingress",
				"from_port": float64(22),
				"to_port":   float64(22),
				"protocol":  "tcp",
			}
			rule := planResource{
				typ: "aws_security_group_rule", address: "aws_security_group_rule.cluster_ssh",
				values: ruleVals,
			}
			if o.clusterRuleUnknown {
				rule.afterUnknown = map[string]any{"cidr_blocks": true}
			} else {
				rule.values["cidr_blocks"] = []any{"0.0.0.0/0"}
			}
			resources = append(resources, rule)
			idx.resources[rule.address] = exprSet{
				refs: map[string][]string{
					"security_group_id": {
						"aws_eks_cluster.this.vpc_config[0].cluster_security_group_id",
						"aws_eks_cluster.this",
					},
				},
				raw: map[string]any{
					"security_group_id": map[string]any{"references": []any{
						"aws_eks_cluster.this.vpc_config[0].cluster_security_group_id",
						"aws_eks_cluster.this",
					}},
				},
			}
		}
	}
	return ng, resources, idx
}

func ngModuleFixture(t *testing.T) (planResource, []planResource, configIndex) {
	t.Helper()
	// terraform-aws-modules/eks managed node group shape.
	ng := planResource{
		typ: "aws_eks_node_group", address: "module.eks_managed_node_group.aws_eks_node_group.this[0]",
		values: map[string]any{
			"node_group_name": "workers",
			"cluster_name":    "fray-eks",
			"launch_template": []any{map[string]any{
				"id":      "lt-0modng0011",
				"version": "$Latest",
			}},
		},
	}
	subnet := planResource{
		typ: "aws_subnet", address: "aws_subnet.public",
		values: map[string]any{"map_public_ip_on_launch": true, "id": "subnet-0modng0011"},
	}
	sg := planResource{
		typ: "aws_security_group", address: "module.eks_managed_node_group.aws_security_group.this[0]",
		values: map[string]any{"ingress": []any{map[string]any{
			"from_port": float64(22), "to_port": float64(22), "protocol": "tcp",
			"cidr_blocks": []any{"0.0.0.0/0"},
		}}},
	}
	tmpl := planResource{
		typ: "aws_launch_template", address: "module.eks_managed_node_group.aws_launch_template.this[0]",
		values: map[string]any{
			"id": "lt-0modng0011",
			"network_interfaces": []any{map[string]any{
				"associate_public_ip_address": true,
			}},
		},
		actions: []string{"no-op"},
	}
	cluster := planResource{
		typ: "aws_eks_cluster", address: "module.eks.aws_eks_cluster.this[0]",
		values: map[string]any{
			"name": "fray-eks",
			"vpc_config": []any{map[string]any{
				"cluster_security_group_id": "sg-0modcluster0011",
			}},
		},
	}
	idx := configIndex{resources: map[string]exprSet{}, calls: map[string]exprSet{}}
	ngKey, _ := resourceKey(ng.address)
	tmplKey, _ := resourceKey(tmpl.address)
	sgKey, _ := resourceKey(sg.address)
	clusterKey, _ := resourceKey(cluster.address)
	idx.resources[ngKey] = exprSet{
		refs: map[string][]string{
			"launch_template": {
				"module.eks_managed_node_group.aws_launch_template.this[0].id",
				"module.eks_managed_node_group.aws_launch_template.this[0]",
			},
			"subnet_ids": {"aws_subnet.public.id", "aws_subnet.public"},
			"cluster_name": {
				"module.eks.aws_eks_cluster.this[0].name",
				"module.eks.aws_eks_cluster.this[0]",
			},
		},
		raw: map[string]any{
			"launch_template": []any{map[string]any{
				"id": map[string]any{"references": []any{
					"module.eks_managed_node_group.aws_launch_template.this[0].id",
					"module.eks_managed_node_group.aws_launch_template.this[0]",
				}},
				"version": map[string]any{"constant_value": "$Latest"},
			}},
			"subnet_ids": map[string]any{"references": []any{"aws_subnet.public.id", "aws_subnet.public"}},
			"cluster_name": map[string]any{"references": []any{
				"module.eks.aws_eks_cluster.this[0].name",
				"module.eks.aws_eks_cluster.this[0]",
			}},
		},
	}
	idx.resources[tmplKey] = exprSet{
		refs: map[string][]string{
			"network_interfaces": {
				"module.eks_managed_node_group.aws_security_group.this[0].id",
				"module.eks_managed_node_group.aws_security_group.this[0]",
			},
		},
		raw: map[string]any{
			"network_interfaces": []any{map[string]any{
				"security_groups": map[string]any{"references": []any{
					"module.eks_managed_node_group.aws_security_group.this[0].id",
					"module.eks_managed_node_group.aws_security_group.this[0]",
				}},
			}},
		},
	}
	idx.resources[sgKey] = exprSet{}
	idx.resources[subnet.address] = exprSet{}
	idx.resources[clusterKey] = exprSet{}
	return ng, []planResource{ng, subnet, sg, tmpl, cluster}, idx
}

func ngNoLeakPlanJSON(t *testing.T) []byte {
	t.Helper()
	root := map[string]any{
		"resource_changes": []any{
			map[string]any{
				"address": "aws_eks_node_group.workers", "mode": "managed", "type": "aws_eks_node_group",
				"change": map[string]any{
					"actions": []any{"create"},
					"after": map[string]any{
						"node_group_name": "fray-ng-leak-name-zz9",
						"cluster_name":    "fray-eks-leak-zz9",
						"remote_access": []any{map[string]any{
							"ec2_ssh_key":               "fray-ng-leak-key-zz9",
							"source_security_group_ids": []any{},
						}},
					},
				},
			},
			map[string]any{
				"address": "aws_eks_cluster.this", "mode": "managed", "type": "aws_eks_cluster",
				"change": map[string]any{"after": map[string]any{
					"name": "fray-eks-leak-zz9",
					"vpc_config": []any{map[string]any{
						"cluster_security_group_id": "sg-0ngleakclustersg0011",
					}},
				}},
			},
			map[string]any{
				"address": "aws_subnet.public", "mode": "managed", "type": "aws_subnet",
				"change": map[string]any{"after": map[string]any{
					"map_public_ip_on_launch": true,
					"id":                      "subnet-0ngleaksub0011",
				}},
			},
			map[string]any{
				"address": "aws_security_group.bastion", "mode": "managed", "type": "aws_security_group",
				"change": map[string]any{"after": map[string]any{
					"id": "sg-0ngleakbastion0011",
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
						"address": "aws_eks_node_group.workers", "type": "aws_eks_node_group", "name": "workers",
						"expressions": map[string]any{
							"subnet_ids": map[string]any{
								"references": []any{"aws_subnet.public.id", "aws_subnet.public"},
							},
							"cluster_name": map[string]any{
								"references": []any{"aws_eks_cluster.this.name", "aws_eks_cluster.this"},
							},
							"remote_access": []any{map[string]any{
								"ec2_ssh_key": map[string]any{"constant_value": "fray-ng-leak-key-zz9"},
							}},
						},
					},
					map[string]any{
						"address": "aws_eks_cluster.this", "type": "aws_eks_cluster", "name": "this",
						"expressions": map[string]any{},
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

var ngLeakNeedles = []string{
	"fray-ng-leak-name-zz9",
	"fray-eks-leak-zz9",
	"fray-ng-leak-key-zz9",
	"sg-0ngleakclustersg0011",
	"sg-0ngleakbastion0011",
	"subnet-0ngleaksub0011",
	"198.51.100.64/26",
}

func assertNGNoLeak(t *testing.T, body []byte) {
	t.Helper()
	for _, n := range ngLeakNeedles {
		if bytes.Contains(body, []byte(n)) {
			t.Errorf("FAIL: leak needle %q PRESENT", n)
		}
	}
}
