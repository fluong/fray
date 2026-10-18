package client

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestAPIGatewayResourcePolicyClassification(t *testing.T) {
	ctx := awsResourcePolicyContext{owner: "111122223333", ownerOK: true}
	cases := []struct {
		name   string
		policy string
		world  triBool
		cross  triBool
		ctx    *awsResourcePolicyContext
	}{
		{
			name:   "allow_star_no_conditions",
			policy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"}]}`,
			world:  triTrue, cross: triTrue,
		},
		{
			name: "vpce_deny_neutralizes",
			policy: `{"Statement":[
				{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"},
				{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*","Condition":{"StringNotEquals":{"aws:SourceVpce":"vpce-123"}}}
			]}`,
			world: triFalse, cross: triFalse,
		},
		{
			name: "deny_string_equals_omits",
			policy: `{"Statement":[
				{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"},
				{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-123"}}}
			]}`,
			world: triOmit, cross: triOmit,
		},
		{
			name:   "deny_two_condition_keys_omits",
			policy: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"*","Condition":{"StringNotEquals":{"aws:SourceVpce":"vpce-1","aws:SourceVpc":"vpc-1"}}}]}`,
			world:  triOmit, cross: triOmit,
		},
		{
			name: "deny_narrower_resource_omits",
			policy: `{"Statement":[
				{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"},
				{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/prod/GET/*","Condition":{"StringNotEquals":{"aws:SourceVpce":"vpce-123"}}}
			]}`,
			world: triOmit, cross: triOmit,
		},
		{
			name: "shorthand_deny_covers_allow",
			policy: `{"Statement":[
				{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"},
				{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*","Condition":{"StringNotEquals":{"aws:SourceVpc":"vpc-abc"}}}
			]}`,
			world: triFalse, cross: triFalse,
		},
		{
			name: "not_ip_address_restricts_world_only",
			policy: `{"Statement":[
				{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"},
				{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*","Condition":{"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}
			]}`,
			world: triFalse, cross: triTrue,
		},
		{
			name: "not_ip_address_open_cidr_world_true",
			policy: `{"Statement":[
				{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"},
				{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*","Condition":{"NotIpAddress":{"aws:SourceIp":["0.0.0.0/0"]}}}
			]}`,
			world: triTrue, cross: triTrue,
		},
		{
			name: "not_ip_address_ipv6_open",
			policy: `{"Statement":[
				{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"},
				{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*","Condition":{"NotIpAddress":{"aws:SourceIp":["::/0"]}}}
			]}`,
			world: triTrue, cross: triTrue,
		},
		{
			name:   "foreign_account_only",
			policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"444455556666"},"Action":"execute-api:Invoke","Resource":"execute-api:/*"}]}`,
			world:  triFalse, cross: triTrue,
		},
		{
			name:   "owner_account_only",
			policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"111122223333"},"Action":"execute-api:Invoke","Resource":"execute-api:/*"}]}`,
			world:  triFalse, cross: triFalse,
		},
		{
			name:   "org_restricted",
			policy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-exampleorgid"}}}]}`,
			world:  triFalse, cross: triFalse,
		},
		{
			name:   "foreign_unknown_owner_cross_omit",
			policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"444455556666"},"Action":"execute-api:Invoke","Resource":"execute-api:/*"}]}`,
			world:  triFalse, cross: triOmit,
			ctx: &awsResourcePolicyContext{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useCtx := ctx
			if tc.ctx != nil {
				useCtx = *tc.ctx
			}
			doc, ok := syntheticDocFromPolicyJSON("aws_api_gateway_rest_api_policy.test", tc.policy)
			if !ok {
				t.Fatal("bad policy json")
			}
			got := classifyAPIGatewayResourcePolicyDoc(doc, useCtx)
			if got.world != tc.world || got.cross != tc.cross {
				t.Fatalf("world=%v cross=%v want world=%v cross=%v", got.world, got.cross, tc.world, tc.cross)
			}
		})
	}
}

func TestAPIGatewayPolicyIntegration(t *testing.T) {
	cases := []struct {
		name      string
		plan      string
		wantEdge  bool
		world     *bool
		cross     *bool
		attrsOmit bool
	}{
		{
			name:     "no_policy_edge",
			plan:     apigwRESTPlanWithPolicy(t, "", false, "REGIONAL"),
			wantEdge: true,
			world:    apigwBPtr(false), cross: apigwBPtr(false),
		},
		{
			name:     "inline_allow_star_edge",
			plan:     apigwRESTPlanWithPolicy(t, `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"}]}`, false, "REGIONAL"),
			wantEdge: true, world: apigwBPtr(true), cross: apigwBPtr(true),
		},
		{
			name:     "standalone_policy_linked",
			plan:     apigwRESTPlanStandalonePolicy(t, `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"}]}`, false),
			wantEdge: true, world: apigwBPtr(true), cross: apigwBPtr(true),
		},
		{
			name: "vpce_restricted_no_edge",
			plan: apigwRESTPlanWithPolicy(t, `{"Statement":[
				{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"},
				{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*","Condition":{"StringNotEquals":{"aws:SourceVpce":"vpce-abc"}}}
			]}`, false, "REGIONAL"),
			wantEdge: false, world: apigwBPtr(false), cross: apigwBPtr(false),
		},
		{
			name:     "private_allow_star_no_edge",
			plan:     apigwRESTPlanWithPolicy(t, `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"}]}`, false, "PRIVATE"),
			wantEdge: false, world: apigwBPtr(true), cross: apigwBPtr(true),
		},
		{
			name: "private_restrictive_no_edge",
			plan: apigwRESTPlanWithPolicy(t, `{"Statement":[
				{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"},
				{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*","Condition":{"StringNotEquals":{"aws:SourceVpce":"vpce-x"}}}
			]}`, false, "PRIVATE"),
			wantEdge: false, world: apigwBPtr(false), cross: apigwBPtr(false),
		},
		{
			name: "string_equals_deny_omits_no_edge",
			plan: apigwRESTPlanWithPolicy(t, `{"Statement":[
				{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"},
				{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-x"}}}
			]}`, false, "REGIONAL"),
			wantEdge: false, attrsOmit: true,
		},
		{
			name:     "unlinkable_standalone_omits",
			plan:     apigwRESTPlanStandalonePolicy(t, `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"}]}`, true),
			wantEdge: true, attrsOmit: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, err := Parse([]byte(tc.plan), apigwOwnerConfig(t), "", Source{
				Repo: "example/api-gw", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Tool: "terraform", Fidelity: "plan",
			}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			edge := findEdgeFlow(doc)
			if tc.wantEdge && edge == nil {
				t.Fatal("want edge flow")
			}
			if !tc.wantEdge && edge != nil {
				t.Fatalf("want no edge, got %+v", edge)
			}
			api := apigwElement(doc)
			if api == nil {
				t.Fatal("want api_gateway element")
			}
			_, wOK := api.Attributes["resource_policy_world_principal"]
			if tc.attrsOmit {
				if wOK {
					t.Fatal("want attrs omitted")
				}
				return
			}
			if tc.world != nil {
				if !wOK {
					t.Fatal("want world attr")
				}
				if api.Attributes["resource_policy_world_principal"] != *tc.world {
					t.Fatalf("world=%v want %v", api.Attributes["resource_policy_world_principal"], *tc.world)
				}
			}
			if tc.cross != nil {
				c, ok := api.Attributes["resource_policy_cross_account"]
				if !ok {
					t.Fatal("want cross attr when world known")
				}
				if c != *tc.cross {
					t.Fatalf("cross=%v want %v", c, *tc.cross)
				}
			}
		})
	}
}

func TestAPIGatewayEmptyPolicyDocumentOmitsAttrs(t *testing.T) {
	// Same as B-73 classifyResourcePolicyDoc when Statement is absent (aws_resource_policy.go:224-225).
	doc, ok := syntheticDocFromPolicyJSON("aws_api_gateway_rest_api.api", `{"Version":"2012-10-17"}`)
	if !ok {
		t.Fatal("bad policy json")
	}
	got := classifyAPIGatewayResourcePolicyDoc(doc, awsResourcePolicyContext{owner: "111122223333", ownerOK: true})
	if got.world != triOmit || got.cross != triOmit {
		t.Fatalf("world=%v cross=%v want omit/omit", got.world, got.cross)
	}
}

func TestAPIGatewayResourcePolicyRedaction(t *testing.T) {
	plan := apigwRESTPlanWithPolicy(t, `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"444455556666"},"Action":"execute-api:Invoke","Resource":"execute-api:/*"}]}`, false, "REGIONAL")
	doc, _, err := Parse([]byte(plan), apigwOwnerConfig(t), "", Source{
		Repo: "example/api-gw", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tool: "terraform", Fidelity: "plan",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	red, _, err := Redact(doc, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(red)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("444455556666")) {
		t.Fatal("foreign account leaked in redacted DFD")
	}
	if !bytes.Contains(raw, []byte("resource_policy_cross_account")) {
		t.Fatal("want cross attr on wire")
	}
}

func apigwOwnerConfig(t *testing.T) []byte {
	t.Helper()
	return []byte("schema_version: fray-config/v1\n")
}

func apigwElement(doc DFD) *Element {
	for i := range doc.Elements {
		if doc.Elements[i].Kind == "api_gateway" {
			return &doc.Elements[i]
		}
	}
	return nil
}

func apigwBPtr(b bool) *bool { return &b }

func apigwRESTPlanWithPolicy(t *testing.T, policy string, _ bool, endpointType string) string {
	t.Helper()
	resources := []map[string]any{
		{
			"address": "aws_api_gateway_rest_api.api", "mode": "managed", "type": "aws_api_gateway_rest_api",
			"name": "api",
			"change": map[string]any{"after": map[string]any{
				"name":                   "api",
				"endpoint_configuration": []any{map[string]any{"types": []any{endpointType}}},
				"policy":                 nullIfEmpty(policy),
			}},
		},
		{
			"address": "aws_api_gateway_stage.prod", "mode": "managed", "type": "aws_api_gateway_stage",
			"name": "prod", "change": map[string]any{"after": map[string]any{"stage_name": "prod"}},
		},
		{
			"address": "aws_api_gateway_method.m", "mode": "managed", "type": "aws_api_gateway_method",
			"name": "m", "change": map[string]any{"after": map[string]any{"http_method": "GET", "authorization": "NONE"}},
		},
	}
	cfgResources := []map[string]any{
		{"address": "aws_api_gateway_rest_api.api", "type": "aws_api_gateway_rest_api", "name": "api", "expressions": map[string]any{}},
		{
			"address": "aws_api_gateway_stage.prod", "type": "aws_api_gateway_stage", "name": "prod",
			"expressions": map[string]any{
				"rest_api_id": map[string]any{"references": []any{"aws_api_gateway_rest_api.api.id", "aws_api_gateway_rest_api.api"}},
			},
		},
		{
			"address": "aws_api_gateway_method.m", "type": "aws_api_gateway_method", "name": "m",
			"expressions": map[string]any{
				"rest_api_id": map[string]any{"references": []any{"aws_api_gateway_rest_api.api.id", "aws_api_gateway_rest_api.api"}},
			},
		},
	}
	return apigwMarshalPlan(t, resources, cfgResources)
}

func apigwRESTPlanStandalonePolicy(t *testing.T, policy string, unlink bool) string {
	t.Helper()
	refs := []any{"aws_api_gateway_rest_api.api.id", "aws_api_gateway_rest_api.api"}
	if unlink {
		refs = []any{"var.unknown_api"}
	}
	resources := []map[string]any{
		{
			"address": "aws_api_gateway_rest_api.api", "mode": "managed", "type": "aws_api_gateway_rest_api",
			"name": "api",
			"change": map[string]any{"after": map[string]any{
				"name":                   "api",
				"endpoint_configuration": []any{map[string]any{"types": []any{"REGIONAL"}}},
			}},
		},
		{
			"address": "aws_api_gateway_rest_api_policy.api", "mode": "managed", "type": "aws_api_gateway_rest_api_policy",
			"name": "api", "change": map[string]any{"after": map[string]any{"policy": policy}},
		},
		{
			"address": "aws_api_gateway_stage.prod", "mode": "managed", "type": "aws_api_gateway_stage",
			"name": "prod", "change": map[string]any{"after": map[string]any{"stage_name": "prod"}},
		},
		{
			"address": "aws_api_gateway_method.m", "mode": "managed", "type": "aws_api_gateway_method",
			"name": "m", "change": map[string]any{"after": map[string]any{"http_method": "GET", "authorization": "NONE"}},
		},
	}
	cfgResources := []map[string]any{
		{"address": "aws_api_gateway_rest_api.api", "type": "aws_api_gateway_rest_api", "name": "api", "expressions": map[string]any{}},
		{
			"address": "aws_api_gateway_rest_api_policy.api", "type": "aws_api_gateway_rest_api_policy", "name": "api",
			"expressions": map[string]any{
				"rest_api_id": map[string]any{"references": refs},
				"policy":      map[string]any{"constant_value": policy},
			},
		},
		{
			"address": "aws_api_gateway_stage.prod", "type": "aws_api_gateway_stage", "name": "prod",
			"expressions": map[string]any{
				"rest_api_id": map[string]any{"references": []any{"aws_api_gateway_rest_api.api.id", "aws_api_gateway_rest_api.api"}},
			},
		},
		{
			"address": "aws_api_gateway_method.m", "type": "aws_api_gateway_method", "name": "m",
			"expressions": map[string]any{
				"rest_api_id": map[string]any{"references": []any{"aws_api_gateway_rest_api.api.id", "aws_api_gateway_rest_api.api"}},
			},
		},
	}
	return apigwMarshalPlan(t, resources, cfgResources)
}

func TestCoverageF51VPCEPolicyHCLConditionShape(t *testing.T) {
	modDir := filepath.Join("..", "..", "fray-demo-coverage", "infra")
	idx, err := readRootIAMPolicyLiterals(modDir)
	if err != nil {
		t.Skip(err)
	}
	pol, ok := idx["aws_api_gateway_rest_api.f51_vpce"]
	if !ok {
		t.Fatal("missing f51_vpce policy in HCL index")
	}
	if len(pol.statements) < 2 {
		t.Fatalf("want 2 statements, got %d", len(pol.statements))
	}
	cond := pol.statements[1].condition
	body, ok := cond["StringNotEquals"].(map[string]any)
	if !ok {
		t.Fatalf("StringNotEquals body type %T value %#v", cond["StringNotEquals"], cond["StringNotEquals"])
	}
	if _, ok := body["aws:SourceVpce"]; !ok {
		t.Fatalf("missing aws:SourceVpce key in %#v", body)
	}
}

func TestPlanRootResourceAttrVPCEIDUnknown(t *testing.T) {
	resources := []planResource{{
		address:      "aws_vpc_endpoint.vpce",
		typ:          "aws_vpc_endpoint",
		values:       map[string]any{"vpc_id": "vpc-1"},
		afterUnknown: map[string]any{"id": true},
	}}
	got, ok := planRootResourceAttr("aws_vpc_endpoint.vpce.id", resources)
	if !ok {
		t.Fatal("want plan ref for unknown vpc endpoint id")
	}
	if _, ok := planResourceRefAddr(got); !ok {
		t.Fatalf("got %q want plan resource ref", got)
	}
}

func TestAPIGatewayUnknownInlinePolicyFromConfig(t *testing.T) {
	t.Run("vpce_ref_from_hcl_mitigated_no_edge", func(t *testing.T) {
		dir := t.TempDir()
		writeTF(t, dir, `resource "aws_vpc_endpoint" "vpce" {
  vpc_id       = "vpc-1"
  service_name = "com.amazonaws.us-east-1.execute-api"
}
resource "aws_api_gateway_rest_api" "api" {
  name = "api"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "execute-api:/*"
      },
      {
        Effect    = "Deny"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "execute-api:/*"
        Condition = {
          StringNotEquals = {
            "aws:SourceVpce" = aws_vpc_endpoint.vpce.id
          }
        }
      },
    ]
  })
}`)
		plan := apigwRESTPlanInlinePolicyUnknown(t, []any{
			"aws_vpc_endpoint.vpce.id", "aws_vpc_endpoint.vpce",
		})
		doc, _, err := Parse([]byte(plan), apigwOwnerConfig(t), "", Source{
			Repo: "example/api-gw", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Tool: "terraform", Fidelity: "plan",
		}, dir)
		if err != nil {
			t.Fatal(err)
		}
		if findEdgeFlow(doc) != nil {
			t.Fatal("want no edge when VPCE-restricted policy is resolved from config")
		}
		api := apigwElement(doc)
		if api == nil {
			t.Fatal("want api_gateway element")
		}
		w, ok := api.Attributes["resource_policy_world_principal"].(bool)
		if !ok || w {
			t.Fatalf("world=%v ok=%v want false", w, ok)
		}
		c, ok := api.Attributes["resource_policy_cross_account"].(bool)
		if !ok || c {
			t.Fatalf("cross=%v ok=%v want false", c, ok)
		}
	})
	t.Run("unresolvable_unknown_omits_no_edge", func(t *testing.T) {
		plan := apigwRESTPlanInlinePolicyUnknown(t, []any{"var.opaque_policy"})
		doc, _, err := Parse([]byte(plan), apigwOwnerConfig(t), "", Source{
			Repo: "example/api-gw", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Tool: "terraform", Fidelity: "plan",
		}, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if findEdgeFlow(doc) != nil {
			t.Fatal("want no edge when policy is configured but unreadable")
		}
		api := apigwElement(doc)
		if api == nil {
			t.Fatal("want api_gateway element")
		}
		if _, ok := api.Attributes["resource_policy_world_principal"]; ok {
			t.Fatal("want attrs omitted")
		}
	})
	t.Run("known_empty_string_still_no_policy", func(t *testing.T) {
		plan := apigwRESTPlanWithPolicy(t, "", false, "REGIONAL")
		doc, _, err := Parse([]byte(plan), apigwOwnerConfig(t), "", Source{
			Repo: "example/api-gw", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Tool: "terraform", Fidelity: "plan",
		}, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if findEdgeFlow(doc) == nil {
			t.Fatal("want edge when policy is known empty")
		}
		api := apigwElement(doc)
		w, ok := api.Attributes["resource_policy_world_principal"].(bool)
		if !ok || w {
			t.Fatalf("world=%v ok=%v want false", w, ok)
		}
	})
}

func apigwRESTPlanInlinePolicyUnknown(t *testing.T, policyRefs []any) string {
	t.Helper()
	resources := []map[string]any{
		{
			"address": "aws_vpc_endpoint.vpce", "mode": "managed", "type": "aws_vpc_endpoint",
			"name": "vpce",
			"change": map[string]any{
				"after":         map[string]any{"vpc_id": "vpc-1"},
				"after_unknown": map[string]any{"id": true, "arn": true},
			},
		},
		{
			"address": "aws_api_gateway_rest_api.api", "mode": "managed", "type": "aws_api_gateway_rest_api",
			"name": "api",
			"change": map[string]any{
				"after": map[string]any{
					"name":                   "api",
					"endpoint_configuration": []any{map[string]any{"types": []any{"REGIONAL"}}},
				},
				"after_unknown": map[string]any{"policy": true, "id": true, "arn": true},
			},
		},
		{
			"address": "aws_api_gateway_stage.prod", "mode": "managed", "type": "aws_api_gateway_stage",
			"name": "prod", "change": map[string]any{"after": map[string]any{"stage_name": "prod"}},
		},
		{
			"address": "aws_api_gateway_method.m", "mode": "managed", "type": "aws_api_gateway_method",
			"name": "m", "change": map[string]any{"after": map[string]any{"http_method": "GET", "authorization": "NONE"}},
		},
	}
	cfgResources := []map[string]any{
		{
			"address": "aws_api_gateway_rest_api.api", "type": "aws_api_gateway_rest_api", "name": "api",
			"expressions": map[string]any{
				"policy": map[string]any{"references": policyRefs},
			},
		},
		{
			"address": "aws_api_gateway_stage.prod", "type": "aws_api_gateway_stage", "name": "prod",
			"expressions": map[string]any{
				"rest_api_id": map[string]any{"references": []any{"aws_api_gateway_rest_api.api.id", "aws_api_gateway_rest_api.api"}},
			},
		},
		{
			"address": "aws_api_gateway_method.m", "type": "aws_api_gateway_method", "name": "m",
			"expressions": map[string]any{
				"rest_api_id": map[string]any{"references": []any{"aws_api_gateway_rest_api.api.id", "aws_api_gateway_rest_api.api"}},
			},
		},
	}
	return apigwMarshalPlan(t, resources, cfgResources)
}

func apigwMarshalPlan(t *testing.T, resources, cfgResources []map[string]any) string {
	t.Helper()
	doc := map[string]any{
		"resource_changes": resources,
		"configuration": map[string]any{
			"provider_config": map[string]any{
				"aws": map[string]any{
					"expressions": map[string]any{
						"allowed_account_ids": map[string]any{"constant_value": []any{"111122223333"}},
					},
				},
			},
			"root_module": map[string]any{"resources": cfgResources},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
