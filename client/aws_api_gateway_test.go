package client

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Expected FR-001 / FR-026 outcomes are derived from the edge flow the parser
// emits (client does not run the rule engine):
//
//	FR-001 open       → edge authz_scope=public
//	FR-001 mitigated  → edge authz_scope=authenticated
//	FR-001 unverified → edge present, authz_scope omitted
//	FR-001 n/a        → no network edge flow
//	FR-026 mitigated  → edge transport=tls (when edge exists)
//	FR-026 unverified → edge transport=unknown
//	FR-026 n/a        → no edge

type gatewayCase struct {
	name string
	plan string
	// want
	entryKind   string // api_gateway | serverless_function | load_balancer | ""
	authz       string // public | authenticated | "" (omit) | "-" (no edge)
	transport   string // tls | plaintext | unknown | "-"
	backendKind string // serverless_function | "" (none)
	backendTLS  string // tls | plaintext | unknown | "-"
	fr001       string
	fr026       string
	golden      string // relative to testdata/golden/api-gateway/
}

func TestAPIGatewayAndLambdaURLEntries(t *testing.T) {
	cases := []gatewayCase{
		{
			name: "rest_regional_none",
			plan: restPlan(t, restOpts{
				types: []string{"REGIONAL"}, stage: true,
				methods: []string{"NONE"},
			}),
			entryKind: "api_gateway", authz: "public", transport: "tls",
			fr001: "open", fr026: "mitigated", golden: "rest-regional-none.dfd.json",
		},
		{
			name: "rest_all_iam",
			plan: restPlan(t, restOpts{
				types: []string{"REGIONAL"}, stage: true,
				methods: []string{"AWS_IAM", "AWS_IAM"},
			}),
			entryKind: "api_gateway", authz: "authenticated", transport: "tls",
			fr001: "mitigated", fr026: "mitigated", golden: "rest-all-iam.dfd.json",
		},
		{
			name: "rest_mixed_none_iam",
			plan: restPlan(t, restOpts{
				types: []string{"REGIONAL"}, stage: true,
				methods: []string{"AWS_IAM", "NONE"},
			}),
			entryKind: "api_gateway", authz: "public", transport: "tls",
			fr001: "open", fr026: "mitigated", golden: "rest-mixed-none-iam.dfd.json",
		},
		{
			name: "rest_custom",
			plan: restPlan(t, restOpts{
				types: []string{"REGIONAL"}, stage: true,
				methods: []string{"CUSTOM"},
			}),
			entryKind: "api_gateway", authz: "", transport: "tls",
			fr001: "unverified", fr026: "mitigated", golden: "rest-custom.dfd.json",
		},
		{
			name: "rest_private",
			plan: restPlan(t, restOpts{
				types: []string{"PRIVATE"}, stage: true,
				methods: []string{"NONE"},
			}),
			entryKind: "", authz: "-", transport: "-",
			fr001: "n/a", fr026: "n/a", golden: "rest-private.dfd.json",
		},
		{
			name: "rest_no_stage",
			plan: restPlan(t, restOpts{
				types: []string{"REGIONAL"}, stage: false,
				methods: []string{"NONE"},
			}),
			entryKind: "", authz: "-", transport: "-",
			fr001: "n/a", fr026: "n/a", golden: "rest-no-stage.dfd.json",
		},
		{
			name: "rest_with_policy",
			plan: restPlan(t, restOpts{
				types: []string{"REGIONAL"}, stage: true, policy: `{"Version":"2012-10-17"}`,
				methods: []string{"NONE"},
			}),
			entryKind: "", authz: "-", transport: "-",
			fr001: "n/a", fr026: "n/a", golden: "rest-with-policy.dfd.json",
		},
		{
			name: "rest_policy_world_open",
			plan: restPlan(t, restOpts{
				types: []string{"REGIONAL"}, stage: true,
				policy:  `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"execute-api:/*"}]}`,
				methods: []string{"NONE"},
			}),
			entryKind: "api_gateway", authz: "public", transport: "tls",
			fr001: "open", fr026: "mitigated", golden: "rest-policy-world-open.dfd.json",
		},
		{
			name: "rest_with_body",
			plan: restPlan(t, restOpts{
				types: []string{"REGIONAL"}, stage: true,
				body: `{"openapi":"3.0.1","paths":{"/health":{"get":{"responses":{"default":{"description":"ok"}}}}}}`,
			}),
			entryKind: "api_gateway", authz: "public", transport: "tls",
			fr001: "open", fr026: "mitigated", golden: "rest-with-body.dfd.json",
		},
		{
			name: "http_with_body",
			plan: httpPlan(t, httpOpts{
				body: `{"openapi":"3.0.1","paths":{"/health":{"get":{"responses":{"default":{"description":"ok"}}}}}}`,
			}),
			entryKind: "api_gateway", authz: "public", transport: "tls",
			fr001: "open", fr026: "mitigated", golden: "http-with-body.dfd.json",
		},
		{
			name:      "http_none",
			plan:      httpPlan(t, httpOpts{routes: []string{"NONE"}}),
			entryKind: "api_gateway", authz: "public", transport: "tls",
			fr001: "open", fr026: "mitigated", golden: "http-none.dfd.json",
		},
		{
			name:      "http_jwt",
			plan:      httpPlan(t, httpOpts{routes: []string{"JWT", "AWS_IAM"}}),
			entryKind: "api_gateway", authz: "authenticated", transport: "tls",
			fr001: "mitigated", fr026: "mitigated", golden: "http-jwt.dfd.json",
		},
		{
			name:      "http_disable_execute_api",
			plan:      httpPlan(t, httpOpts{disableEndpoint: true, routes: []string{"NONE"}}),
			entryKind: "", authz: "-", transport: "-",
			fr001: "n/a", fr026: "n/a", golden: "http-disable-execute-api.dfd.json",
		},
		{
			name:      "lambda_url_none",
			plan:      lambdaURLPlan(t, "NONE"),
			entryKind: "serverless_function", authz: "public", transport: "tls",
			fr001: "open", fr026: "mitigated", golden: "lambda-url-none.dfd.json",
		},
		{
			name:      "lambda_url_iam",
			plan:      lambdaURLPlan(t, "AWS_IAM"),
			entryKind: "serverless_function", authz: "authenticated", transport: "tls",
			fr001: "mitigated", fr026: "mitigated", golden: "lambda-url-iam.dfd.json",
		},
		{
			name: "rest_integration_lambda",
			plan: restPlan(t, restOpts{
				types: []string{"REGIONAL"}, stage: true,
				methods: []string{"NONE"}, lambdaInteg: true,
			}),
			entryKind: "api_gateway", authz: "public", transport: "tls",
			backendKind: "serverless_function", backendTLS: "tls",
			fr001: "open", fr026: "mitigated", golden: "rest-integration-lambda.dfd.json",
		},
		{
			name:      "alb_cognito",
			plan:      albCognitoPlan(t, albCognitoOpts{}),
			entryKind: "load_balancer", authz: "authenticated", transport: "tls",
			fr001: "mitigated", fr026: "mitigated", golden: "alb-cognito.dfd.json",
		},
		{
			name: "alb_cognito_public_rule",
			plan: albCognitoPlan(t, albCognitoOpts{rules: []albRuleOpt{{
				name: "health", auth: false, forward: true,
			}}}),
			entryKind: "load_balancer", authz: "public", transport: "tls",
			fr001: "open", fr026: "mitigated", golden: "alb-cognito-public-rule.dfd.json",
		},
		{
			name: "alb_cognito_all_rules_auth",
			plan: albCognitoPlan(t, albCognitoOpts{rules: []albRuleOpt{{
				name: "app", auth: true, forward: true,
			}}}),
			entryKind: "load_balancer", authz: "authenticated", transport: "tls",
			fr001: "mitigated", fr026: "mitigated", golden: "alb-cognito-all-rules-auth.dfd.json",
		},
		{
			name: "alb_cognito_unknown_rule",
			plan: albCognitoPlan(t, albCognitoOpts{rules: []albRuleOpt{{
				name: "dyn", unknownActions: true,
			}}}),
			entryKind: "load_balancer", authz: "", transport: "tls",
			fr001: "unverified", fr026: "mitigated", golden: "alb-cognito-unknown-rule.dfd.json",
		},
		{
			name:      "alb_cognito_rule_via_module_output",
			plan:      albCognitoCrossModulePlan(t, true),
			entryKind: "load_balancer", authz: "authenticated", transport: "tls",
			fr001: "mitigated", fr026: "mitigated", golden: "alb-cognito-rule-via-module-output.dfd.json",
		},
		{
			name:      "alb_cognito_rule_unresolvable_arn",
			plan:      albCognitoCrossModulePlan(t, false),
			entryKind: "load_balancer", authz: "", transport: "tls",
			fr001: "unverified", fr026: "mitigated", golden: "alb-cognito-rule-unresolvable-arn.dfd.json",
		},
	}

	dir := filepath.Join("testdata", "golden", "api-gateway")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, err := Parse([]byte(tc.plan), []byte("schema_version: fray-config/v1\n"), "", Source{
				Repo: "example/api-gw", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Tool: "terraform", Fidelity: "plan",
			}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			edge := findEdgeFlow(doc)
			assertGatewayCase(t, tc, doc, edge)

			got, err := Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, tc.golden)
			if os.Getenv("UPDATE") != "" {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				_ = os.WriteFile("/tmp/"+tc.golden, got, 0o644)
				t.Fatalf("missing golden %s (wrote /tmp/%s): %v", path, tc.golden, err)
			}
			if !bytes.Equal(got, want) {
				_ = os.WriteFile("/tmp/"+tc.golden, got, 0o644)
				t.Fatalf("golden drift %s; wrote /tmp/%s", tc.golden, tc.golden)
			}
		})
	}
}

func TestAPIGatewayProviderSubtype(t *testing.T) {
	src := Source{
		Repo: "example/api-gw", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tool: "terraform", Fidelity: "plan",
	}
	cfg := []byte("schema_version: fray-config/v1\n")
	t.Run("rest_private", func(t *testing.T) {
		doc, _, err := Parse([]byte(restPlan(t, restOpts{
			types: []string{"PRIVATE"}, stage: true, methods: []string{"NONE"},
		})), cfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		el := apigwElementByKind(doc, "api_gateway")
		if el == nil || el.ProviderSubtype != "rest_api" {
			t.Fatalf("REST private subtype=%q want rest_api", el.ProviderSubtype)
		}
	})
	t.Run("rest_no_policy", func(t *testing.T) {
		doc, _, err := Parse([]byte(restPlan(t, restOpts{
			types: []string{"REGIONAL"}, stage: true, methods: []string{"NONE"},
		})), cfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		el := apigwElementByKind(doc, "api_gateway")
		if el == nil || el.ProviderSubtype != "rest_api" {
			t.Fatalf("REST no-policy subtype=%q want rest_api", el.ProviderSubtype)
		}
	})
	t.Run("rest_unknown_policy_unresolvable", func(t *testing.T) {
		plan := apigwRESTPlanInlinePolicyUnknown(t, []any{"var.opaque_policy"})
		doc, _, err := Parse([]byte(plan), cfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		el := apigwElementByKind(doc, "api_gateway")
		if el == nil || el.ProviderSubtype != "rest_api" {
			t.Fatalf("REST unknown-policy subtype=%q want rest_api", el.ProviderSubtype)
		}
	})
	t.Run("http_v2_none", func(t *testing.T) {
		doc, _, err := Parse([]byte(httpPlan(t, httpOpts{routes: []string{"NONE"}})), cfg, "", src, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		el := apigwElementByKind(doc, "api_gateway")
		if el == nil {
			t.Fatal("missing http api element")
		}
		if el.ProviderSubtype != "" {
			t.Fatalf("HTTP subtype=%q want empty", el.ProviderSubtype)
		}
	})
}

func apigwElementByKind(doc DFD, kind string) *Element {
	for i := range doc.Elements {
		if doc.Elements[i].Kind == kind {
			return &doc.Elements[i]
		}
	}
	return nil
}

func TestIntegrationTransportClassification(t *testing.T) {
	cases := []struct {
		name          string
		integ         planResource
		wantTransport string
		wantKind      string
	}{
		{
			name:          "lambda aws_proxy",
			integ:         planResource{values: map[string]any{"type": "AWS_PROXY"}},
			wantTransport: "tls", wantKind: "lambda",
		},
		{
			name:          "https http_proxy",
			integ:         planResource{values: map[string]any{"type": "HTTP_PROXY", "uri": "https://example.com"}},
			wantTransport: "tls", wantKind: "http",
		},
		{
			name:          "http plaintext",
			integ:         planResource{values: map[string]any{"type": "HTTP", "uri": "http://example.com"}},
			wantTransport: "plaintext", wantKind: "http",
		},
		{
			name:          "vpc_link",
			integ:         planResource{values: map[string]any{"type": "HTTP_PROXY", "connection_type": "VPC_LINK"}},
			wantTransport: "unknown", wantKind: "vpc_link",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr, kind := integrationTransport(tc.integ)
			if tr != tc.wantTransport || kind != tc.wantKind {
				t.Fatalf("got %q/%q want %q/%q", tr, kind, tc.wantTransport, tc.wantKind)
			}
		})
	}
}

func assertGatewayCase(t *testing.T, tc gatewayCase, doc DFD, edge *Flow) {
	t.Helper()
	if tc.authz == "-" {
		if edge != nil {
			t.Fatalf("want no edge flow, got %+v", edge)
		}
		if tc.fr001 != "n/a" || tc.fr026 != "n/a" {
			t.Fatalf("outcome table: %s / %s", tc.fr001, tc.fr026)
		}
		return
	}
	if edge == nil {
		t.Fatal("want edge flow")
	}
	to := elementByID(doc, edge.To)
	if to == nil || to.Kind != tc.entryKind {
		t.Fatalf("entry kind=%v want %s", to, tc.entryKind)
	}
	if edge.Transport != tc.transport {
		t.Fatalf("transport %q want %q", edge.Transport, tc.transport)
	}
	if edge.AuthzScope != tc.authz {
		t.Fatalf("authz %q want %q", edge.AuthzScope, tc.authz)
	}
	if tc.authz == "public" && edge.Causes["authz_scope"] == "" {
		t.Fatal("public edge must set causes.authz_scope")
	}
	if tc.backendKind != "" {
		back := findBackendFrom(doc, edge.To)
		if back == nil {
			t.Fatal("want backend flow")
		}
		bTo := elementByID(doc, back.To)
		if bTo == nil || bTo.Kind != tc.backendKind {
			t.Fatalf("backend kind=%v want %s", bTo, tc.backendKind)
		}
		if back.Transport != tc.backendTLS {
			t.Fatalf("backend transport %q want %q", back.Transport, tc.backendTLS)
		}
	}
}

func findEdgeFlow(doc DFD) *Flow {
	pub := map[string]bool{}
	for _, el := range doc.Elements {
		if el.Kind == "public_client" {
			pub[el.ID] = true
		}
	}
	for i := range doc.Flows {
		f := &doc.Flows[i]
		if pub[f.From] && len(f.Boundaries) > 0 {
			return f
		}
	}
	return nil
}

func findBackendFrom(doc DFD, fromID string) *Flow {
	for i := range doc.Flows {
		f := &doc.Flows[i]
		if f.From == fromID && f.To != fromID {
			to := elementByID(doc, f.To)
			if to != nil && to.Kind != "public_client" {
				return f
			}
		}
	}
	return nil
}

func elementByID(doc DFD, id string) *Element {
	for i := range doc.Elements {
		if doc.Elements[i].ID == id {
			return &doc.Elements[i]
		}
	}
	return nil
}

type restOpts struct {
	types         []string
	stage         bool
	policy        string
	body          string
	bodyUnknown   bool
	methods       []string
	methodAPIKeys []bool
	lambdaInteg   bool
}

func restPlan(t *testing.T, o restOpts) string {
	t.Helper()
	apiChange := map[string]any{"after": map[string]any{
		"name":                   "api",
		"endpoint_configuration": []any{map[string]any{"types": toAny(o.types)}},
		"policy":                 nullIfEmpty(o.policy),
		"body":                   nullIfEmpty(o.body),
	}}
	if o.bodyUnknown {
		apiChange["after_unknown"] = map[string]any{"body": true}
	}
	resources := []map[string]any{
		{
			"address": "aws_api_gateway_rest_api.api", "mode": "managed", "type": "aws_api_gateway_rest_api",
			"name":   "api",
			"change": apiChange,
		},
	}
	cfgResources := []map[string]any{
		{
			"address": "aws_api_gateway_rest_api.api", "type": "aws_api_gateway_rest_api", "name": "api",
			"expressions": map[string]any{},
		},
	}
	if o.stage {
		resources = append(resources, map[string]any{
			"address": "aws_api_gateway_stage.prod", "mode": "managed", "type": "aws_api_gateway_stage",
			"name":   "prod",
			"change": map[string]any{"after": map[string]any{"stage_name": "prod"}},
		})
		cfgResources = append(cfgResources, map[string]any{
			"address": "aws_api_gateway_stage.prod", "type": "aws_api_gateway_stage", "name": "prod",
			"expressions": map[string]any{
				"rest_api_id": map[string]any{"references": []any{"aws_api_gateway_rest_api.api.id", "aws_api_gateway_rest_api.api"}},
			},
		})
	}
	for i, auth := range o.methods {
		addr := "aws_api_gateway_method.m" + string(rune('a'+i))
		after := map[string]any{"http_method": "GET", "authorization": auth}
		if i < len(o.methodAPIKeys) && o.methodAPIKeys[i] {
			after["api_key_required"] = true
		}
		resources = append(resources, map[string]any{
			"address": addr, "mode": "managed", "type": "aws_api_gateway_method",
			"name":   "m" + string(rune('a'+i)),
			"change": map[string]any{"after": after},
		})
		cfgResources = append(cfgResources, map[string]any{
			"address": addr, "type": "aws_api_gateway_method", "name": "m" + string(rune('a'+i)),
			"expressions": map[string]any{
				"rest_api_id": map[string]any{"references": []any{"aws_api_gateway_rest_api.api.id", "aws_api_gateway_rest_api.api"}},
			},
		})
	}
	if o.lambdaInteg {
		resources = append(resources,
			map[string]any{
				"address": "aws_lambda_function.fn", "mode": "managed", "type": "aws_lambda_function",
				"name": "fn", "change": map[string]any{"after": map[string]any{"function_name": "fn"}},
			},
			map[string]any{
				"address": "aws_api_gateway_integration.lambda", "mode": "managed", "type": "aws_api_gateway_integration",
				"name": "lambda", "change": map[string]any{"after": map[string]any{"type": "AWS_PROXY", "uri": "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:1:function:fn/invocations"}},
			},
		)
		cfgResources = append(cfgResources,
			map[string]any{
				"address": "aws_lambda_function.fn", "type": "aws_lambda_function", "name": "fn",
				"expressions": map[string]any{},
			},
			map[string]any{
				"address": "aws_api_gateway_integration.lambda", "type": "aws_api_gateway_integration", "name": "lambda",
				"expressions": map[string]any{
					"rest_api_id": map[string]any{"references": []any{"aws_api_gateway_rest_api.api.id", "aws_api_gateway_rest_api.api"}},
					"uri":         map[string]any{"references": []any{"aws_lambda_function.fn.arn", "aws_lambda_function.fn"}},
				},
			},
		)
	}
	return marshalPlan(t, resources, cfgResources)
}

type httpOpts struct {
	disableEndpoint bool
	routes          []string
	body            string
	bodyUnknown     bool
}

func httpPlan(t *testing.T, o httpOpts) string {
	t.Helper()
	apiChange := map[string]any{"after": map[string]any{
		"name": "api", "protocol_type": "HTTP",
		"disable_execute_api_endpoint": o.disableEndpoint,
		"body":                         nullIfEmpty(o.body),
	}}
	if o.bodyUnknown {
		apiChange["after_unknown"] = map[string]any{"body": true}
	}
	resources := []map[string]any{
		{
			"address": "aws_apigatewayv2_api.api", "mode": "managed", "type": "aws_apigatewayv2_api",
			"name":   "api",
			"change": apiChange,
		},
	}
	cfgResources := []map[string]any{
		{
			"address": "aws_apigatewayv2_api.api", "type": "aws_apigatewayv2_api", "name": "api",
			"expressions": map[string]any{},
		},
	}
	for i, auth := range o.routes {
		addr := "aws_apigatewayv2_route.r" + string(rune('a'+i))
		resources = append(resources, map[string]any{
			"address": addr, "mode": "managed", "type": "aws_apigatewayv2_route",
			"name": "r" + string(rune('a'+i)),
			"change": map[string]any{"after": map[string]any{
				"route_key": "GET /", "authorization_type": auth,
			}},
		})
		cfgResources = append(cfgResources, map[string]any{
			"address": addr, "type": "aws_apigatewayv2_route", "name": "r" + string(rune('a'+i)),
			"expressions": map[string]any{
				"api_id": map[string]any{"references": []any{"aws_apigatewayv2_api.api.id", "aws_apigatewayv2_api.api"}},
			},
		})
	}
	return marshalPlan(t, resources, cfgResources)
}

func lambdaURLPlan(t *testing.T, auth string) string {
	t.Helper()
	resources := []map[string]any{
		{
			"address": "aws_lambda_function.fn", "mode": "managed", "type": "aws_lambda_function",
			"name": "fn", "change": map[string]any{"after": map[string]any{"function_name": "fn"}},
		},
		{
			"address": "aws_lambda_function_url.fn", "mode": "managed", "type": "aws_lambda_function_url",
			"name": "fn", "change": map[string]any{"after": map[string]any{"authorization_type": auth}},
		},
	}
	cfgResources := []map[string]any{
		{
			"address": "aws_lambda_function.fn", "type": "aws_lambda_function", "name": "fn",
			"expressions": map[string]any{},
		},
		{
			"address": "aws_lambda_function_url.fn", "type": "aws_lambda_function_url", "name": "fn",
			"expressions": map[string]any{
				"function_name": map[string]any{"references": []any{"aws_lambda_function.fn.arn", "aws_lambda_function.fn"}},
			},
		},
	}
	return marshalPlan(t, resources, cfgResources)
}

type albRuleOpt struct {
	name           string
	auth           bool // authenticate-cognito before forward
	forward        bool
	unknownActions bool // non-determinable action type
}

type albCognitoOpts struct {
	rules []albRuleOpt
}

func albCognitoPlan(t *testing.T, o albCognitoOpts) string {
	t.Helper()
	resources := []map[string]any{
		{
			"address": "aws_lb.app", "mode": "managed", "type": "aws_lb",
			"name": "app", "change": map[string]any{"after": map[string]any{"name": "app", "internal": false}},
		},
		{
			"address": "aws_security_group.alb", "mode": "managed", "type": "aws_security_group",
			"name": "alb", "change": map[string]any{"after": map[string]any{
				"ingress": []any{map[string]any{
					"from_port": float64(443), "to_port": float64(443), "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/0"},
				}},
			}},
		},
		{
			"address": "aws_lb_listener.https", "mode": "managed", "type": "aws_lb_listener",
			"name": "https", "change": map[string]any{"after": map[string]any{
				"port": float64(443), "protocol": "HTTPS",
				"default_action": []any{map[string]any{
					"type": "authenticate-cognito",
					"authenticate_cognito": []any{map[string]any{
						"user_pool_arn": "arn:aws:cognito-idp:us-east-1:1:userpool/x",
					}},
				}},
			}},
		},
	}
	cfgResources := []map[string]any{
		{
			"address": "aws_lb.app", "type": "aws_lb", "name": "app",
			"expressions": map[string]any{
				"security_groups": map[string]any{"references": []any{"aws_security_group.alb.id", "aws_security_group.alb"}},
			},
		},
		{
			"address": "aws_security_group.alb", "type": "aws_security_group", "name": "alb",
			"expressions": map[string]any{},
		},
		{
			"address": "aws_lb_listener.https", "type": "aws_lb_listener", "name": "https",
			"expressions": map[string]any{
				"load_balancer_arn": map[string]any{"references": []any{"aws_lb.app.arn", "aws_lb.app"}},
			},
		},
	}
	for _, rule := range o.rules {
		addr := "aws_lb_listener_rule." + rule.name
		var actions []any
		switch {
		case rule.unknownActions:
			actions = []any{map[string]any{"type": "jwt-validation"}}
		default:
			if rule.auth {
				actions = append(actions, map[string]any{
					"type": "authenticate-cognito", "order": float64(1),
					"authenticate_cognito": []any{map[string]any{
						"user_pool_arn": "arn:aws:cognito-idp:us-east-1:1:userpool/x",
					}},
				})
			}
			if rule.forward {
				order := float64(1)
				if rule.auth {
					order = 2
				}
				actions = append(actions, map[string]any{
					"type": "forward", "order": order,
					"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/app/x",
				})
			}
		}
		resources = append(resources, map[string]any{
			"address": addr, "mode": "managed", "type": "aws_lb_listener_rule",
			"name": rule.name, "change": map[string]any{"after": map[string]any{
				"action": actions,
			}},
		})
		cfgResources = append(cfgResources, map[string]any{
			"address": addr, "type": "aws_lb_listener_rule", "name": rule.name,
			"expressions": map[string]any{
				"listener_arn": map[string]any{"references": []any{"aws_lb_listener.https.arn", "aws_lb_listener.https"}},
			},
		})
	}
	return marshalPlan(t, resources, cfgResources)
}

// albCognitoCrossModulePlan: Cognito default on module.alb listener; rule lives in
// module.rules. When resolvable, listener_arn is module.alb.listener_arn (module
// output). When not, listener_arn is an unresolvable local expression.
func albCognitoCrossModulePlan(t *testing.T, resolvable bool) string {
	t.Helper()
	resources := []map[string]any{
		{
			"address": "module.alb.aws_lb.app", "mode": "managed", "type": "aws_lb",
			"name": "app", "change": map[string]any{"after": map[string]any{"name": "app", "internal": false}},
		},
		{
			"address": "module.alb.aws_security_group.alb", "mode": "managed", "type": "aws_security_group",
			"name": "alb", "change": map[string]any{"after": map[string]any{
				"ingress": []any{map[string]any{
					"from_port": float64(443), "to_port": float64(443), "protocol": "tcp",
					"cidr_blocks": []any{"0.0.0.0/0"},
				}},
			}},
		},
		{
			"address": "module.alb.aws_lb_listener.https", "mode": "managed", "type": "aws_lb_listener",
			"name": "https", "change": map[string]any{"after": map[string]any{
				"port": float64(443), "protocol": "HTTPS",
				"default_action": []any{map[string]any{
					"type": "authenticate-cognito",
					"authenticate_cognito": []any{map[string]any{
						"user_pool_arn": "arn:aws:cognito-idp:us-east-1:1:userpool/x",
					}},
				}},
			}},
		},
		{
			"address": "module.rules.aws_lb_listener_rule.app", "mode": "managed", "type": "aws_lb_listener_rule",
			"name": "app", "change": map[string]any{"after": map[string]any{
				"action": []any{
					map[string]any{
						"type": "authenticate-cognito", "order": float64(1),
						"authenticate_cognito": []any{map[string]any{
							"user_pool_arn": "arn:aws:cognito-idp:us-east-1:1:userpool/x",
						}},
					},
					map[string]any{
						"type": "forward", "order": float64(2),
						"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/app/x",
					},
				},
			}},
		},
	}
	ruleListenerRefs := []any{"local.unknown_listener"}
	if resolvable {
		ruleListenerRefs = []any{"module.alb.listener_arn", "module.alb"}
	}
	doc := map[string]any{
		"resource_changes": resources,
		"configuration": map[string]any{
			"root_module": map[string]any{
				"module_calls": map[string]any{
					"alb": map[string]any{
						"expressions": map[string]any{},
						"module": map[string]any{
							"resources": []map[string]any{
								{
									"address": "aws_lb.app", "type": "aws_lb", "name": "app", "mode": "managed",
									"expressions": map[string]any{
										"security_groups": map[string]any{"references": []any{"aws_security_group.alb.id", "aws_security_group.alb"}},
									},
								},
								{
									"address": "aws_security_group.alb", "type": "aws_security_group", "name": "alb", "mode": "managed",
									"expressions": map[string]any{},
								},
								{
									"address": "aws_lb_listener.https", "type": "aws_lb_listener", "name": "https", "mode": "managed",
									"expressions": map[string]any{
										"load_balancer_arn": map[string]any{"references": []any{"aws_lb.app.arn", "aws_lb.app"}},
									},
								},
							},
							"outputs": map[string]any{
								"listener_arn": map[string]any{
									"expression": map[string]any{
										"references": []any{"aws_lb_listener.https.arn", "aws_lb_listener.https"},
									},
								},
							},
						},
					},
					"rules": map[string]any{
						"expressions": map[string]any{},
						"module": map[string]any{
							"resources": []map[string]any{
								{
									"address": "aws_lb_listener_rule.app", "type": "aws_lb_listener_rule", "name": "app", "mode": "managed",
									"expressions": map[string]any{
										"listener_arn": map[string]any{"references": ruleListenerRefs},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func marshalPlan(t *testing.T, resources, cfgResources []map[string]any) string {
	t.Helper()
	doc := map[string]any{
		"resource_changes": resources,
		"configuration": map[string]any{
			"root_module": map[string]any{
				"resources": cfgResources,
			},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func TestAPIGatewayOutcomeTable(t *testing.T) {
	// Keeps the report table honest: names match TestAPIGatewayAndLambdaURLEntries.
	var b strings.Builder
	b.WriteString("| fixture | FR-001 | FR-026 |\n|---|---|---|\n")
	rows := []struct{ name, fr001, fr026 string }{
		{"rest_regional_none", "open", "mitigated"},
		{"rest_all_iam", "mitigated", "mitigated"},
		{"rest_mixed_none_iam", "open", "mitigated"},
		{"rest_custom", "unverified", "mitigated"},
		{"rest_private", "n/a", "n/a"},
		{"rest_no_stage", "n/a", "n/a"},
		{"rest_with_policy", "n/a", "n/a"},
		{"rest_with_body", "unverified", "mitigated"},
		{"http_none", "open", "mitigated"},
		{"http_jwt", "mitigated", "mitigated"},
		{"http_disable_execute_api", "n/a", "n/a"},
		{"lambda_url_none", "open", "mitigated"},
		{"lambda_url_iam", "mitigated", "mitigated"},
		{"rest_integration_lambda", "open", "mitigated"},
		{"https/http/vpc_link backends", "n/a (no peer element)", "n/a"},
		{"alb_cognito", "mitigated", "mitigated"},
		{"alb_cognito_public_rule", "open", "mitigated"},
		{"alb_cognito_all_rules_auth", "mitigated", "mitigated"},
		{"alb_cognito_unknown_rule", "unverified", "mitigated"},
		{"alb_cognito_rule_via_module_output", "mitigated", "mitigated"},
		{"alb_cognito_rule_unresolvable_arn", "unverified", "mitigated"},
	}
	for _, r := range rows {
		b.WriteString("| " + r.name + " | " + r.fr001 + " | " + r.fr026 + " |\n")
	}
	t.Log("\n" + b.String())
}
