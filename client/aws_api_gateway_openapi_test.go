package client

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestOpenAPIBodyAuthEquivalenceREST(t *testing.T) {
	rows := []struct {
		name   string
		body   string
		method string // authorization on aws_api_gateway_method
		apiKey bool
		want   string
	}{
		{name: "none", body: oas3RESTNone(), method: "NONE", want: "public"},
		{name: "iam", body: oas3RESTIAM(), method: "AWS_IAM", want: "authenticated"},
		{name: "cognito", body: oas3RESTCognito(), method: "COGNITO_USER_POOLS", want: "authenticated"},
		{name: "custom", body: oas3RESTCustom(), method: "CUSTOM", want: ""},
		{name: "api_key", body: oas3RESTAPIKey(), method: "NONE", apiKey: true, want: "authenticated"},
		{name: "mixed_none_iam", body: oas3RESTMixedNoneIAM(), method: "NONE", want: "public"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			fromBody := authFromRESTPlan(t, restBodyOnly{body: row.body})
			fromMethod := authFromRESTPlan(t, restBodyOnly{
				methods: []methodAuth{{auth: row.method, apiKey: row.apiKey}},
			})
			if fromBody != row.want || fromMethod != row.want {
				t.Fatalf("body=%q method=%q want %q", fromBody, fromMethod, row.want)
			}
		})
	}
}

func TestOpenAPIBodyAuthEquivalenceHTTP(t *testing.T) {
	rows := []struct {
		name  string
		body  string
		route string
		want  string
	}{
		{name: "none", body: oas3HTTPNone(), route: "NONE", want: "public"},
		{name: "iam", body: oas3HTTPIAM(), route: "AWS_IAM", want: "authenticated"},
		{name: "jwt", body: oas3HTTPJWT(), route: "JWT", want: "authenticated"},
		{name: "custom", body: oas3HTTPCustom(), route: "CUSTOM", want: ""},
		{name: "mixed_none_iam", body: oas3HTTPMixedNoneIAM(), route: "NONE", want: "public"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			fromBody := authFromHTTPPlan(t, httpBodyOnly{body: row.body})
			fromRoute := authFromHTTPPlan(t, httpBodyOnly{routes: []string{row.route}})
			if row.name == "mixed_none_iam" {
				fromRoute = authFromHTTPPlan(t, httpBodyOnly{routes: []string{"AWS_IAM", "NONE"}})
			}
			if fromBody != row.want || fromRoute != row.want {
				t.Fatalf("body=%q route=%q want %q", fromBody, fromRoute, row.want)
			}
		})
	}
}

func TestOpenAPIBodyGlobalVsOperationSecurity(t *testing.T) {
	body := `{
	  "openapi":"3.0.1",
	  "security":[{"sigv4":[]}],
	  "paths":{
	    "/public":{"get":{"security":[],"responses":{"default":{"description":"ok"}}}},
	    "/secure":{"get":{"responses":{"default":{"description":"ok"}}}}
	  },
	  "components":{"securitySchemes":{"sigv4":{"type":"apiKey","name":"Authorization","in":"header","x-amazon-apigateway-authtype":"awsSigv4"}}}
	}`
	if got := authFromRESTPlan(t, restBodyOnly{body: body}); got != "public" {
		t.Fatalf("global IAM + op override none → public, got %q", got)
	}
}

func TestOpenAPIBodyFailClosed(t *testing.T) {
	cases := []struct {
		name string
		plan string
	}{
		{name: "body_unknown", plan: restPlanWithBodyMeta(t, restBodyMeta{body: oas3RESTNone(), bodyUnknown: true})},
		{name: "oversize", plan: restPlanWithBodyMeta(t, restBodyMeta{body: strings.Repeat(" ", openapiBodyMaxBytes) + "{}"})},
		{name: "invalid_json", plan: restPlanWithBodyMeta(t, restBodyMeta{body: "{not-json"})},
		{name: "yaml_anchors", plan: restPlanWithBodyMeta(t, restBodyMeta{body: "openapi: 3.0.1\npaths:\n  /x:\n    get:\n      responses:\n        default:\n          description: ok\nx-anchor: &a\n  type: apiKey\nsecuritySchemes:\n  k: *a\n"})},
		{name: "external_ref", plan: restPlanWithBodyMeta(t, restBodyMeta{body: oas3RESTExternalRef()})},
		{name: "unknown_security", plan: restPlanWithBodyMeta(t, restBodyMeta{body: oas3RESTUnknownSecurity()})},
		{name: "conflict_body_method", plan: restPlanWithBodyMeta(t, restBodyMeta{body: oas3RESTNone(), methods: []methodAuth{{auth: "NONE"}}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if authFromPlan(t, tc.plan) != "" {
				t.Fatal("want omitted authz_scope")
			}
		})
	}
}

func TestOpenAPIBodyYAMLPlain(t *testing.T) {
	body := "openapi: 3.0.1\npaths:\n  /health:\n    get:\n      responses:\n        default:\n          description: ok\n"
	if authFromRESTPlan(t, restBodyOnly{body: body}) != "public" {
		t.Fatal("want public from YAML body")
	}
}

func TestOpenAPIBodyDoesNotLeak(t *testing.T) {
	const (
		pathSent    = "SENTINEL-PATH-7f3a"
		opSent      = "SENTINEL-OP-7f3a"
		paramSent   = "SENTINEL-PARAM-7f3a"
		exampleSent = "SENTINEL-EXAMPLE-7f3a"
		serverSent  = "https://example.com/SENTINEL-SERVER-7f3a"
	)
	body, _ := json.Marshal(map[string]any{
		"openapi": "3.0.1",
		"servers": []any{map[string]any{"url": serverSent}},
		"paths": map[string]any{
			"/" + pathSent: map[string]any{
				"get": map[string]any{
					"operationId": opSent,
					"parameters": []any{map[string]any{
						"name": paramSent, "in": "query", "schema": map[string]any{"type": "string"},
					}},
					"responses": map[string]any{
						"default": map[string]any{
							"description": "ok",
							"content": map[string]any{
								"application/json": map[string]any{
									"example": exampleSent,
								},
							},
						},
					},
				},
			},
		},
	})
	plan := restPlanWithBodyMeta(t, restBodyMeta{body: string(body)})
	doc, warns, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "", Source{
		Repo: "example/api-gw", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tool: "terraform", Fidelity: "plan",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	redacted, _, err := Redact(doc, []byte("test-redaction-key-32-bytes-long!!"))
	if err != nil {
		t.Fatal(err)
	}
	redBytes, err := Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	blob := string(plain) + string(redBytes) + strings.Join(warns, "\n")
	for _, s := range []string{pathSent, opSent, paramSent, exampleSent, serverSent} {
		if strings.Contains(blob, s) {
			t.Fatalf("sentinel %q leaked", s)
		}
	}
}

type methodAuth struct {
	auth   string
	apiKey bool
}

type restBodyOnly struct {
	body    string
	methods []methodAuth
}

type restBodyMeta struct {
	body        string
	bodyUnknown bool
	methods     []methodAuth
}

type httpBodyOnly struct {
	body   string
	routes []string
}

type httpBodyMeta struct {
	body        string
	bodyUnknown bool
	routes      []string
}

func authFromRESTPlan(t *testing.T, o restBodyOnly) string {
	t.Helper()
	return authFromPlan(t, restPlanWithBodyMeta(t, restBodyMeta{body: o.body, methods: o.methods}))
}

func authFromHTTPPlan(t *testing.T, o httpBodyOnly) string {
	t.Helper()
	meta := httpBodyMeta{body: o.body}
	if len(o.routes) > 0 {
		meta.routes = o.routes
	}
	return authFromPlan(t, httpPlanWithBodyMeta(t, meta))
}

func authFromPlan(t *testing.T, plan string) string {
	t.Helper()
	doc, _, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "", Source{
		Repo: "example/api-gw", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tool: "terraform", Fidelity: "plan",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	edge := findEdgeFlow(doc)
	if edge == nil {
		return "-"
	}
	return edge.AuthzScope
}

func restPlanWithBodyMeta(t *testing.T, o restBodyMeta) string {
	t.Helper()
	ro := restOpts{types: []string{"REGIONAL"}, stage: true, body: o.body, bodyUnknown: o.bodyUnknown}
	for _, m := range o.methods {
		ro.methods = append(ro.methods, m.auth)
		ro.methodAPIKeys = append(ro.methodAPIKeys, m.apiKey)
	}
	return restPlan(t, ro)
}

func httpPlanWithBodyMeta(t *testing.T, o httpBodyMeta) string {
	t.Helper()
	return httpPlan(t, httpOpts{
		body: o.body, bodyUnknown: o.bodyUnknown, routes: o.routes,
	})
}

func oas3RESTNone() string {
	return `{"openapi":"3.0.1","paths":{"/health":{"get":{"responses":{"default":{"description":"ok"}}}}}}`
}

func oas3RESTIAM() string {
	return `{"openapi":"3.0.1","paths":{"/x":{"get":{"security":[{"sigv4":[]}],"responses":{"default":{"description":"ok"}}}}},"components":{"securitySchemes":{"sigv4":{"type":"apiKey","name":"Authorization","in":"header","x-amazon-apigateway-authtype":"awsSigv4"}}}}`
}

func oas3RESTCognito() string {
	return `{"openapi":"3.0.1","paths":{"/x":{"get":{"security":[{"cog":[]}],"responses":{"default":{"description":"ok"}}}}},"components":{"securitySchemes":{"cog":{"type":"apiKey","name":"Authorization","in":"header","x-amazon-apigateway-authtype":"cognito_user_pools","x-amazon-apigateway-authorizer":{"type":"cognito_user_pools","providerARNs":["arn:aws:cognito-idp:us-east-1:1:userpool/x"]}}}}}`
}

func oas3RESTCustom() string {
	return `{"openapi":"3.0.1","paths":{"/x":{"get":{"security":[{"custom":[]}],"responses":{"default":{"description":"ok"}}}}},"components":{"securitySchemes":{"custom":{"type":"apiKey","name":"Authorization","in":"header","x-amazon-apigateway-authtype":"custom","x-amazon-apigateway-authorizer":{"type":"token","authorizerUri":"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/x/invocations"}}}}}`
}

func oas3RESTAPIKey() string {
	return `{"openapi":"3.0.1","paths":{"/x":{"get":{"x-amazon-apigateway-api-key-required":true,"responses":{"default":{"description":"ok"}}}}}}`
}

func oas3RESTMixedNoneIAM() string {
	return `{"openapi":"3.0.1","paths":{
	  "/a":{"get":{"responses":{"default":{"description":"ok"}}}},
	  "/b":{"get":{"security":[{"sigv4":[]}],"responses":{"default":{"description":"ok"}}}}
	},"components":{"securitySchemes":{"sigv4":{"type":"apiKey","name":"Authorization","in":"header","x-amazon-apigateway-authtype":"awsSigv4"}}}}`
}

func oas3RESTExternalRef() string {
	return `{"openapi":"3.0.1","paths":{"/x":{"get":{"security":[{"ext":[]}],"responses":{"default":{"description":"ok"}}}}},"components":{"securitySchemes":{"ext":{"$ref":"https://example.com/s.yaml#/components/securitySchemes/x"}}}}`
}

func oas3RESTUnknownSecurity() string {
	return `{"openapi":"3.0.1","paths":{"/x":{"get":{"security":[{"weird":[]}],"responses":{"default":{"description":"ok"}}}}},"components":{"securitySchemes":{"weird":{"type":"mutualTLS"}}}}`
}

func oas3HTTPNone() string {
	return oas3RESTNone()
}

func oas3HTTPIAM() string {
	return `{"openapi":"3.0.1","paths":{"/x":{"get":{"security":[{"iam":[]}],"responses":{"default":{"description":"ok"}}}}},"components":{"securitySchemes":{"iam":{"type":"oauth2","scheme":"aws_iam"}}}}`
}

func oas3HTTPJWT() string {
	return `{"openapi":"3.0.1","paths":{"/x":{"get":{"security":[{"jwt":[]}],"responses":{"default":{"description":"ok"}}}}},"components":{"securitySchemes":{"jwt":{"type":"oauth2","x-amazon-apigateway-authorizer":{"type":"jwt","jwtConfiguration":{"issuer":"https://example.com","audience":["a"]}}}}}}`
}

func oas3HTTPCustom() string {
	return `{"openapi":"3.0.1","paths":{"/x":{"get":{"security":[{"lam":[]}],"responses":{"default":{"description":"ok"}}}}},"components":{"securitySchemes":{"lam":{"type":"oauth2","x-amazon-apigateway-authorizer":{"type":"request","authorizerUri":"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/x/invocations"}}}}}`
}

func oas3HTTPMixedNoneIAM() string {
	return oas3RESTMixedNoneIAM()
}

func TestOpenAPIBodyGoldenUpdateREST(t *testing.T) {
	// Ensures rest-with-body golden path stays in sync when UPDATE is set elsewhere.
	body := oas3RESTNone()
	plan := restPlanWithBodyMeta(t, restBodyMeta{body: body})
	doc, _, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "", Source{
		Repo: "example/api-gw", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tool: "terraform", Fidelity: "plan",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	edge := findEdgeFlow(doc)
	if edge == nil || edge.AuthzScope != "public" {
		t.Fatalf("edge=%v", edge)
	}
	got, _ := Marshal(doc)
	if !bytes.Contains(got, []byte(`"authz_scope": "public"`)) {
		t.Fatal("missing public authz_scope in marshal")
	}
}
