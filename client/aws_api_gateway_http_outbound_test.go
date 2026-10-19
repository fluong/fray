package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const outboundSentinel = "SENTINEL-HOST-9c1e"

type restHTTPInteg struct {
	name       string
	integType  string
	uri        string
	uriUnknown bool
	connType   string
}

func restOutboundPlan(t *testing.T, types []string, stage bool, integs []restHTTPInteg) string {
	t.Helper()
	apiChange := map[string]any{"after": map[string]any{
		"name":                   "api",
		"endpoint_configuration": []any{map[string]any{"types": toAny(types)}},
	}}
	resources := []map[string]any{
		{
			"address": "aws_api_gateway_rest_api.api", "mode": "managed", "type": "aws_api_gateway_rest_api",
			"name": "api", "change": apiChange,
		},
	}
	cfgResources := []map[string]any{
		{
			"address": "aws_api_gateway_rest_api.api", "type": "aws_api_gateway_rest_api", "name": "api",
			"expressions": map[string]any{},
		},
	}
	if stage {
		resources = append(resources, map[string]any{
			"address": "aws_api_gateway_stage.prod", "mode": "managed", "type": "aws_api_gateway_stage",
			"name": "prod", "change": map[string]any{"after": map[string]any{"stage_name": "prod"}},
		})
		cfgResources = append(cfgResources, map[string]any{
			"address": "aws_api_gateway_stage.prod", "type": "aws_api_gateway_stage", "name": "prod",
			"expressions": map[string]any{
				"rest_api_id": map[string]any{"references": []any{"aws_api_gateway_rest_api.api.id", "aws_api_gateway_rest_api.api"}},
			},
		})
	}
	for _, ig := range integs {
		after := map[string]any{"type": ig.integType}
		if ig.uri != "" {
			after["uri"] = ig.uri
		}
		if ig.connType != "" {
			after["connection_type"] = ig.connType
		}
		ch := map[string]any{"after": after}
		if ig.uriUnknown {
			ch["after_unknown"] = map[string]any{"uri": true}
		}
		addr := "aws_api_gateway_integration." + ig.name
		resources = append(resources, map[string]any{
			"address": addr, "mode": "managed", "type": "aws_api_gateway_integration",
			"name": ig.name, "change": ch,
		})
		cfgResources = append(cfgResources, map[string]any{
			"address": addr, "type": "aws_api_gateway_integration", "name": ig.name,
			"expressions": map[string]any{
				"rest_api_id": map[string]any{"references": []any{"aws_api_gateway_rest_api.api.id", "aws_api_gateway_rest_api.api"}},
			},
		})
	}
	return marshalPlan(t, resources, cfgResources)
}

func v2HTTPProxyPlan(t *testing.T, uri, connType string) string {
	t.Helper()
	after := map[string]any{
		"integration_type": "HTTP_PROXY",
		"integration_uri":  uri,
	}
	if connType != "" {
		after["connection_type"] = connType
	}
	resources := []map[string]any{
		{
			"address": "aws_apigatewayv2_api.api", "mode": "managed", "type": "aws_apigatewayv2_api",
			"name": "api",
			"change": map[string]any{"after": map[string]any{
				"name": "api", "protocol_type": "HTTP",
			}},
		},
		{
			"address": "aws_apigatewayv2_integration.proxy", "mode": "managed", "type": "aws_apigatewayv2_integration",
			"name": "proxy", "change": map[string]any{"after": after},
		},
	}
	cfgResources := []map[string]any{
		{
			"address": "aws_apigatewayv2_api.api", "type": "aws_apigatewayv2_api", "name": "api",
			"expressions": map[string]any{},
		},
		{
			"address": "aws_apigatewayv2_integration.proxy", "type": "aws_apigatewayv2_integration", "name": "proxy",
			"expressions": map[string]any{
				"api_id": map[string]any{"references": []any{"aws_apigatewayv2_api.api.id", "aws_apigatewayv2_api.api"}},
			},
		},
	}
	return marshalPlan(t, resources, cfgResources)
}

func parseOutbound(t *testing.T, plan string) (DFD, []string) {
	t.Helper()
	doc, warnings, err := Parse([]byte(plan), []byte("schema_version: fray-config/v1\n"), "", Source{
		Repo: "example/api-gw", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tool: "terraform", Fidelity: "plan",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return doc, warnings
}

func outboundFlows(doc DFD) []Flow {
	var out []Flow
	peerID := ""
	for _, el := range doc.Elements {
		if el.Kind == "external_http_endpoint" {
			peerID = el.ID
			break
		}
	}
	if peerID == "" {
		return nil
	}
	for _, f := range doc.Flows {
		if f.To == peerID {
			out = append(out, f)
		}
	}
	return out
}

func TestOutboundHTTPIntegrationTransport(t *testing.T) {
	cases := []struct {
		name      string
		plan      string
		wantTrans string
		wantPeer  bool
	}{
		{
			name: "REST HTTP_PROXY https",
			plan: restOutboundPlan(t, []string{"REGIONAL"}, true, []restHTTPInteg{
				{name: "proxy", integType: "HTTP_PROXY", uri: "https://api.example.com/path"},
			}),
			wantTrans: "tls", wantPeer: true,
		},
		{
			name: "REST HTTP http",
			plan: restOutboundPlan(t, []string{"REGIONAL"}, true, []restHTTPInteg{
				{name: "http", integType: "HTTP", uri: "http://api.example.com/"},
			}),
			wantTrans: "plaintext", wantPeer: true,
		},
		{
			name: "REST uri unknown after apply",
			plan: restOutboundPlan(t, []string{"REGIONAL"}, true, []restHTTPInteg{
				{name: "unk", integType: "HTTP_PROXY", uriUnknown: true},
			}),
			wantTrans: "unknown", wantPeer: true,
		},
		{
			name: "REST ftp scheme",
			plan: restOutboundPlan(t, []string{"REGIONAL"}, true, []restHTTPInteg{
				{name: "ftp", integType: "HTTP", uri: "ftp://api.example.com/x"},
			}),
			wantTrans: "unknown", wantPeer: true,
		},
		{
			name: "REST VPC_LINK",
			plan: restOutboundPlan(t, []string{"REGIONAL"}, true, []restHTTPInteg{
				{name: "vl", integType: "HTTP", uri: "https://api.example.com", connType: "VPC_LINK"},
			}),
			wantPeer: false,
		},
		{
			name:      "v2 HTTP_PROXY INTERNET",
			plan:      v2HTTPProxyPlan(t, "https://api.example.com", "INTERNET"),
			wantTrans: "tls", wantPeer: true,
		},
		{
			name:     "v2 VPC_LINK",
			plan:     v2HTTPProxyPlan(t, "https://api.example.com", "VPC_LINK"),
			wantPeer: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, _ := parseOutbound(t, tc.plan)
			peer := apigwElementByKind(doc, "external_http_endpoint")
			if tc.wantPeer && peer == nil {
				t.Fatal("want external_http_endpoint element")
			}
			if !tc.wantPeer && peer != nil {
				t.Fatal("unexpected external_http_endpoint element")
			}
			if !tc.wantPeer {
				return
			}
			flows := outboundFlows(doc)
			if len(flows) != 1 {
				t.Fatalf("outbound flows=%d want 1", len(flows))
			}
			if flows[0].Transport != tc.wantTrans {
				t.Fatalf("transport=%q want %q", flows[0].Transport, tc.wantTrans)
			}
		})
	}
}

func TestOutboundHTTPPrivateRESTEmitsBackend(t *testing.T) {
	plan := restOutboundPlan(t, []string{"PRIVATE"}, true, []restHTTPInteg{
		{name: "proxy", integType: "HTTP_PROXY", uri: "https://api.example.com/x"},
	})
	doc, _ := parseOutbound(t, plan)
	if apigwElementByKind(doc, "public_client") != nil {
		t.Fatal("private API must not create public_client edge")
	}
	flows := outboundFlows(doc)
	if len(flows) != 1 {
		t.Fatalf("want 1 outbound flow, got %d", len(flows))
	}
	if len(flows[0].Boundaries) == 0 {
		t.Fatal("want network boundary on outbound flow")
	}
}

func TestOutboundHTTPTwoIntegrationsSharedPeer(t *testing.T) {
	plan := restOutboundPlan(t, []string{"REGIONAL"}, true, []restHTTPInteg{
		{name: "a", integType: "HTTP_PROXY", uri: "https://api.example.com/a"},
		{name: "b", integType: "HTTP_PROXY", uri: "https://api.example.com/b"},
	})
	doc, _ := parseOutbound(t, plan)
	peers := 0
	for _, el := range doc.Elements {
		if el.Kind == "external_http_endpoint" {
			peers++
		}
	}
	if peers != 1 {
		t.Fatalf("peer elements=%d want 1", peers)
	}
	flows := outboundFlows(doc)
	if len(flows) != 2 {
		t.Fatalf("outbound flows=%d want 2", len(flows))
	}
}

func TestOutboundHTTPDistinctSARIFFingerprints(t *testing.T) {
	plan := restOutboundPlan(t, []string{"REGIONAL"}, true, []restHTTPInteg{
		{name: "a", integType: "HTTP_PROXY", uri: "https://api.example.com/a"},
		{name: "b", integType: "HTTP_PROXY", uri: "https://api.example.com/b"},
	})
	doc, _ := parseOutbound(t, plan)
	fp := func(cause string) string {
		sum := sha256.Sum256([]byte("FR-026|" + cause))
		return hex.EncodeToString(sum[:])
	}
	causes := map[string]bool{}
	for _, f := range outboundFlows(doc) {
		c := f.Causes["transport"]
		if c == "" {
			t.Fatal("missing transport cause")
		}
		causes[c] = true
		if fp(c) == "" {
			t.Fatal("empty fingerprint")
		}
	}
	if len(causes) != 2 {
		t.Fatalf("causes=%v want 2 distinct", causes)
	}
	if fp("aws_api_gateway_integration.a") == fp("aws_api_gateway_integration.b") {
		t.Fatal("fingerprints must differ")
	}
}

func TestOutboundHTTPNoQualifyingIntegrationNoPeer(t *testing.T) {
	plan := restPlan(t, restOpts{types: []string{"REGIONAL"}, stage: true, lambdaInteg: true})
	doc, _ := parseOutbound(t, plan)
	if apigwElementByKind(doc, "external_http_endpoint") != nil {
		t.Fatal("lambda-only API must not emit external_http_endpoint")
	}
}

func TestOutboundHTTPBoundaryInsideToOutside(t *testing.T) {
	plan := restOutboundPlan(t, []string{"REGIONAL"}, true, []restHTTPInteg{
		{name: "proxy", integType: "HTTP_PROXY", uri: "https://api.example.com/"},
	})
	doc, _ := parseOutbound(t, plan)
	api := apigwElementByKind(doc, "api_gateway")
	peer := apigwElementByKind(doc, "external_http_endpoint")
	if api == nil || peer == nil {
		t.Fatal("missing api or peer")
	}
	var netBound *Boundary
	for i := range doc.TrustBoundaries {
		if doc.TrustBoundaries[i].Kind == "network" {
			netBound = &doc.TrustBoundaries[i]
			break
		}
	}
	if netBound == nil {
		t.Fatal("missing network trust boundary")
	}
	inAPI, outPeer := false, false
	for _, id := range netBound.Inside {
		if id == api.ID {
			inAPI = true
		}
	}
	for _, id := range netBound.Outside {
		if id == peer.ID {
			outPeer = true
		}
	}
	if !inAPI || !outPeer {
		t.Fatalf("boundary inside=%v outside=%v api=%s peer=%s", inAPI, outPeer, api.ID, peer.ID)
	}
	flows := outboundFlows(doc)
	if len(flows) != 1 || len(flows[0].Boundaries) == 0 {
		t.Fatal("flow must cross network boundary")
	}
}

func TestOutboundHTTPLleakSentinels(t *testing.T) {
	uri := "https://" + outboundSentinel + ".example.com/path?q=" + outboundSentinel
	plan := restOutboundPlan(t, []string{"REGIONAL"}, true, []restHTTPInteg{
		{name: "leak", integType: "HTTP_PROXY", uri: uri},
	})
	doc, warnings := parseOutbound(t, plan)
	plain, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, blob := range []string{string(plain), strings.Join(warnings, "\n")} {
		if strings.Contains(blob, outboundSentinel) {
			t.Fatalf("sentinel leaked in output")
		}
	}
	redacted, _, err := Redact(doc, testRedactKey())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	if err := AssertNoPlaintext(raw, []string{outboundSentinel, uri}); err != nil {
		t.Fatal(err)
	}
}

func testRedactKey() []byte {
	return bytes.Repeat([]byte{0xab}, 32)
}

func TestAPIGatewayHTTPIntegrationGoldens(t *testing.T) {
	dir := filepath.Join("testdata", "golden", "api-gateway")
	cases := []struct {
		name   string
		plan   string
		golden string
	}{
		{
			name:   "rest_integration_http",
			golden: "rest-integration-http.dfd.json",
			plan: restOutboundPlan(t, []string{"REGIONAL"}, true, []restHTTPInteg{
				{name: "proxy", integType: "HTTP_PROXY", uri: "https://api.example.com/v1"},
			}),
		},
		{
			name:   "http_integration_proxy",
			golden: "http-integration-proxy.dfd.json",
			plan:   v2HTTPProxyPlan(t, "http://api.example.com/hook", "INTERNET"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, err := Parse([]byte(tc.plan), []byte("schema_version: fray-config/v1\n"), "", Source{
				Repo: "example/api-gw", Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Tool: "terraform", Fidelity: "plan",
			}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			got, err := Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, tc.golden)
			if os.Getenv("UPDATE") != "" {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				_ = os.WriteFile("/tmp/"+tc.golden, got, 0o644)
				t.Fatalf("missing golden (wrote /tmp/%s): %v", tc.golden, err)
			}
			if !bytes.Equal(got, want) {
				_ = os.WriteFile("/tmp/"+tc.golden, got, 0o644)
				t.Fatalf("golden drift %s; wrote /tmp/%s", tc.golden, tc.golden)
			}
		})
	}
}
