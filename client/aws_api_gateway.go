package client

import (
	"strings"
)

// API Gateway (REST v1 / HTTP·WebSocket v2) and Lambda function URL internet
// entries. Mirrors the ALB path: inferred public_client → edge flow → network
// boundary, plus entry → backend integration flows.
//
// Known limitation: a REST API with a resource policy (policy attribute set) is
// treated like an unresolved ALB security group — exposure is unknown, so no
// entry flow is emitted. Parsing resource policies for internet reachability is
// out of scope.

func awsAPIGatewayElement(r planResource) *Element {
	name, _ := r.values["name"].(string)
	attrs := map[string]any{"public": true}
	return &Element{
		Name: DisplayName(r.address, name, "api_gateway"), Type: "process", Kind: "api_gateway", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

func awsLambdaFunctionElement(r planResource) *Element {
	name, _ := r.values["function_name"].(string)
	return &Element{
		Name: DisplayName(r.address, name, "serverless_function"), Type: "process", Kind: "serverless_function", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
	}
}

// awsAPIEntries appends public_client edge flows and backend flows for REST,
// HTTP/WebSocket APIs, and Lambda function URLs. public may be nil; a new
// inferred public_client is created on first entry.
func awsAPIEntries(
	resources []planResource,
	idx configIndex,
	byAddr map[string]*Element,
	public **Element,
	extra *[]*Element,
	addInside func(*Element),
) (flows []*Flow, warnings []string) {
	ensurePublic := func() *Element {
		if *public != nil {
			return *public
		}
		el := &Element{
			Name: "Public client", Type: "external_entity", Kind: "public_client",
			Provenance: "inferred",
			Evidence:   Evidence{Signals: []Signal{{Type: "network_ingress", Name: "0.0.0.0/0"}}},
		}
		*extra = append(*extra, el)
		*public = el
		return el
	}
	ensureLambda := func(fn planResource) *Element {
		if el := byAddr[fn.address]; el != nil {
			return el
		}
		el := awsLambdaFunctionElement(fn)
		*extra = append(*extra, el)
		byAddr[fn.address] = el
		return el
	}

	for _, api := range resources {
		if api.typ != "aws_api_gateway_rest_api" {
			continue
		}
		if !restAPIInternetEntry(api, resources, idx) {
			continue
		}
		apiEl := byAddr[api.address]
		if apiEl == nil {
			continue
		}
		pub := ensurePublic()
		flow := &Flow{
			From: pub.canonicalKey(), To: apiEl.canonicalKey(),
			DataClass: "unknown", Transport: "tls",
		}
		if scope, cause, ok := restAPIEdgeAuth(api, resources, idx); ok {
			flow.AuthzScope = scope
			flow.AuthzGrants = normalizeAuthzGrants(scope)
			if cause != "" {
				flow.Causes = map[string]string{"authz_scope": cause}
			}
		}
		flows = append(flows, flow)
		addInside(apiEl)
		for _, f := range restAPIBackendFlows(api, apiEl, resources, idx, byAddr, ensureLambda, &warnings) {
			flows = append(flows, f)
			if to := byAddrElement(byAddr, f.To); to != nil {
				addInside(to)
			}
		}
	}

	for _, api := range resources {
		if api.typ != "aws_apigatewayv2_api" {
			continue
		}
		if !httpAPIInternetEntry(api) {
			continue
		}
		apiEl := byAddr[api.address]
		if apiEl == nil {
			continue
		}
		pub := ensurePublic()
		flow := &Flow{
			From: pub.canonicalKey(), To: apiEl.canonicalKey(),
			DataClass: "unknown", Transport: "tls",
		}
		if scope, cause, ok := httpAPIEdgeAuth(api, resources, idx); ok {
			flow.AuthzScope = scope
			flow.AuthzGrants = normalizeAuthzGrants(scope)
			if cause != "" {
				flow.Causes = map[string]string{"authz_scope": cause}
			}
		}
		flows = append(flows, flow)
		addInside(apiEl)
		for _, f := range httpAPIBackendFlows(api, apiEl, resources, idx, byAddr, ensureLambda, &warnings) {
			flows = append(flows, f)
			if to := byAddrElement(byAddr, f.To); to != nil {
				addInside(to)
			}
		}
	}

	for _, url := range resources {
		if url.typ != "aws_lambda_function_url" {
			continue
		}
		fn, ok := resolveLambdaFromURL(url, resources, idx)
		if !ok {
			warnings = append(warnings, "unresolved function for "+url.address)
			continue
		}
		fnEl := ensureLambda(fn)
		pub := ensurePublic()
		flow := &Flow{
			From: pub.canonicalKey(), To: fnEl.canonicalKey(),
			DataClass: "unknown", Transport: "tls",
		}
		switch strings.ToUpper(stringAttr(url.values["authorization_type"])) {
		case "NONE":
			flow.AuthzScope = "public"
			flow.AuthzGrants = normalizeAuthzGrants("public")
			flow.Causes = map[string]string{"authz_scope": url.address}
		case "AWS_IAM":
			flow.AuthzScope = "authenticated"
			flow.AuthzGrants = normalizeAuthzGrants("authenticated")
			flow.Causes = map[string]string{"authz_scope": url.address}
		}
		flows = append(flows, flow)
		addInside(fnEl)
	}
	return flows, warnings
}

func byAddrElement(byAddr map[string]*Element, canonicalOrAddr string) *Element {
	for _, el := range byAddr {
		if el.canonicalKey() == canonicalOrAddr {
			return el
		}
	}
	return nil
}

// restAPIInternetEntry is true for EDGE/REGIONAL APIs that have a stage (or
// deployment with stage_name) and no resource policy. A set policy means
// exposure is unknown — same fail-closed stance as an unresolved ALB SG.
func restAPIInternetEntry(api planResource, resources []planResource, idx configIndex) bool {
	if restAPIHasPolicy(api) {
		return false
	}
	if !restAPIHasPublicEndpointType(api) {
		return false
	}
	return restAPIHasStage(api, resources, idx)
}

func restAPIHasPolicy(api planResource) bool {
	raw, ok := api.values["policy"]
	if !ok || raw == nil {
		return false
	}
	if s, is := raw.(string); is {
		return strings.TrimSpace(s) != ""
	}
	return true
}

func restAPIHasPublicEndpointType(api planResource) bool {
	for _, t := range restAPIEndpointTypes(api) {
		if t == "EDGE" || t == "REGIONAL" {
			return true
		}
	}
	return false
}

func restAPIEndpointTypes(api planResource) []string {
	var out []string
	for _, block := range asList(api.values["endpoint_configuration"]) {
		m, ok := block.(map[string]any)
		if !ok {
			continue
		}
		for _, t := range asList(m["types"]) {
			if s, ok := t.(string); ok && s != "" {
				out = append(out, strings.ToUpper(s))
			}
		}
	}
	return out
}

func restAPIHasStage(api planResource, resources []planResource, idx configIndex) bool {
	for _, r := range resources {
		switch r.typ {
		case "aws_api_gateway_stage":
			if refsAPI(r, idx, "rest_api_id", api) {
				return true
			}
		case "aws_api_gateway_deployment":
			if refsAPI(r, idx, "rest_api_id", api) && stringAttr(r.values["stage_name"]) != "" {
				return true
			}
		}
	}
	return false
}

func httpAPIInternetEntry(api planResource) bool {
	if v, ok := api.values["disable_execute_api_endpoint"].(bool); ok && v {
		return false
	}
	return true
}

func restAPIHasOpenAPIBody(api planResource) bool {
	s, ok := api.values["body"].(string)
	return ok && strings.TrimSpace(s) != ""
}

func httpAPIHasOpenAPIBody(api planResource) bool {
	s, ok := api.values["body"].(string)
	return ok && strings.TrimSpace(s) != ""
}

// restAPIEdgeAuth returns the edge authz_scope. ok is false when the scope
// must be omitted (CUSTOM, OpenAPI body, undeterminable methods).
func restAPIEdgeAuth(api planResource, resources []planResource, idx configIndex) (scope, cause string, ok bool) {
	if restAPIHasOpenAPIBody(api) {
		return "", "", false
	}
	var methods []planResource
	for _, r := range resources {
		if r.typ == "aws_api_gateway_method" && refsAPI(r, idx, "rest_api_id", api) {
			methods = append(methods, r)
		}
	}
	if len(methods) == 0 {
		return "", "", false
	}
	return aggregateMethodAuth(methods)
}

func httpAPIEdgeAuth(api planResource, resources []planResource, idx configIndex) (scope, cause string, ok bool) {
	if httpAPIHasOpenAPIBody(api) {
		return "", "", false
	}
	var routes []planResource
	for _, r := range resources {
		if r.typ == "aws_apigatewayv2_route" && refsAPI(r, idx, "api_id", api) {
			routes = append(routes, r)
		}
	}
	if len(routes) == 0 {
		return "", "", false
	}
	return aggregateRouteAuth(routes)
}

func aggregateMethodAuth(methods []planResource) (scope, cause string, ok bool) {
	hasNone, hasIdentity, hasCustom, hasUnknown := false, false, false, false
	noneCause := ""
	for _, m := range methods {
		auth := strings.ToUpper(stringAttr(m.values["authorization"]))
		switch auth {
		case "NONE", "":
			// Empty authorization defaults to NONE in the AWS provider.
			hasNone = true
			if noneCause == "" {
				noneCause = m.address
			}
		case "AWS_IAM", "COGNITO_USER_POOLS":
			hasIdentity = true
		case "CUSTOM":
			hasCustom = true
		default:
			hasUnknown = true
		}
	}
	if hasNone {
		return "public", noneCause, true
	}
	if hasCustom || hasUnknown {
		return "", "", false
	}
	if hasIdentity {
		return "authenticated", "", true
	}
	return "", "", false
}

func aggregateRouteAuth(routes []planResource) (scope, cause string, ok bool) {
	hasNone, hasIdentity, hasCustom, hasUnknown := false, false, false, false
	noneCause := ""
	for _, r := range routes {
		auth := strings.ToUpper(stringAttr(r.values["authorization_type"]))
		switch auth {
		case "NONE", "":
			hasNone = true
			if noneCause == "" {
				noneCause = r.address
			}
		case "AWS_IAM", "JWT":
			hasIdentity = true
		case "CUSTOM":
			hasCustom = true
		default:
			hasUnknown = true
		}
	}
	if hasNone {
		return "public", noneCause, true
	}
	if hasCustom || hasUnknown {
		return "", "", false
	}
	if hasIdentity {
		return "authenticated", "", true
	}
	return "", "", false
}

func restAPIBackendFlows(
	api planResource, apiEl *Element, resources []planResource, idx configIndex,
	byAddr map[string]*Element, ensureLambda func(planResource) *Element, warnings *[]string,
) []*Flow {
	var flows []*Flow
	seen := map[string]bool{}
	for _, integ := range resources {
		if integ.typ != "aws_api_gateway_integration" || !refsAPI(integ, idx, "rest_api_id", api) {
			continue
		}
		f, ok := integrationBackendFlow(apiEl, integ, resources, idx, byAddr, ensureLambda, warnings)
		if !ok {
			continue
		}
		key := f.From + "\n" + f.To + "\n" + f.Transport
		if seen[key] {
			continue
		}
		seen[key] = true
		flows = append(flows, f)
	}
	return flows
}

func httpAPIBackendFlows(
	api planResource, apiEl *Element, resources []planResource, idx configIndex,
	byAddr map[string]*Element, ensureLambda func(planResource) *Element, warnings *[]string,
) []*Flow {
	var flows []*Flow
	seen := map[string]bool{}
	for _, integ := range resources {
		if integ.typ != "aws_apigatewayv2_integration" || !refsAPI(integ, idx, "api_id", api) {
			continue
		}
		f, ok := integrationBackendFlow(apiEl, integ, resources, idx, byAddr, ensureLambda, warnings)
		if !ok {
			continue
		}
		key := f.From + "\n" + f.To + "\n" + f.Transport
		if seen[key] {
			continue
		}
		seen[key] = true
		flows = append(flows, f)
	}
	return flows
}

func integrationBackendFlow(
	apiEl *Element, integ planResource, resources []planResource, idx configIndex,
	byAddr map[string]*Element, ensureLambda func(planResource) *Element, warnings *[]string,
) (*Flow, bool) {
	transport, kind := integrationTransport(integ)
	switch kind {
	case "lambda":
		fn, ok := resolveLambdaFromIntegration(integ, resources, idx)
		if !ok {
			*warnings = append(*warnings, "unresolved Lambda integration on "+integ.address)
			return nil, false
		}
		fnEl := ensureLambda(fn)
		return &Flow{
			From: apiEl.canonicalKey(), To: fnEl.canonicalKey(),
			DataClass: "unknown", Transport: transport,
		}, true
	case "http", "vpc_link":
		// HTTP URLs and VPC links are not modeled as DFD elements in this
		// change — no peer → no backend flow (transport classification is
		// covered by integrationTransport unit tests).
		return nil, false
	default:
		return nil, false
	}
}

// integrationTransport classifies an API Gateway integration.
// kind is "lambda", "http", "vpc_link", or "".
func integrationTransport(integ planResource) (transport, kind string) {
	typ := strings.ToUpper(stringAttr(integ.values["integration_type"]))
	if typ == "" {
		typ = strings.ToUpper(stringAttr(integ.values["type"]))
	}
	conn := strings.ToUpper(stringAttr(integ.values["connection_type"]))
	if conn == "VPC_LINK" || typ == "VPC_LINK" {
		return "unknown", "vpc_link"
	}
	switch typ {
	case "AWS", "AWS_PROXY":
		return "tls", "lambda"
	case "HTTP", "HTTP_PROXY":
		uri := stringAttr(integ.values["uri"])
		if uri == "" {
			uri = stringAttr(integ.values["integration_uri"])
		}
		return httpURITransport(uri), "http"
	default:
		return "", ""
	}
}

func httpURITransport(uri string) string {
	u := strings.ToLower(strings.TrimSpace(uri))
	switch {
	case strings.HasPrefix(u, "https://"):
		return "tls"
	case strings.HasPrefix(u, "http://"):
		return "plaintext"
	default:
		return ""
	}
}

func refsAPI(r planResource, idx configIndex, attr string, api planResource) bool {
	_, _, name, ok := splitResourceAddress(api.address)
	if !ok {
		return false
	}
	for _, ref := range idx.attrRefs(r.address, attr) {
		if containsResource(ref, api.typ, name) {
			return true
		}
	}
	return false
}

func resolveLambdaFromURL(url planResource, resources []planResource, idx configIndex) (planResource, bool) {
	for _, ref := range idx.attrRefs(url.address, "function_name") {
		if fn, ok := findLambdaByRef(ref, resources); ok {
			return fn, true
		}
	}
	name := stringAttr(url.values["function_name"])
	if name == "" {
		return planResource{}, false
	}
	return findLambdaByNameOrARN(name, resources)
}

func resolveLambdaFromIntegration(integ planResource, resources []planResource, idx configIndex) (planResource, bool) {
	for _, attr := range []string{"uri", "integration_uri"} {
		for _, ref := range idx.attrRefs(integ.address, attr) {
			if fn, ok := findLambdaByRef(ref, resources); ok {
				return fn, true
			}
		}
	}
	uri := stringAttr(integ.values["uri"])
	if uri == "" {
		uri = stringAttr(integ.values["integration_uri"])
	}
	if fn, ok := findLambdaByNameOrARN(uri, resources); ok {
		return fn, true
	}
	return planResource{}, false
}

func findLambdaByRef(ref string, resources []planResource) (planResource, bool) {
	for _, r := range resources {
		if r.typ != "aws_lambda_function" {
			continue
		}
		_, _, name, ok := splitResourceAddress(r.address)
		if !ok {
			continue
		}
		if containsResource(ref, "aws_lambda_function", name) {
			return r, true
		}
	}
	return planResource{}, false
}

func findLambdaByNameOrARN(nameOrARN string, resources []planResource) (planResource, bool) {
	needle := nameOrARN
	if i := strings.Index(needle, ":function:"); i >= 0 {
		rest := needle[i+len(":function:"):]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			rest = rest[:j]
		}
		needle = rest
	}
	var hits []planResource
	for _, r := range resources {
		if r.typ != "aws_lambda_function" {
			continue
		}
		fn, _ := r.values["function_name"].(string)
		if fn == needle || r.address == needle || strings.HasSuffix(r.address, "."+needle) {
			hits = append(hits, r)
		}
	}
	if len(hits) == 1 {
		return hits[0], true
	}
	return planResource{}, false
}
