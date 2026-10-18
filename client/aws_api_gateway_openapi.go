package client

import (
	"encoding/json"
	"strings"

	"gopkg.in/yaml.v3"
)

const openapiBodyMaxBytes = 256 << 10

// apiOpenAPIBody returns the planned body string when it is known and non-empty.
func apiOpenAPIBody(api planResource) (raw string, ok bool) {
	if openapiBodyUnknown(api) {
		return "", false
	}
	s, ok := api.values["body"].(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", false
	}
	return s, true
}

func openapiBodyUnknown(api planResource) bool {
	if api.afterUnknown == nil {
		return false
	}
	u, ok := api.afterUnknown["body"]
	if !ok {
		return false
	}
	b, _ := u.(bool)
	return b
}

func restAPIMethods(api planResource, resources []planResource, idx configIndex) []planResource {
	var methods []planResource
	for _, r := range resources {
		if r.typ == "aws_api_gateway_method" && refsAPI(r, idx, "rest_api_id", api) {
			methods = append(methods, r)
		}
	}
	return methods
}

func httpAPIRoutes(api planResource, resources []planResource, idx configIndex) []planResource {
	var routes []planResource
	for _, r := range resources {
		if r.typ == "aws_apigatewayv2_route" && refsAPI(r, idx, "api_id", api) {
			routes = append(routes, r)
		}
	}
	return routes
}

func openAPIEdgeAuthFromBody(apiAddr, raw string, httpV2 bool) (scope, cause string, ok bool) {
	if len(raw) > openapiBodyMaxBytes {
		return "", "", false
	}
	doc, ok := parseOpenAPIDocument(raw)
	if !ok {
		return "", "", false
	}
	auths, ok := collectOpenAPIOperationAuths(doc, httpV2)
	if !ok || len(auths) == 0 {
		return "", "", false
	}
	scope, cause, ok = aggregateAuthorizationAuths(auths)
	if ok && scope == "public" && cause == "" {
		cause = apiAddr
	}
	return scope, cause, ok
}

func aggregateAuthorizationAuths(auths []string) (scope, cause string, ok bool) {
	hasNone, hasIdentity, hasCustom, hasUnknown := false, false, false, false
	noneCause := ""
	for _, auth := range auths {
		switch strings.ToUpper(auth) {
		case "NONE", "":
			hasNone = true
		case "AWS_IAM", "COGNITO_USER_POOLS", "JWT", "API_KEY":
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

func parseOpenAPIDocument(raw string) (map[string]any, bool) {
	trim := strings.TrimSpace(raw)
	if trim == "" {
		return nil, false
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(trim), &doc); err == nil {
		return doc, true
	}
	if yamlDocumentHasAnchors(trim) {
		return nil, false
	}
	if err := yaml.Unmarshal([]byte(trim), &doc); err != nil {
		return nil, false
	}
	return doc, true
}

func yamlDocumentHasAnchors(raw string) bool {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &node); err != nil {
		return false
	}
	return yamlNodeUsesAlias(&node)
}

func yamlNodeUsesAlias(n *yaml.Node) bool {
	if n == nil {
		return false
	}
	if n.Kind == yaml.AliasNode {
		return true
	}
	for i := range n.Content {
		if yamlNodeUsesAlias(n.Content[i]) {
			return true
		}
	}
	return false
}

func collectOpenAPIOperationAuths(doc map[string]any, httpV2 bool) ([]string, bool) {
	oas2 := stringAttr(doc["swagger"]) == "2.0"
	globalSec, _ := asSecurityList(doc["security"])
	paths, _ := doc["paths"].(map[string]any)
	if paths == nil {
		return nil, false
	}
	var auths []string
	for pathKey, pathItemRaw := range paths {
		_ = pathKey
		pathItem, ok := pathItemRaw.(map[string]any)
		if !ok {
			continue
		}
		for method, opRaw := range pathItem {
			if !isOpenAPIOperationKey(method) {
				continue
			}
			op, ok := opRaw.(map[string]any)
			if !ok {
				return nil, false
			}
			sec := globalSec
			if _, defined := op["security"]; defined {
				sec, _ = asSecurityList(op["security"])
			} else if _, defined := pathItem["security"]; defined {
				sec, _ = asSecurityList(pathItem["security"])
			}
			auth, ok := operationOpenAPIAuth(doc, op, sec, oas2, httpV2)
			if !ok {
				return nil, false
			}
			auths = append(auths, auth)
		}
	}
	return auths, true
}

func isOpenAPIOperationKey(k string) bool {
	switch strings.ToLower(k) {
	case "get", "put", "post", "delete", "options", "head", "patch", "trace",
		"x-amazon-apigateway-any-method":
		return true
	default:
		return false
	}
}

func operationOpenAPIAuth(doc, op map[string]any, sec []any, oas2, httpV2 bool) (string, bool) {
	if ext, ok := op["x-amazon-apigateway-auth"].(map[string]any); ok {
		class := legacyAmazonAuthType(ext["type"])
		if class == "UNKNOWN" {
			return "", false
		}
		return class, true
	}
	if apiKey, ok := op["x-amazon-apigateway-api-key-required"].(bool); ok && apiKey {
		return "API_KEY", true
	}
	if sec != nil && len(sec) == 0 {
		return "NONE", true
	}
	if len(sec) == 0 {
		return "NONE", true
	}
	return securityAlternativesAuth(doc, sec, oas2, httpV2)
}

func securityAlternativesAuth(doc map[string]any, sec []any, oas2, httpV2 bool) (string, bool) {
	anyNone := false
	anyIdentity := false
	for _, altRaw := range sec {
		alt, ok := altRaw.(map[string]any)
		if !ok {
			return "", false
		}
		class, ok := securityRequirementAuth(doc, alt, oas2, httpV2)
		if !ok {
			return "", false
		}
		switch class {
		case "NONE":
			anyNone = true
		case "AWS_IAM", "COGNITO_USER_POOLS", "JWT", "API_KEY":
			anyIdentity = true
		default:
			return "", false
		}
	}
	if anyNone {
		return "NONE", true
	}
	if anyIdentity {
		return "AWS_IAM", true
	}
	return "NONE", true
}

func securityRequirementAuth(doc map[string]any, req map[string]any, oas2, httpV2 bool) (string, bool) {
	if len(req) == 0 {
		return "NONE", true
	}
	hasIdentity := false
	for name := range req {
		if strings.HasPrefix(name, "$") {
			return "", false
		}
		class, ok := resolveNamedSecurityScheme(doc, name, oas2, httpV2)
		if !ok {
			return "", false
		}
		switch class {
		case "NONE":
			// AND group cannot include explicit NONE scheme name.
			return "", false
		case "AWS_IAM", "COGNITO_USER_POOLS", "JWT", "API_KEY":
			hasIdentity = true
		default:
			return "", false
		}
	}
	if hasIdentity {
		return "AWS_IAM", true
	}
	return "NONE", true
}

func resolveNamedSecurityScheme(doc map[string]any, name string, oas2, httpV2 bool) (string, bool) {
	scheme, ok := lookupSecurityScheme(doc, name, oas2)
	if !ok {
		return "", false
	}
	if ref, is := scheme["$ref"].(string); is {
		if !strings.HasPrefix(ref, "#/") {
			return "", false
		}
		resolved, ok := resolveInternalRef(doc, ref)
		if !ok {
			return "", false
		}
		scheme, ok = resolved.(map[string]any)
		if !ok {
			return "", false
		}
	}
	return classifySecurityScheme(scheme, httpV2)
}

func lookupSecurityScheme(doc map[string]any, name string, oas2 bool) (map[string]any, bool) {
	if oas2 {
		defs, ok := doc["securityDefinitions"].(map[string]any)
		if !ok {
			return nil, false
		}
		raw, ok := defs[name]
		if !ok {
			return nil, false
		}
		scheme, ok := raw.(map[string]any)
		return scheme, ok
	}
	comp, ok := doc["components"].(map[string]any)
	if !ok {
		return nil, false
	}
	schemes, ok := comp["securitySchemes"].(map[string]any)
	if !ok {
		return nil, false
	}
	raw, ok := schemes[name]
	if !ok {
		return nil, false
	}
	scheme, ok := raw.(map[string]any)
	return scheme, ok
}

func resolveInternalRef(doc map[string]any, ref string) (any, bool) {
	ref = strings.TrimPrefix(ref, "#/")
	parts := strings.Split(ref, "/")
	var cur any = doc
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func classifySecurityScheme(scheme map[string]any, httpV2 bool) (string, bool) {
	if authz, ok := scheme["x-amazon-apigateway-authorizer"].(map[string]any); ok {
		switch strings.ToLower(stringAttr(authz["type"])) {
		case "jwt":
			return "JWT", true
		case "request", "token":
			return "CUSTOM", true
		case "cognito_user_pools":
			return "COGNITO_USER_POOLS", true
		default:
			return "", false
		}
	}
	authtype := strings.ToLower(stringAttr(scheme["x-amazon-apigateway-authtype"]))
	switch authtype {
	case "awssigv4", "aws_sigv4":
		return "AWS_IAM", true
	case "cognito_user_pools":
		return "COGNITO_USER_POOLS", true
	case "custom":
		return "CUSTOM", true
	case "":
		// fall through
	default:
		if strings.HasPrefix(authtype, "aws") {
			return "AWS_IAM", true
		}
		if authtype != "" {
			return "CUSTOM", true
		}
	}
	typ := strings.ToLower(stringAttr(scheme["type"]))
	switch typ {
	case "oauth2":
		if httpV2 && strings.EqualFold(stringAttr(scheme["scheme"]), "aws_iam") {
			return "AWS_IAM", true
		}
		return "", false
	case "apikey", "api_key":
		if authtype == "" {
			return "API_KEY", true
		}
		return "", false
	default:
		return "", false
	}
}

func legacyAmazonAuthType(v any) string {
	switch strings.ToUpper(stringAttr(v)) {
	case "NONE":
		return "NONE"
	case "AWS_IAM":
		return "AWS_IAM"
	case "COGNITO_USER_POOLS":
		return "COGNITO_USER_POOLS"
	case "CUSTOM":
		return "CUSTOM"
	default:
		return "UNKNOWN"
	}
}

func asSecurityList(v any) ([]any, bool) {
	if v == nil {
		return nil, false
	}
	list, ok := v.([]any)
	return list, ok
}
