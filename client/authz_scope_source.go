package client

import "strings"

const authzScopeSourceDeclared = "declared"

// markAuthzScopeFromConfig records that authz_scope on f came from fray.yaml
// (top-level flows or annotations.flows fill). Call after assigning AuthzScope.
func markAuthzScopeFromConfig(f *Flow) {
	if f == nil || strings.TrimSpace(f.AuthzScope) == "" {
		return
	}
	f.AuthzScopeSource = authzScopeSourceDeclared
}

// redactedAuthzScopeSource keeps only declared on the redacted wire; any other
// value (including derived) is dropped so payloads stay privacy-safe and schema-valid.
func redactedAuthzScopeSource(raw string) string {
	if strings.TrimSpace(raw) == authzScopeSourceDeclared {
		return authzScopeSourceDeclared
	}
	return ""
}
