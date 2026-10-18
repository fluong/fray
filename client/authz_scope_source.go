package client

import "strings"

const authzScopeSourceDeclared = "declared"

// redactedAuthzScopeSource keeps only declared on the redacted wire; any other
// value (including derived) is dropped so payloads stay privacy-safe and schema-valid.
func redactedAuthzScopeSource(raw string) string {
	if strings.TrimSpace(raw) == authzScopeSourceDeclared {
		return authzScopeSourceDeclared
	}
	return ""
}
