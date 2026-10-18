package client

import (
	"slices"
	"strings"
)

// WireProviderSubtypes are the only provider_subtype values emitted on redacted
// DFDs (schema element_redacted enum). FR-043 uses memcached to skip Redis-only
// at-rest checks; FR-051 scopes rules to REST APIs via rest_api.
var WireProviderSubtypes = []string{"redis", "valkey", "memcached", "rest_api"}

func redactedProviderSubtype(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if slices.Contains(WireProviderSubtypes, s) {
		return s
	}
	return ""
}
