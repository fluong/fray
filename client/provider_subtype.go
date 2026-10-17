package client

import (
	"slices"
	"strings"
)

// WireProviderSubtypes are the only provider_subtype values emitted on redacted
// DFDs (schema element_redacted enum). FR-043 uses memcached to skip Redis-only
// at-rest checks.
var WireProviderSubtypes = []string{"redis", "valkey", "memcached"}

func redactedProviderSubtype(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if slices.Contains(WireProviderSubtypes, s) {
		return s
	}
	return ""
}
