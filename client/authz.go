package client

import "slices"

// authzRank orders scopes from narrowest to broadest. Effective authz_scope is
// the maximum rank among authz_grants.
var authzRank = map[string]int{
	"resource":     1,
	"project":      2,
	"account":      3,
	"organization": 4,
	"public":       5,
}

// normalizeAuthzGrants dedupes and sorts scopes narrowest-first. Unknown values
// are dropped. Returns nil when empty so JSON omits the field.
func normalizeAuthzGrants(scopes ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range scopes {
		if authzRank[s] == 0 || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	slices.SortFunc(out, func(a, b string) int {
		return authzRank[a] - authzRank[b]
	})
	return out
}

// effectiveAuthzScope is the broadest grant in scopes, or "".
func effectiveAuthzScope(scopes []string) string {
	best, bestRank := "", 0
	for _, s := range scopes {
		if r := authzRank[s]; r > bestRank {
			best, bestRank = s, r
		}
	}
	return best
}
