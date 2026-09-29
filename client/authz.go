package client

import (
	"encoding/json"
	"slices"
	"strings"
)

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

const (
	cfR2BucketResourcePrefix  = "com.cloudflare.edge.r2.bucket."
	cfAccountResourcePrefix   = "com.cloudflare.api.account."
)

// r2TokenAuthz derives service→R2 authz from cloudflare_api_token (or
// cloudflare_account_token) policies in the plan. Bucket-scoped resource keys
// → resource; account-wide keys → account. ok is false when no token is present
// or no R2/account resources are parseable.
func r2TokenAuthz(resources []planResource) (scope string, grants []string, cause string, ok bool) {
	var scopes []string
	causeByScope := map[string]string{}
	for _, r := range resources {
		if r.typ != "cloudflare_api_token" && r.typ != "cloudflare_account_token" {
			continue
		}
		for _, s := range tokenPolicyScopes(r.values) {
			scopes = append(scopes, s)
			if causeByScope[s] == "" {
				causeByScope[s] = r.address
			}
		}
	}
	grants = normalizeAuthzGrants(scopes...)
	scope = effectiveAuthzScope(grants)
	if scope == "" {
		return "", nil, "", false
	}
	return scope, grants, causeByScope[scope], true
}

func tokenPolicyScopes(values map[string]any) []string {
	raw, ok := values["policies"]
	if !ok {
		return nil
	}
	var scopes []string
	for _, p := range asList(raw) {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if effect, _ := pm["effect"].(string); effect != "" && !strings.EqualFold(effect, "allow") {
			continue
		}
		for _, key := range policyResourceKeys(pm["resources"]) {
			switch {
			case strings.HasPrefix(key, cfAccountResourcePrefix):
				scopes = append(scopes, "account")
			case strings.HasPrefix(key, cfR2BucketResourcePrefix):
				scopes = append(scopes, "resource")
			}
		}
	}
	return scopes
}

func policyResourceKeys(raw any) []string {
	switch v := raw.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		return keys
	case string:
		if v == "" {
			return nil
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			return nil
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		return keys
	default:
		return nil
	}
}
