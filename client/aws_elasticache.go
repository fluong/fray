package client

import "strings"

func awsElastiCacheElements(resources, data []planResource, idx configIndex, warnings *[]string) []*Element {
	memberClusters := elasticacheMemberClusters(resources, idx)
	var out []*Element
	for _, r := range resources {
		switch r.typ {
		case "aws_elasticache_replication_group":
			out = append(out, awsElastiCacheReplicationGroupElement(r, resources, data, idx))
		case "aws_elasticache_cluster":
			if memberClusters[r.address] {
				continue
			}
			out = append(out, awsElastiCacheClusterElement(r, resources, data, idx))
		}
	}
	return out
}

func elasticacheMemberClusters(resources []planResource, idx configIndex) map[string]bool {
	out := map[string]bool{}
	for _, r := range resources {
		if r.typ != "aws_elasticache_cluster" {
			continue
		}
		if elasticacheClusterIsMember(r, idx) {
			out[r.address] = true
		}
	}
	return out
}

func elasticacheClusterIsMember(r planResource, idx configIndex) bool {
	if v, ok := r.values["replication_group_id"].(string); ok && strings.TrimSpace(v) != "" {
		return true
	}
	for _, ref := range idx.attrRefs(r.address, "replication_group_id") {
		if strings.TrimSpace(ref) != "" {
			return true
		}
	}
	return false
}

func awsElastiCacheReplicationGroupElement(r planResource, resources, data []planResource, idx configIndex) *Element {
	name, _ := r.values["replication_group_id"].(string)
	engine := elasticacheEngine(r)
	attrs := elasticacheAttrs(r, resources, data, idx, engine)
	return &Element{
		Name: DisplayName(r.address, name, "cache"), Type: "datastore", Kind: "cache", Provider: "aws",
		ProviderSubtype: engine,
		Provenance:      "iac",
		Evidence:        Evidence{Addresses: []string{r.address}},
		Attributes:      attrs,
	}
}

func awsElastiCacheClusterElement(r planResource, resources, data []planResource, idx configIndex) *Element {
	name, _ := r.values["cluster_id"].(string)
	engine := elasticacheEngine(r)
	attrs := elasticacheAttrs(r, resources, data, idx, engine)
	return &Element{
		Name: DisplayName(r.address, name, "cache"), Type: "datastore", Kind: "cache", Provider: "aws",
		ProviderSubtype: engine,
		Provenance:      "iac",
		Evidence:        Evidence{Addresses: []string{r.address}},
		Attributes:      attrs,
	}
}

func elasticacheAttrs(r planResource, resources, data []planResource, idx configIndex, engine string) map[string]any {
	attrs := map[string]any{}
	if restricted, ok := cacheNetworkRestricted(r, resources, data, idx, engine); ok {
		attrs["network_restricted"] = restricted
	}
	if !attrUnknownMap(r.afterUnknown, "transit_encryption_enabled") {
		if v, ok := asBoolish(r.values["transit_encryption_enabled"]); ok {
			attrs["tls_enforced"] = v
		}
	}
	if engineAllowsAtRest(engine) && !attrUnknownMap(r.afterUnknown, "at_rest_encryption_enabled") {
		if v, ok := asBoolish(r.values["at_rest_encryption_enabled"]); ok {
			attrs["encrypted_at_rest"] = v
		}
	}
	return attrs
}

func elasticacheEngine(r planResource) string {
	if e, ok := r.values["engine"].(string); ok {
		return strings.ToLower(strings.TrimSpace(e))
	}
	return ""
}

func engineAllowsAtRest(engine string) bool {
	switch engine {
	case "redis", "valkey":
		return true
	default:
		return false
	}
}

func cacheListenPort(engine string, values map[string]any) (port int, known bool) {
	if n, ok := number(values["port"]); ok {
		return int(n), true
	}
	switch strings.ToLower(engine) {
	case "memcached":
		return 11211, true
	case "redis", "valkey":
		return 6379, true
	default:
		return 0, false
	}
}

// cacheNetworkRestricted uses the same ingress classifier as relational_db.
func cacheNetworkRestricted(r planResource, resources, data []planResource, idx configIndex, engine string) (restricted bool, known bool) {
	sgs, ok := resolveCacheSecurityGroups(r, resources, data, idx)
	if !ok || len(sgs) == 0 {
		return false, false
	}
	port, portKnown := cacheListenPort(engine, r.values)
	sawRestricted := false
	for _, sg := range sgs {
		cls, coversWorld := classifySGIngress(sg, resources, idx, port, portKnown)
		switch {
		case coversWorld:
			return false, true
		case cls == netSrcUnknown:
			return false, false
		case cls == netSrcRestricted:
			sawRestricted = true
		}
	}
	if !sawRestricted {
		return false, false
	}
	return true, true
}

func resolveCacheSecurityGroups(r planResource, resources, data []planResource, idx configIndex) ([]planResource, bool) {
	refs := cacheSecurityGroupRefs(r, idx)
	if len(refs) == 0 {
		return nil, false
	}
	var out []planResource
	seen := map[string]bool{}
	for _, ref := range refs {
		if isVarRef(ref) {
			continue
		}
		sg, ok, skip := resolveSecurityGroupRefDetailed(ref, resources, data, idx)
		if skip {
			continue
		}
		if !ok {
			return nil, false
		}
		if seen[sg.address] {
			continue
		}
		seen[sg.address] = true
		out = append(out, sg)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func cacheSecurityGroupRefs(r planResource, idx configIndex) []string {
	var refs []string
	refs = append(refs, idx.attrRefs(r.address, "security_group_ids")...)
	if v, ok := r.values["security_group_ids"].([]any); ok {
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				refs = append(refs, s)
			}
		}
	}
	return uniqueStrings(refs)
}
