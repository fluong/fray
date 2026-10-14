package client

import "strings"

// findDataResource looks up a mode=data resource already loaded by
// loadDataResources (resource_changes first, then prior_state — that order is
// preserved in the data slice). typ is the Terraform type without a data.
// prefix (e.g. "aws_subnet"). name is the local resource name from the ref.
//
// Absent attributes on the returned values must be treated as omit by callers
// (never as empty list / false).
func findDataResource(data []planResource, typ, name, ref string) (planResource, bool) {
	if name == "" || typ == "" {
		return planResource{}, false
	}
	var hits []planResource
	for _, r := range data {
		if r.typ != typ {
			continue
		}
		if dataName(r.address) == name {
			hits = append(hits, r)
		}
	}
	if len(hits) == 1 {
		return hits[0], true
	}
	if len(hits) == 0 {
		return planResource{}, false
	}
	for _, h := range hits {
		mod, _, _, _ := splitResourceAddress(normalizeDataAddress(h.address))
		if mod == "" && !strings.Contains(ref, "module.") {
			return h, true
		}
		if mod != "" && strings.Contains(ref, mod+".") {
			return h, true
		}
	}
	return planResource{}, false
}

// normalizeDataAddress strips the data. marker so splitResourceAddress yields
// module/type/name without a data. type prefix.
func normalizeDataAddress(addr string) string {
	normalized := strings.ReplaceAll(addr, ".data.", ".")
	return strings.TrimPrefix(normalized, "data.")
}

// isDataTypeRef reports whether ref names a data.<typ>.* (root or module).
func isDataTypeRef(ref, typ string) bool {
	if typ == "" {
		return false
	}
	needle := "data." + typ + "."
	return strings.Contains(ref, needle) || strings.Contains(ref, "."+needle)
}

// isDataAddress reports whether a plan address is a data source
// (data.* or module.*.data.*).
func isDataAddress(addr string) bool {
	return strings.HasPrefix(addr, "data.") || strings.Contains(addr, ".data.")
}

// findDataResourceByID finds a data source of typ whose values["id"] equals id.
func findDataResourceByID(data []planResource, typ, id string) (planResource, bool) {
	if id == "" {
		return planResource{}, false
	}
	var hit planResource
	found := false
	for _, r := range data {
		if r.typ != typ {
			continue
		}
		if s, _ := r.values["id"].(string); s == id {
			if found {
				return planResource{}, false
			}
			hit, found = r, true
		}
	}
	return hit, found
}
