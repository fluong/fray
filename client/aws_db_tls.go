package client

import (
	"strconv"
	"strings"
)

// dbTLSEnforced reports attributes.tls_enforced for an RDS instance or Aurora
// cluster from its parameter group.
//
// Resolution: planned parameter_group_name / db_cluster_parameter_group_name,
// or a direct configuration reference to a managed aws_db_parameter_group /
// aws_rds_cluster_parameter_group. Data sources, vars/locals, and other
// unresolvable refs omit the attribute.
//
// Parameters: rds.force_ssl (postgres, aurora-postgresql);
// require_secure_transport (mysql, mariadb, aurora-mysql). Values
// 1/ON/on/true → true; 0/OFF/off/false → false.
//
// When the parameter is unset in a custom group, or there is no custom group
// (absent name or default.*):
//
//	postgres on aws_db_instance with major version >= 15 → true; major <= 14 → false.
//	// Source: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html
//	// "The rds.force_ssl parameter default value is 1 (on) for RDS for
//	// PostgreSQL version 15 and later. For all other RDS for PostgreSQL major
//	// versions 14 and older, the default value of this parameter is 0 (off)."
//
// Any other engine, Aurora, or unparseable engine_version → omit.
func dbTLSEnforced(r planResource, resources []planResource, idx configIndex) (enforced bool, known bool) {
	engine, _ := r.values["engine"].(string)
	engine = strings.ToLower(strings.TrimSpace(engine))
	param := tlsParamForEngine(engine)
	if param == "" {
		return false, false
	}
	version, _ := r.values["engine_version"].(string)

	groupAttr, groupType := "parameter_group_name", "aws_db_parameter_group"
	if r.typ == "aws_rds_cluster" {
		groupAttr, groupType = "db_cluster_parameter_group_name", "aws_rds_cluster_parameter_group"
	}

	planned, hasPlanned := r.values[groupAttr].(string)
	planned = strings.TrimSpace(planned)
	unknown := r.attrAfterUnknown(groupAttr)
	refs := idx.attrRefs(r.address, groupAttr)

	switch {
	case hasPlanned && planned != "":
		if isDefaultParamGroupName(planned) {
			return engineTLSDefault(engine, version, r.typ)
		}
		g, ok := findParamGroupByPlannedName(resources, groupType, planned)
		if !ok {
			return false, false
		}
		return paramGroupTLS(g, param, engine, version, r.typ)
	case unknown:
		g, ok := resolveParamGroupFromRefs(refs, resources, groupType)
		if !ok {
			return false, false
		}
		return paramGroupTLS(g, param, engine, version, r.typ)
	default:
		// Absent planned value (not unknown).
		if g, ok := resolveParamGroupFromRefs(refs, resources, groupType); ok {
			return paramGroupTLS(g, param, engine, version, r.typ)
		}
		if len(refs) > 0 {
			// Configured but not a direct managed-group ref.
			return false, false
		}
		return engineTLSDefault(engine, version, r.typ)
	}
}

func tlsParamForEngine(engine string) string {
	switch engine {
	case "postgres", "aurora-postgresql":
		return "rds.force_ssl"
	case "mysql", "mariadb", "aurora-mysql":
		return "require_secure_transport"
	default:
		return ""
	}
}

func isDefaultParamGroupName(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "default.")
}

func resolveParamGroupFromRefs(refs []string, resources []planResource, groupType string) (planResource, bool) {
	var hits []planResource
	seen := map[string]bool{}
	for _, ref := range refs {
		if isIndirectParamGroupRef(ref) {
			continue
		}
		g, ok := findParamGroupFromRef(resources, groupType, ref)
		if !ok {
			continue
		}
		if seen[g.address] {
			continue
		}
		seen[g.address] = true
		hits = append(hits, g)
	}
	if len(hits) == 1 {
		return hits[0], true
	}
	return planResource{}, false
}

func isIndirectParamGroupRef(ref string) bool {
	switch {
	case strings.HasPrefix(ref, "each.") || strings.Contains(ref, ".each."):
		return true
	case strings.HasPrefix(ref, "var.") || strings.Contains(ref, ".var."):
		return true
	case strings.HasPrefix(ref, "local.") || strings.Contains(ref, ".local."):
		return true
	case strings.Contains(ref, "data.aws_db_parameter_group.") || strings.Contains(ref, ".data.aws_db_parameter_group."):
		return true
	case strings.Contains(ref, "data.aws_rds_cluster_parameter_group.") || strings.Contains(ref, ".data.aws_rds_cluster_parameter_group."):
		return true
	default:
		return false
	}
}

func findParamGroupFromRef(resources []planResource, groupType, ref string) (planResource, bool) {
	needle := groupType + "."
	i := strings.Index(ref, needle)
	if i < 0 {
		return planResource{}, false
	}
	if i >= 5 && ref[i-5:i] == "data." {
		return planResource{}, false
	}
	if i >= 6 && strings.HasSuffix(ref[:i], ".data.") {
		return planResource{}, false
	}
	rest := ref[i+len(needle):]
	end := len(rest)
	for j := 0; j < len(rest); j++ {
		if rest[j] == '.' || rest[j] == '[' {
			end = j
			break
		}
	}
	name := rest[:end]
	if name == "" {
		return planResource{}, false
	}
	modHint := ""
	if i > 0 {
		modHint = strings.TrimSuffix(ref[:i], ".")
	}
	var hits []planResource
	for _, r := range resources {
		if r.typ != groupType {
			continue
		}
		_, _, n, ok := splitResourceAddress(r.address)
		if !ok || n != name {
			continue
		}
		hits = append(hits, r)
	}
	if len(hits) == 1 {
		return hits[0], true
	}
	if len(hits) == 0 || modHint == "" {
		return planResource{}, false
	}
	for _, h := range hits {
		mod, _, _, _ := splitResourceAddress(h.address)
		if mod == modHint || strings.HasPrefix(h.address, modHint+".") {
			return h, true
		}
	}
	return planResource{}, false
}

func findParamGroupByPlannedName(resources []planResource, groupType, plannedName string) (planResource, bool) {
	var hits []planResource
	for _, r := range resources {
		if r.typ != groupType {
			continue
		}
		if n, _ := r.values["name"].(string); n == plannedName {
			hits = append(hits, r)
			continue
		}
		if id, _ := r.values["id"].(string); id == plannedName {
			hits = append(hits, r)
		}
	}
	if len(hits) == 1 {
		return hits[0], true
	}
	return planResource{}, false
}

func paramGroupTLS(g planResource, param, engine, version, typ string) (enforced bool, known bool) {
	if v, ok := paramValue(g.values["parameter"], param); ok {
		return parseTLSParamValue(v)
	}
	// Custom group present but parameter unset → engine defaults.
	return engineTLSDefault(engine, version, typ)
}

func paramValue(raw any, name string) (string, bool) {
	for _, item := range asList(raw) {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		n, _ := m["name"].(string)
		if n != name {
			continue
		}
		switch v := m["value"].(type) {
		case string:
			return v, true
		case bool:
			if v {
				return "true", true
			}
			return "false", true
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64), true
		default:
			return "", false
		}
	}
	return "", false
}

func parseTLSParamValue(v string) (enforced bool, known bool) {
	switch strings.TrimSpace(v) {
	case "1", "ON", "on", "true":
		return true, true
	case "0", "OFF", "off", "false":
		return false, true
	default:
		return false, false
	}
}

func engineTLSDefault(engine, version, typ string) (enforced bool, known bool) {
	// Aurora and non-postgres engines have no documented default we rely on.
	if typ != "aws_db_instance" || engine != "postgres" {
		return false, false
	}
	major, ok := postgresMajor(version)
	if !ok {
		return false, false
	}
	if major >= 15 {
		return true, true
	}
	return false, true
}

func postgresMajor(version string) (int, bool) {
	version = strings.TrimSpace(version)
	if version == "" {
		return 0, false
	}
	major := version
	if i := strings.IndexAny(version, "."); i >= 0 {
		major = version[:i]
	}
	n, err := strconv.Atoi(major)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}
