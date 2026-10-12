package client

import (
	"strconv"
	"strings"
)

const maxParamGroupDepth = 3

// dbTLSEnforced reports attributes.tls_enforced for an RDS instance or Aurora
// cluster from its parameter group.
//
// Resolution: planned parameter_group_name / db_cluster_parameter_group_name,
// or configuration references followed through module input variables, locals,
// and conditional/try() wrappers (depth ≤ 3) to exactly one managed
// aws_db_parameter_group / aws_rds_cluster_parameter_group. A literal
// default.* in another branch is a second candidate unless create/count is
// statically known. Data sources and other unresolvable refs omit the attribute.
//
// Parameters: rds.force_ssl (postgres, aurora-postgresql);
// require_secure_transport (mysql, mariadb, aurora-mysql). Values
// 1/ON/on/true → true; 0/OFF/off/false → false.
//
// When the parameter is unset in a custom group, or there is no custom group
// (absent name or default.*):
//
//	postgres on aws_db_instance with major version >= 15 → true; major <= 14 → false.
//	// Source: https://docs.aws.amazon.com/AmazonRDS/Latest/UserGuide/PostgreSQL.Concepts.General.SSL.html
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
		g, def, ok := resolveParamGroupBinding(r, resources, idx, groupAttr, groupType)
		if !ok {
			return false, false
		}
		if def != "" {
			return engineTLSDefault(engine, version, r.typ)
		}
		return paramGroupTLS(g, param, engine, version, r.typ)
	default:
		// Absent planned value (not unknown).
		g, def, ok := resolveParamGroupBinding(r, resources, idx, groupAttr, groupType)
		if ok {
			if def != "" {
				return engineTLSDefault(engine, version, r.typ)
			}
			return paramGroupTLS(g, param, engine, version, r.typ)
		}
		if len(refs) > 0 {
			// Configured but not resolvable to a managed group or default.*.
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

// paramGroupCand is one candidate from following configuration expressions.
type paramGroupCand struct {
	group    *planResource
	defName  string // literal default.* name
	external bool   // non-default unresolved/external name branch
}

// resolveParamGroupBinding follows refs through vars/locals/try up to depth 3
// and returns either exactly one managed group or a default.* name.
func resolveParamGroupBinding(r planResource, resources []planResource, idx configIndex, groupAttr, groupType string) (planResource, string, bool) {
	mod, _, _, _ := splitResourceAddress(r.address)
	refs := idx.attrRefs(r.address, groupAttr)
	var constNames []string
	if key, ok := resourceKey(r.address); ok {
		if cv, ok := idx.resources[key].constants[groupAttr].(string); ok {
			constNames = append(constNames, cv)
		}
	}
	cands := collectParamGroupCands(refs, constNames, mod, resources, idx, groupType, 0)
	return pickParamGroupCand(cands, mod, idx, groupType)
}

func collectParamGroupCands(refs, constNames []string, scopeMod string, resources []planResource, idx configIndex, groupType string, depth int) []paramGroupCand {
	if depth > maxParamGroupDepth {
		return nil
	}
	var out []paramGroupCand
	for _, name := range constNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if isDefaultParamGroupName(name) {
			out = append(out, paramGroupCand{defName: name})
		} else {
			out = append(out, paramGroupCand{external: true})
		}
	}
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		if isEachRef(ref) {
			continue
		}
		if isDataParamGroupRef(ref) {
			continue
		}
		if g, ok := findParamGroupFromRef(resources, groupType, ref); ok {
			g := g
			out = append(out, paramGroupCand{group: &g})
			continue
		}
		// Ref names a managed group that is not in resource_changes (count=0).
		if namesManagedParamGroup(ref, groupType) {
			continue
		}
		if isVarRef(ref) {
			out = append(out, followParamGroupVar(ref, scopeMod, resources, idx, groupType, depth)...)
			continue
		}
		if isLocalRef(ref) {
			out = append(out, expandParamGroupLocal(scopeMod, resources, idx, groupType)...)
			continue
		}
		// module.output → try resolving to a managed group in that module.
		if g, ok := resolveModuleOutputResource(ref, groupType, idx, resources, depth); ok {
			g := g
			out = append(out, paramGroupCand{group: &g})
			continue
		}
		if isModuleOutputRef(ref) || strings.HasPrefix(ref, "module.") {
			// Unresolved module/output branch counts as external.
			out = append(out, paramGroupCand{external: true})
		}
	}
	return out
}

func followParamGroupVar(ref, scopeMod string, resources []planResource, idx configIndex, groupType string, depth int) []paramGroupCand {
	varName := varNameFromRef(ref)
	if varName == "" {
		return []paramGroupCand{{external: true}}
	}
	// Module call whose body declares this var is scopeMod (resource's module).
	call, ok := idx.calls[scopeMod]
	if !ok {
		return []paramGroupCand{{external: true}}
	}
	var constNames []string
	if cv, ok := call.constants[varName].(string); ok {
		constNames = append(constNames, cv)
	}
	callRefs := call.refs[varName]
	if len(callRefs) == 0 && len(constNames) == 0 {
		// Unknown external name (var not wired or non-constant).
		return []paramGroupCand{{external: true}}
	}
	parent := parentModuleAddr(scopeMod)
	return collectParamGroupCands(callRefs, constNames, parent, resources, idx, groupType, depth+1)
}

func expandParamGroupLocal(scopeMod string, resources []planResource, idx configIndex, groupType string) []paramGroupCand {
	// Locals are not in plan JSON. Collect managed groups under the module that
	// owns the local (terraform-aws-modules/rds: local.parameter_group_name_id
	// → module.db_parameter_group.aws_db_parameter_group.this).
	groups := paramGroupsUnderModule(resources, scopeMod, groupType)
	if len(groups) == 0 {
		return nil
	}
	var out []paramGroupCand
	for i := range groups {
		g := groups[i]
		out = append(out, paramGroupCand{group: &g})
	}
	return out
}

func pickParamGroupCand(cands []paramGroupCand, scopeMod string, idx configIndex, groupType string) (planResource, string, bool) {
	create, createKnown := paramGroupCreateFlag(idx, scopeMod, groupType)

	var groups []planResource
	var defs []string
	var external bool
	seenG := map[string]bool{}
	seenD := map[string]bool{}

	for _, c := range cands {
		switch {
		case c.external:
			if createKnown && create {
				continue // create=true selects the managed-group branch
			}
			external = true
		case c.defName != "":
			if createKnown && create {
				continue
			}
			if !seenD[c.defName] {
				seenD[c.defName] = true
				defs = append(defs, c.defName)
			}
		case c.group != nil:
			if createKnown && !create {
				continue
			}
			if seenG[c.group.address] {
				continue
			}
			seenG[c.group.address] = true
			groups = append(groups, *c.group)
		}
	}

	if createKnown && create {
		if len(groups) == 1 {
			return groups[0], "", true
		}
		return planResource{}, "", false
	}
	if createKnown && !create {
		if len(groups) == 0 && len(defs) == 1 {
			return planResource{}, defs[0], true
		}
		return planResource{}, "", false
	}

	// create unknown: accept only a single unambiguous candidate.
	if external && (len(groups) > 0 || len(defs) > 0) {
		return planResource{}, "", false
	}
	if len(groups) == 1 && len(defs) == 0 && !external {
		return groups[0], "", true
	}
	if len(groups) == 0 && len(defs) == 1 && !external {
		return planResource{}, defs[0], true
	}
	return planResource{}, "", false
}

func paramGroupCreateFlag(idx configIndex, scopeMod, groupType string) (create bool, known bool) {
	attrs := []string{"create_db_parameter_group"}
	if groupType == "aws_rds_cluster_parameter_group" {
		attrs = []string{"create_db_cluster_parameter_group", "create_cluster_parameter_group", "create_db_parameter_group"}
	}
	for m := scopeMod; ; m = parentModuleAddr(m) {
		for _, attr := range attrs {
			if v, ok := idx.callConstant(m, attr).(bool); ok {
				return v, true
			}
		}
		// Nested parameter-group submodule often uses `create`.
		for callAddr, set := range idx.calls {
			if !strings.Contains(callAddr, "parameter_group") {
				continue
			}
			if m != "" && callAddr != m && !strings.HasPrefix(callAddr, m+".") {
				continue
			}
			if m == "" && strings.Count(callAddr, "module.") != 1 {
				continue
			}
			if v, ok := set.constants["create"].(bool); ok {
				return v, true
			}
		}
		if m == "" {
			break
		}
	}
	return false, false
}

func paramGroupsUnderModule(resources []planResource, moduleAddr, groupType string) []planResource {
	var out []planResource
	for _, r := range resources {
		if r.typ != groupType {
			continue
		}
		mod, _, _, ok := splitResourceAddress(r.address)
		if !ok {
			continue
		}
		if moduleAddr == "" {
			if mod == "" {
				out = append(out, r)
			}
			continue
		}
		if mod == moduleAddr || strings.HasPrefix(mod, moduleAddr+".") {
			out = append(out, r)
		}
	}
	return out
}

func isLocalRef(ref string) bool {
	return strings.HasPrefix(ref, "local.") || strings.Contains(ref, ".local.")
}

func isEachRef(ref string) bool {
	return strings.HasPrefix(ref, "each.") || strings.Contains(ref, ".each.")
}

func isDataParamGroupRef(ref string) bool {
	return strings.Contains(ref, "data.aws_db_parameter_group.") ||
		strings.Contains(ref, ".data.aws_db_parameter_group.") ||
		strings.Contains(ref, "data.aws_rds_cluster_parameter_group.") ||
		strings.Contains(ref, ".data.aws_rds_cluster_parameter_group.")
}

func namesManagedParamGroup(ref, groupType string) bool {
	needle := groupType + "."
	i := strings.Index(ref, needle)
	if i < 0 {
		return false
	}
	if i >= 5 && ref[i-5:i] == "data." {
		return false
	}
	if i >= 6 && strings.HasSuffix(ref[:i], ".data.") {
		return false
	}
	return true
}

func varNameFromRef(ref string) string {
	i := strings.LastIndex(ref, "var.")
	if i < 0 {
		return ""
	}
	name := ref[i+len("var."):]
	if j := strings.IndexAny(name, ".["); j >= 0 {
		name = name[:j]
	}
	return name
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
