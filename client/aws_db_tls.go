package client

import (
	"strconv"
	"strings"
)

const maxParamGroupDepth = 3

// dbTLSEnforced reports attributes.tls_enforced for an RDS instance or Aurora
// cluster from its parameter group.
//
// Resolution when parameter_group_name / db_cluster_parameter_group_name is
// planned and known: default.* → engine default; equals the planned name of
// exactly one managed group → that group; otherwise omit (no subtree guess).
//
// When the planned value is unknown: follow configuration references through
// module inputs and try()/conditionals (depth ≤ 3) to exactly one managed
// group. A local.* (not in plan JSON) may use a subtree heuristic only if
// exactly one matching group exists under the nearest common module call and
// that group's name/name_prefix is unknown or prefix-derived. A literal
// default.* in another branch is a second candidate unless create/count is
// statically known. When after_unknown with no config refs (provider
// Optional+Computed default), engineTLSDefault applies — RDS PostgreSQL
// major ≥15 → true, ≤14 → false.
//
// Parameters: rds.force_ssl (postgres, aurora-postgresql);
// require_secure_transport (mysql, mariadb, aurora-mysql). Values
// 1/ON/on/true → true; 0/OFF/off/false → false.
//
// When the parameter is unset in a custom group, or there is no custom group
// (absent name or default.*), engineTLSDefault applies (documented defaults
// only; see that function). Unparseable/unknown engine_version → omit.
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
		// Known planned name: match by name only — never subtree heuristic.
		if isDefaultParamGroupName(planned) {
			return engineTLSDefault(engine, version, r.typ)
		}
		g, ok := findParamGroupByPlannedName(resources, groupType, planned)
		if !ok {
			return false, false // external / unmatched group
		}
		return paramGroupTLS(g, param, engine, version, r.typ)
	case unknown:
		g, def, ok := resolveParamGroupBinding(r, resources, idx, groupAttr, groupType, true)
		if !ok {
			// Provider Optional+Computed: omitted parameter_group_name is
			// after_unknown with no config refs → engine default.* group.
			if len(refs) == 0 {
				return engineTLSDefault(engine, version, r.typ)
			}
			return false, false
		}
		if def != "" {
			return engineTLSDefault(engine, version, r.typ)
		}
		return paramGroupTLS(g, param, engine, version, r.typ)
	default:
		// Absent planned value (not unknown): follow refs without local heuristic.
		g, def, ok := resolveParamGroupBinding(r, resources, idx, groupAttr, groupType, false)
		if ok {
			if def != "" {
				return engineTLSDefault(engine, version, r.typ)
			}
			return paramGroupTLS(g, param, engine, version, r.typ)
		}
		if len(refs) > 0 {
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
// allowLocalHeuristic enables the locals subtree guess (unknown planned values only).
func resolveParamGroupBinding(r planResource, resources []planResource, idx configIndex, groupAttr, groupType string, allowLocalHeuristic bool) (planResource, string, bool) {
	mod, _, _, _ := splitResourceAddress(r.address)
	refs := idx.attrRefs(r.address, groupAttr)
	var constNames []string
	if key, ok := resourceKey(r.address); ok {
		if cv, ok := idx.resources[key].constants[groupAttr].(string); ok {
			constNames = append(constNames, cv)
		}
	}
	cands := collectParamGroupCands(refs, constNames, mod, mod, resources, idx, groupType, allowLocalHeuristic, 0)
	return pickParamGroupCand(cands, mod, idx, groupType)
}

func collectParamGroupCands(refs, constNames []string, scopeMod, instanceMod string, resources []planResource, idx configIndex, groupType string, allowLocalHeuristic bool, depth int) []paramGroupCand {
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
			out = append(out, followParamGroupVar(ref, scopeMod, instanceMod, resources, idx, groupType, allowLocalHeuristic, depth)...)
			continue
		}
		if isLocalRef(ref) {
			if !allowLocalHeuristic {
				continue
			}
			out = append(out, expandParamGroupLocal(scopeMod, instanceMod, resources, groupType)...)
			continue
		}
		// module.output → try resolving to a managed group in that module.
		if g, ok := resolveModuleOutputResource(ref, groupType, idx, resources, depth); ok {
			g := g
			out = append(out, paramGroupCand{group: &g})
			continue
		}
		if isModuleOutputRef(ref) || strings.HasPrefix(ref, "module.") {
			out = append(out, paramGroupCand{external: true})
		}
	}
	return out
}

func followParamGroupVar(ref, scopeMod, instanceMod string, resources []planResource, idx configIndex, groupType string, allowLocalHeuristic bool, depth int) []paramGroupCand {
	varName := varNameFromRef(ref)
	if varName == "" {
		return []paramGroupCand{{external: true}}
	}
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
		return []paramGroupCand{{external: true}}
	}
	parent := parentModuleAddr(scopeMod)
	return collectParamGroupCands(callRefs, constNames, parent, instanceMod, resources, idx, groupType, allowLocalHeuristic, depth+1)
}

// expandParamGroupLocal applies the locals subtree heuristic: plan JSON has no
// local bodies, so when an expression passes through local.* accept exactly one
// managed group under the nearest common module call that contains the instance
// (the module that owns the local), provided that group's name/name_prefix is
// unknown or prefix-derived.
func expandParamGroupLocal(localMod, instanceMod string, resources []planResource, groupType string) []paramGroupCand {
	root := nearestCommonModuleForLocal(localMod, instanceMod)
	groups := paramGroupsUnderModule(resources, root, groupType)
	if len(groups) != 1 {
		return nil
	}
	g := groups[0]
	if !paramGroupEligibleForLocalHeuristic(g) {
		return nil
	}
	return []paramGroupCand{{group: &g}}
}

// nearestCommonModuleForLocal returns the module whose subtree is searched for
// the locals heuristic: the local's module when it contains the instance,
// otherwise the deepest shared module prefix.
func nearestCommonModuleForLocal(localMod, instanceMod string) string {
	if localMod != "" && moduleContains(localMod, instanceMod) {
		return localMod
	}
	return sharedModulePrefix(localMod, instanceMod)
}

func moduleContains(ancestor, mod string) bool {
	if ancestor == "" {
		return true
	}
	return mod == ancestor || strings.HasPrefix(mod, ancestor+".")
}

func sharedModulePrefix(a, b string) string {
	pa := modulePath(a)
	pb := modulePath(b)
	n := len(pa)
	if len(pb) < n {
		n = len(pb)
	}
	var shared []string
	for i := 0; i < n; i++ {
		if pa[i] != pb[i] {
			break
		}
		shared = append(shared, pa[i])
	}
	if len(shared) == 0 {
		return ""
	}
	return "module." + strings.Join(shared, ".module.")
}

func modulePath(mod string) []string {
	if mod == "" || !strings.HasPrefix(mod, "module.") {
		return nil
	}
	var parts []string
	rest := mod
	for strings.HasPrefix(rest, "module.") {
		rest = strings.TrimPrefix(rest, "module.")
		i := 0
		for i < len(rest) && rest[i] != '.' && rest[i] != '[' {
			i++
		}
		if i == 0 {
			return nil
		}
		parts = append(parts, rest[:i])
		rest = rest[i:]
		if strings.HasPrefix(rest, "[") {
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				return nil
			}
			rest = rest[end+1:]
		}
		rest = strings.TrimPrefix(rest, ".")
	}
	return parts
}

// paramGroupEligibleForLocalHeuristic requires the group's name or name_prefix
// to be unknown after apply, or a name_prefix-derived name (empty name with
// prefix set). A concrete known name is rejected — it cannot be verified against
// an unknown instance parameter_group_name.
func paramGroupEligibleForLocalHeuristic(g planResource) bool {
	if g.attrAfterUnknown("name") || g.attrAfterUnknown("name_prefix") {
		return true
	}
	name, _ := g.values["name"].(string)
	if strings.TrimSpace(name) == "" {
		prefix, _ := g.values["name_prefix"].(string)
		return strings.TrimSpace(prefix) != ""
	}
	return false
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
	// OUT OF SCOPE (B-47): data.aws_db_parameter_group /
	// data.aws_rds_cluster_parameter_group expose no parameter list, so TLS
	// cannot be decided from them. Keep omit (caller skips these refs).
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
		n, _ := r.values["name"].(string)
		if n == plannedName {
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

// engineTLSDefault returns the provider's documented default for
// rds.force_ssl / require_secure_transport when the effective parameter group
// is the engine default (or no custom group is in the plan). Documented OFF
// is emitted as false (known), matching postgres major ≤14 — not omitted.
//
// Sources (cite in branches below):
//
//	postgres (aws_db_instance):
//	https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html
//	aurora-postgresql (aws_rds_cluster):
//	https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraPostgreSQL.Security.html
//	aurora-mysql (aws_rds_cluster):
//	https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Upgrade-v3-v84-security.html
//	mariadb (aws_db_instance):
//	https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/mariadb-ssl-connections.require-ssl.html
//	mysql (aws_db_instance):
//	https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/mysql-ssl-connections.require-ssl.html
func engineTLSDefault(engine, version, typ string) (enforced bool, known bool) {
	switch {
	case typ == "aws_db_instance" && engine == "postgres":
		// Major ≥15 → ON (1); ≤14 → OFF (0). Unparseable → omit.
		major, ok := engineMajor(version)
		if !ok {
			return false, false
		}
		if major >= 15 {
			return true, true
		}
		return false, true

	case typ == "aws_rds_cluster" && engine == "aurora-postgresql":
		// Major ≥17 → ON; ≤16 → OFF. Unparseable → omit.
		major, ok := engineMajor(version)
		if !ok {
			return false, false
		}
		if major >= 17 {
			return true, true
		}
		return false, true

	case typ == "aws_rds_cluster" && engine == "aurora-mysql":
		// Aurora MySQL 8.4 → ON; Aurora MySQL v3 (8.0-compatible) → omit
		// (no documented default we rely on).
		return auroraMySQLTLSDefault(version)

	case typ == "aws_db_instance" && engine == "mariadb":
		// ≥11.8 → ON; 10.5–11.4 → OFF; <10.5 → omit (parameter unsupported);
		// 11.5–11.7 (between documented bands) → omit.
		return mariadbTLSDefault(version)

	case typ == "aws_db_instance" && engine == "mysql":
		// Documented default OFF for require_secure_transport.
		return false, true

	default:
		return false, false
	}
}

// engineMajor parses the leading integer major from an engine_version string
// (e.g. "16.3", "8.0.mysql_aurora.3.04.1" → 8).
func engineMajor(version string) (int, bool) {
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

// engineMajorMinor parses leading major.minor (e.g. "11.8.2" → 11, 8).
func engineMajorMinor(version string) (major, minor int, ok bool) {
	version = strings.TrimSpace(version)
	if version == "" {
		return 0, 0, false
	}
	// Strip trailing vendor suffixes after a second-level segment when needed
	// (e.g. "8.0.mysql_aurora.3.04.1" → major=8, minor=0).
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	minStr := parts[1]
	// minor may be non-numeric in odd strings; take leading digits only
	j := 0
	for j < len(minStr) && minStr[j] >= '0' && minStr[j] <= '9' {
		j++
	}
	if j == 0 {
		return 0, 0, false
	}
	min, err2 := strconv.Atoi(minStr[:j])
	if err1 != nil || err2 != nil || maj <= 0 {
		return 0, 0, false
	}
	return maj, min, true
}

func auroraMySQLTLSDefault(version string) (enforced bool, known bool) {
	maj, min, ok := engineMajorMinor(version)
	if !ok {
		return false, false
	}
	if maj == 8 && min == 4 {
		return true, true
	}
	// 8.0-compatible (Aurora MySQL v3) and anything else → omit.
	return false, false
}

func mariadbTLSDefault(version string) (enforced bool, known bool) {
	maj, min, ok := engineMajorMinor(version)
	if !ok {
		return false, false
	}
	// ≥11.8 → ON.
	if maj > 11 || (maj == 11 && min >= 8) {
		return true, true
	}
	// 11.5–11.7 sit between documented bands → omit.
	if maj == 11 && min >= 5 {
		return false, false
	}
	// 10.5–11.4 → OFF.
	if maj == 11 || (maj == 10 && min >= 5) {
		return false, true
	}
	// <10.5 → omit (parameter unsupported).
	return false, false
}
