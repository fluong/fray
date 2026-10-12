package client

import (
	"strings"
)

const maxModuleOutputDepth = 3

// indexModuleOutputs stores output expressions for moduleAddr (no instance key).
func indexModuleOutputs(mod map[string]any, moduleAddr string, idx *configIndex) {
	outs, _ := mod["outputs"].(map[string]any)
	if len(outs) == 0 {
		return
	}
	set := exprSet{
		refs: map[string][]string{},
		raw:  map[string]any{},
	}
	for name, raw := range outs {
		o, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		expr := o["expression"]
		set.raw[name] = expr
		var refs []string
		collectRefs(expr, &refs)
		if len(refs) > 0 {
			set.refs[name] = refs
		}
	}
	if idx.outputs == nil {
		idx.outputs = map[string]exprSet{}
	}
	idx.outputs[moduleAddr] = set
}

// parseModuleOutputRef parses module.<path>[key].<output> (and .id/.arn suffixes).
// Resource references (containing aws_security_group / aws_ec2_managed_prefix_list)
// return ok=false.
func parseModuleOutputRef(ref string) (moduleAddr, output string, ok bool) {
	if !strings.HasPrefix(ref, "module.") {
		return "", "", false
	}
	if securityGroupNameFromRef(ref) != "" || managedPrefixListNameFromRef(ref) != "" {
		return "", "", false
	}
	if strings.Contains(ref, "data.") {
		return "", "", false
	}
	rest := ref
	var b strings.Builder
	for strings.HasPrefix(rest, "module.") {
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString("module.")
		rest = strings.TrimPrefix(rest, "module.")
		i := 0
		for i < len(rest) && rest[i] != '.' && rest[i] != '[' {
			i++
		}
		if i == 0 {
			return "", "", false
		}
		b.WriteString(rest[:i])
		rest = rest[i:]
		if strings.HasPrefix(rest, "[") {
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				return "", "", false
			}
			b.WriteString(rest[:end+1])
			rest = rest[end+1:]
		}
		if strings.HasPrefix(rest, ".") {
			rest = rest[1:]
		} else if rest != "" {
			return "", "", false
		}
		if strings.HasPrefix(rest, "module.") {
			continue
		}
		break
	}
	if rest == "" {
		return "", "", false
	}
	out := rest
	if i := strings.IndexByte(rest, '.'); i >= 0 {
		out = rest[:i]
	}
	if out == "" || strings.HasPrefix(out, "aws_") {
		return "", "", false
	}
	return b.String(), out, true
}

func isModuleOutputRef(ref string) bool {
	_, _, ok := parseModuleOutputRef(ref)
	return ok
}

// moduleCallAndInstance splits module.sg["app"] into call address module.sg
// and instance key "app" (or "0" for count). No instance → key "".
func moduleCallAndInstance(moduleAddr string) (callAddr, instanceKey string) {
	callAddr = moduleAddr
	// Find the last [key] on the final module segment.
	lb := strings.LastIndexByte(moduleAddr, '[')
	if lb < 0 || !strings.HasSuffix(moduleAddr, "]") {
		return moduleAddr, ""
	}
	// Ensure this bracket belongs to a module segment, not something else.
	before := moduleAddr[:lb]
	if !strings.Contains(before, "module.") {
		return moduleAddr, ""
	}
	key := moduleAddr[lb+1 : len(moduleAddr)-1]
	// Strip quotes from string keys.
	if len(key) >= 2 && ((key[0] == '"' && key[len(key)-1] == '"') || (key[0] == '\'' && key[len(key)-1] == '\'')) {
		key = key[1 : len(key)-1]
	}
	return before, key
}

// resolveModuleOutputResource follows module.<m>.<output> (and nested outputs /
// var passthroughs) to exactly one managed resource of wantType in that module
// instance. depth caps recursion at maxModuleOutputDepth.
func resolveModuleOutputResource(ref, wantType string, idx configIndex, resources []planResource, depth int) (planResource, bool) {
	addr, ok := resolveModuleOutputAddress(ref, wantType, idx, depth)
	if !ok {
		return planResource{}, false
	}
	for _, r := range resources {
		if r.typ == wantType && (r.address == addr || stripIndexed(r.address) == stripIndexed(addr) || resourceKeyMatch(r.address, addr)) {
			return r, true
		}
	}
	// Address may omit [0] count index used in resource_changes.
	for _, r := range resources {
		if r.typ != wantType {
			continue
		}
		if sameResourceIgnoringIndex(r.address, addr) {
			return r, true
		}
	}
	return planResource{}, false
}

func resolveModuleOutputAddress(ref, wantType string, idx configIndex, depth int) (string, bool) {
	if depth > maxModuleOutputDepth {
		return "", false
	}
	modAddr, outName, ok := parseModuleOutputRef(ref)
	if !ok {
		return "", false
	}
	callAddr, instanceKey := moduleCallAndInstance(modAddr)
	outs := idx.outputs[callAddr]
	refs := outs.refs[outName]
	if len(refs) == 0 {
		return "", false
	}
	var addrs []string
	seen := map[string]bool{}
	for _, r := range refs {
		if isBareModuleRef(r) {
			continue
		}
		resolved, ok := expandOutputRef(r, wantType, callAddr, instanceKey, idx, depth)
		if !ok {
			return "", false
		}
		if resolved == "" || seen[resolved] {
			continue
		}
		seen[resolved] = true
		addrs = append(addrs, resolved)
	}
	if len(addrs) != 1 {
		return "", false
	}
	return addrs[0], true
}

func expandOutputRef(ref, wantType, callAddr, instanceKey string, idx configIndex, depth int) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", false
	}
	// Conditional / each / local → unresolvable.
	if strings.HasPrefix(ref, "each.") || strings.Contains(ref, ".each.") {
		return "", false
	}
	if strings.HasPrefix(ref, "local.") || strings.Contains(ref, ".local.") {
		return "", false
	}
	if strings.Contains(ref, "?") { // ternary not represented as refs usually
		return "", false
	}

	if isVarRef(ref) {
		return resolveVarPassthrough(ref, wantType, callAddr, instanceKey, idx, depth)
	}

	if childMod, childOut, ok := parseModuleOutputRef(ref); ok {
		// Qualify relative module.X against callAddr.
		full := qualifyModuleAddr(callAddr, instanceKey, childMod)
		return resolveModuleOutputAddress(full+"."+childOut, wantType, idx, depth+1)
	}
	// Relative child module ref without being an output parse (module.x from inside).
	if strings.HasPrefix(ref, "module.") {
		full := qualifyModuleAddr(callAddr, instanceKey, ref)
		if !strings.Contains(full, wantType+".") {
			// Treat as nested output path: module.child.output already handled;
			// bare module.child is incomplete.
			if _, _, ok := parseModuleOutputRef(full); ok {
				return resolveModuleOutputAddress(full, wantType, idx, depth+1)
			}
			return "", false
		}
		return qualifyResourceInModule(callAddr, instanceKey, ref, wantType)
	}

	if strings.Contains(ref, wantType+".") {
		return qualifyResourceInModule(callAddr, instanceKey, ref, wantType)
	}
	return "", false
}

func resolveVarPassthrough(ref, wantType, callAddr, instanceKey string, idx configIndex, depth int) (string, bool) {
	varName := ref
	if i := strings.LastIndex(ref, "var."); i >= 0 {
		varName = ref[i+len("var."):]
	}
	if j := strings.IndexAny(varName, ".["); j >= 0 {
		varName = varName[:j]
	}
	parent := parentModuleAddr(callAddr)
	// Inputs are on the module call at callAddr.
	callRefs := idx.calls[callAddr].refs[varName]
	if len(callRefs) == 0 {
		return "", false
	}
	var addrs []string
	seen := map[string]bool{}
	for _, r := range callRefs {
		if isVarRef(r) || strings.HasPrefix(r, "local.") || strings.Contains(r, ".local.") {
			return "", false
		}
		if isModuleOutputRef(r) {
			// Absolute from parent scope.
			addr, ok := resolveModuleOutputAddress(qualifyModuleAddr(parent, "", r), wantType, idx, depth+1)
			if !ok {
				return "", false
			}
			if !seen[addr] {
				seen[addr] = true
				addrs = append(addrs, addr)
			}
			continue
		}
		if strings.Contains(r, wantType+".") {
			addr, ok := qualifyResourceInModule(parent, "", r, wantType)
			if !ok {
				return "", false
			}
			if !seen[addr] {
				seen[addr] = true
				addrs = append(addrs, addr)
			}
			continue
		}
		return "", false
	}
	if len(addrs) != 1 {
		return "", false
	}
	return addrs[0], true
}

func qualifyModuleAddr(parent, instanceKey, ref string) string {
	if strings.HasPrefix(ref, "module.") {
		if parent == "" {
			return applyInstanceKey(ref, instanceKey)
		}
		// ref is relative to parent module's body → parent.ref
		return applyInstanceKey(parent+"."+ref, instanceKey)
	}
	return ref
}

func applyInstanceKey(moduleAddr, instanceKey string) string {
	if instanceKey == "" {
		return moduleAddr
	}
	call, existing := moduleCallAndInstance(moduleAddr)
	if existing != "" {
		return moduleAddr
	}
	// Attach key to the last module segment.
	return call + `["` + instanceKey + `"]`
}

func qualifyResourceInModule(moduleAddr, instanceKey, ref, wantType string) (string, bool) {
	name := ""
	switch wantType {
	case "aws_security_group":
		name = securityGroupNameFromRef(ref)
	case "aws_ec2_managed_prefix_list":
		name = managedPrefixListNameFromRef(ref)
	}
	if name == "" {
		return "", false
	}
	base := moduleAddr
	if instanceKey != "" {
		call, existing := moduleCallAndInstance(moduleAddr)
		if existing == "" {
			base = call + `["` + instanceKey + `"]`
		}
	}
	// Preserve count/for_each index from the reference when present.
	idxSuffix := resourceIndexSuffix(ref, wantType, name)
	addr := resourceAddress(base, wantType, name)
	if idxSuffix != "" {
		addr = addr + idxSuffix
	}
	return addr, true
}

func resourceIndexSuffix(ref, typ, name string) string {
	needle := typ + "." + name
	i := strings.Index(ref, needle)
	if i < 0 {
		return ""
	}
	rest := ref[i+len(needle):]
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end >= 0 {
			return rest[:end+1]
		}
	}
	return ""
}

func stripIndexed(addr string) string {
	key, ok := resourceKey(addr)
	if ok {
		return key
	}
	return addr
}

func resourceKeyMatch(a, b string) bool {
	ka, oka := resourceKey(a)
	kb, okb := resourceKey(b)
	return oka && okb && ka == kb
}

func sameResourceIgnoringIndex(a, b string) bool {
	if a == b {
		return true
	}
	ka, oka := resourceKey(a)
	kb, okb := resourceKey(b)
	if oka && okb && ka == kb {
		return true
	}
	// Compare with instance keys normalized.
	return stripModuleInstanceKeys(a) == stripModuleInstanceKeys(b)
}

func stripModuleInstanceKeys(addr string) string {
	var b strings.Builder
	rest := addr
	for strings.HasPrefix(rest, "module.") {
		b.WriteString("module.")
		rest = strings.TrimPrefix(rest, "module.")
		i := 0
		for i < len(rest) && rest[i] != '.' && rest[i] != '[' {
			i++
		}
		b.WriteString(rest[:i])
		rest = rest[i:]
		if strings.HasPrefix(rest, "[") {
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				return addr
			}
			rest = rest[end+1:]
		}
		if strings.HasPrefix(rest, ".") {
			b.WriteByte('.')
			rest = rest[1:]
		}
	}
	b.WriteString(rest)
	return b.String()
}
