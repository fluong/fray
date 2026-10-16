package client

// bareModuleRefPolicy controls when isBareModuleRef refs are skipped.
type bareModuleRefPolicy int

const (
	// bareModuleSkipWithVar skips bare module refs at the start of the loop
	// (together with var refs), before data / module-output handling.
	bareModuleSkipWithVar bareModuleRefPolicy = iota
	// bareModuleSkipAfterModuleOutput skips bare module refs only after the
	// module-output branch (subnet resolvers).
	bareModuleSkipAfterModuleOutput
)

// emptyNamePolicy is applied when resourceNameFromRef returns "".
type emptyNamePolicy int

const (
	emptyNameContinue emptyNamePolicy = iota
	emptyNameFail
)

// resolveSingleByRefOpts encodes per-caller ref resolution behaviour.
type resolveSingleByRefOpts struct {
	ResourceType      string
	SkipVarRef        bool
	BareModule        bareModuleRefPolicy
	EmptyNameData     emptyNamePolicy
	EmptyNameManaged  emptyNamePolicy
	ModuleOutputDepth int
}

// resolveSingleByRef resolves refs to a single planResource of ResourceType.
// Two different successful hits → (zero, false). Lookup miss → (zero, false).
func resolveSingleByRef(refs []string, resources, data []planResource, idx configIndex, opts resolveSingleByRefOpts) (planResource, bool) {
	var hit planResource
	found := false
	typ := opts.ResourceType
	depth := opts.ModuleOutputDepth
	for _, ref := range refs {
		if opts.SkipVarRef && isVarRef(ref) {
			continue
		}
		if opts.BareModule == bareModuleSkipWithVar && isBareModuleRef(ref) {
			continue
		}
		if isDataTypeRef(ref, typ) {
			name := resourceNameFromRef(ref, typ)
			if name == "" {
				if opts.EmptyNameData == emptyNameFail {
					return planResource{}, false
				}
				continue
			}
			res, ok := findDataResource(data, typ, name, ref)
			if !ok {
				return planResource{}, false
			}
			if found && hit.address != res.address {
				return planResource{}, false
			}
			hit, found = res, true
			continue
		}
		if isModuleOutputRef(ref) {
			res, ok := resolveModuleOutputResource(ref, typ, idx, resources, depth)
			if !ok {
				return planResource{}, false
			}
			if found && hit.address != res.address {
				return planResource{}, false
			}
			hit, found = res, true
			continue
		}
		if opts.BareModule == bareModuleSkipAfterModuleOutput && isBareModuleRef(ref) {
			continue
		}
		name := resourceNameFromRef(ref, typ)
		if name == "" {
			if opts.EmptyNameManaged == emptyNameFail {
				return planResource{}, false
			}
			continue
		}
		res, ok := findManagedResource(resources, typ, name, ref)
		if !ok {
			return planResource{}, false
		}
		if found && hit.address != res.address {
			return planResource{}, false
		}
		hit, found = res, true
	}
	if !found {
		return planResource{}, false
	}
	return hit, true
}

// resolveUniqueSecurityGroupPeerAddress collects same-module SG addresses from
// refs. ok when exactly one distinct address; unk when ambiguous or unresolvable.
func resolveUniqueSecurityGroupPeerAddress(refs []string, ruleMod string, idx configIndex) (addr string, ok bool, unk bool) {
	var addrs []string
	seen := map[string]bool{}
	for _, ref := range refs {
		if isBareModuleRef(ref) {
			continue
		}
		if isModuleOutputRef(ref) {
			a, resolved := resolveModuleOutputAddress(ref, "aws_security_group", idx, 0)
			if !resolved {
				return "", false, true
			}
			if !seen[a] {
				seen[a] = true
				addrs = append(addrs, a)
			}
			continue
		}
		if isIndirectIngressRef(ref) {
			return "", false, true
		}
		name := securityGroupNameFromRef(ref)
		if name == "" {
			continue
		}
		a := resourceAddress(ruleMod, "aws_security_group", name)
		if !seen[a] {
			seen[a] = true
			addrs = append(addrs, a)
		}
	}
	if len(addrs) != 1 {
		return "", false, true
	}
	return addrs[0], true, false
}
