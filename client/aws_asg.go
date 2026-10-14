package client

import (
	"fmt"
	"sort"
)

// awsASGElement maps a managed aws_autoscaling_group to a virtual_machine
// process for FR-034. No flows are created. The display name always reads as
// an Auto Scaling group (never "instance").
func awsASGElement(r planResource, resources, data []planResource, idx configIndex) *Element {
	_, _, name, _ := splitResourceAddress(r.address)
	attrs := map[string]any{}
	if v, ok := asgPublicIP(r, resources, data, idx); ok {
		attrs["public_ip"] = v
	}
	if v, ok := asgAdminPortsOpen(r, resources, data, idx); ok {
		attrs["admin_ports_open"] = v
	}
	return &Element{
		Name: ASGDisplayName(r.address, name), Type: "process", Kind: "virtual_machine", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

// asgPublicIP reports attributes.public_ip for an Auto Scaling group.
//
// Launch template / launch configuration associate_public_ip_address wins when
// explicit. Otherwise vpc_zone_identifier subnets: true if any known subnet has
// map_public_ip_on_launch; false only when every subnet is in plan, private,
// and there is no IPv6 on the template(s) or subnets; else omit.
func asgPublicIP(asg planResource, resources, data []planResource, idx configIndex) (public bool, known bool) {
	src := resolveASGLaunchSource(asg, resources, data, idx)
	if src.unknown {
		return false, false
	}

	if assoc, knownAssoc, set := asgLaunchAssociateKnown(src); set {
		if !knownAssoc {
			return false, false // conflict, disagree, or after_unknown
		}
		if assoc {
			return true, true
		}
		hasIPv6, ipv6Known := asgLaunchHasIPv6(src)
		if !ipv6Known || hasIPv6 {
			return false, false
		}
		return false, true
	}

	hasIPv6, ipv6Known := asgLaunchHasIPv6(src)
	return asgPublicIPFromSubnets(asg, resources, data, idx, hasIPv6, ipv6Known)
}

func asgPublicIPFromSubnets(asg planResource, resources, data []planResource, idx configIndex, tmplIPv6, tmplIPv6Known bool) (public bool, known bool) {
	subnets, allResolved, ok := resolveASGSubnets(asg, resources, data, idx)
	if !ok {
		return false, false
	}
	anyPublic := false
	for _, sn := range subnets {
		if v, ok := sn.values["map_public_ip_on_launch"].(bool); ok && v {
			anyPublic = true
			break
		}
	}
	if anyPublic {
		return true, true
	}
	if !allResolved {
		return false, false
	}
	for _, sn := range subnets {
		if sn.attrAfterUnknown("map_public_ip_on_launch") {
			return false, false
		}
	}
	if !tmplIPv6Known {
		return false, false
	}
	if tmplIPv6 {
		return false, false
	}
	for _, sn := range subnets {
		if v, ok := sn.values["assign_ipv6_address_on_creation"].(bool); ok && v {
			return false, false
		}
		if sn.attrAfterUnknown("assign_ipv6_address_on_creation") {
			return false, false
		}
	}
	return false, true
}

func asgAdminPortsOpen(asg planResource, resources, data []planResource, idx configIndex) (open bool, known bool) {
	src := resolveASGLaunchSource(asg, resources, data, idx)
	if src.unknown {
		return false, false
	}
	refs, ok := asgLaunchSecurityGroupRefs(src, idx)
	if !ok || len(refs) == 0 {
		return false, false
	}
	sgs, ok := resolveSecurityGroupRefs(refs, resources, data, idx)
	if !ok || len(sgs) == 0 {
		return false, false
	}
	sawUnknown := false
	for _, sg := range sgs {
		for _, port := range []int{22, 3389} {
			cls, world := classifySGAdminIngress(sg, resources, idx, port)
			if world {
				return true, true
			}
			if cls == netSrcUnknown {
				sawUnknown = true
			}
		}
	}
	if sawUnknown {
		return false, false
	}
	return false, true
}

func resolveSecurityGroupRefs(refs []string, resources, data []planResource, idx configIndex) ([]planResource, bool) {
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

// asgLaunchSource is the launch template(s) or launch configuration an ASG uses.
type asgLaunchSource struct {
	templates []planResource
	lc        planResource
	useLC     bool
	unknown   bool // declared but unresolvable / version / conflict
}

func resolveASGLaunchSource(asg planResource, resources, data []planResource, idx configIndex) asgLaunchSource {
	if instanceDeclaresLaunchTemplate(asg, idx) {
		lt := resolveInstanceLaunchTemplate(asg, resources, data, idx)
		if !lt.declared {
			return asgLaunchSource{}
		}
		if !lt.usable {
			return asgLaunchSource{unknown: true}
		}
		return asgLaunchSource{templates: []planResource{lt.tmpl}}
	}
	if asgDeclaresMixedInstancesPolicy(asg, idx) {
		tmpls, ok := resolveASGMixedLaunchTemplates(asg, resources, data, idx)
		if !ok {
			return asgLaunchSource{unknown: true}
		}
		return asgLaunchSource{templates: tmpls}
	}
	if asgDeclaresLaunchConfiguration(asg, idx) {
		lc, ok := findASGLaunchConfiguration(asg, resources, data, idx)
		if !ok {
			return asgLaunchSource{unknown: true}
		}
		return asgLaunchSource{lc: lc, useLC: true}
	}
	return asgLaunchSource{}
}

func asgDeclaresMixedInstancesPolicy(asg planResource, idx configIndex) bool {
	if hasConfigAttr(idx, asg.address, "mixed_instances_policy") {
		return true
	}
	return len(asList(asg.values["mixed_instances_policy"])) > 0
}

func asgDeclaresLaunchConfiguration(asg planResource, idx configIndex) bool {
	if hasConfigAttr(idx, asg.address, "launch_configuration") {
		return true
	}
	if _, ok := asg.values["launch_configuration"].(string); ok {
		return true
	}
	return false
}

func findASGLaunchConfiguration(asg planResource, resources, data []planResource, idx configIndex) (planResource, bool) {
	refs := idx.attrRefs(asg.address, "launch_configuration")
	var hit planResource
	found := false
	for _, ref := range refs {
		if isVarRef(ref) || isBareModuleRef(ref) {
			continue
		}
		if isDataTypeRef(ref, "aws_launch_configuration") {
			name := resourceNameFromRef(ref, "aws_launch_configuration")
			if name == "" {
				continue
			}
			lc, ok := findDataResource(data, "aws_launch_configuration", name, ref)
			if !ok {
				return planResource{}, false
			}
			if found && hit.address != lc.address {
				return planResource{}, false
			}
			hit, found = lc, true
			continue
		}
		if isModuleOutputRef(ref) {
			lc, ok := resolveModuleOutputResource(ref, "aws_launch_configuration", idx, resources, 0)
			if !ok {
				return planResource{}, false
			}
			if found && hit.address != lc.address {
				return planResource{}, false
			}
			hit, found = lc, true
			continue
		}
		name := resourceNameFromRef(ref, "aws_launch_configuration")
		if name == "" {
			continue
		}
		lc, ok := findManagedResource(resources, "aws_launch_configuration", name, ref)
		if !ok {
			return planResource{}, false
		}
		if found && hit.address != lc.address {
			return planResource{}, false
		}
		hit, found = lc, true
	}
	if !found {
		return planResource{}, false
	}
	return hit, true
}

func resolveASGMixedLaunchTemplates(asg planResource, resources, data []planResource, idx configIndex) ([]planResource, bool) {
	specs := asgMixedTemplateSpecs(asg)
	if len(specs) == 0 {
		// Config declares mixed policy but no planned specs — try refs only.
		refs := idx.attrRefs(asg.address, "mixed_instances_policy")
		names := namedResources(refs, "aws_launch_template")
		if len(names) == 0 {
			return nil, false
		}
		var out []planResource
		seen := map[string]bool{}
		for _, ref := range refs {
			if isDataTypeRef(ref, "aws_launch_template") {
				name := resourceNameFromRef(ref, "aws_launch_template")
				if name == "" {
					continue
				}
				lt, ok := findDataResource(data, "aws_launch_template", name, ref)
				if !ok {
					return nil, false
				}
				if seen[lt.address] {
					continue
				}
				if !launchTemplateVersionDecision("", nil, true, lt) {
					return nil, false
				}
				seen[lt.address] = true
				out = append(out, lt)
				continue
			}
			name := resourceNameFromRef(ref, "aws_launch_template")
			if name == "" {
				continue
			}
			lt, ok := findManagedResource(resources, "aws_launch_template", name, ref)
			if !ok {
				return nil, false
			}
			if seen[lt.address] {
				continue
			}
			// Version omitted on ASG / mixed path defaults to $Default.
			if !launchTemplateVersionDecision("", nil, true, lt) {
				return nil, false
			}
			seen[lt.address] = true
			out = append(out, lt)
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	}

	var out []planResource
	seen := map[string]bool{}
	for _, spec := range specs {
		lt, ok := resolveLaunchTemplateSpec(spec, asg, resources, data, idx)
		if !ok {
			return nil, false
		}
		ver, verRefs, omitted := launchTemplateSpecVersion(spec, asg, idx)
		// ASG / mixed: omitted version = $Default.
		if omitted {
			ver = "$Default"
		}
		if !launchTemplateVersionDecision(ver, verRefs, omitted, lt) {
			return nil, false
		}
		if seen[lt.address] {
			continue
		}
		seen[lt.address] = true
		out = append(out, lt)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func asgMixedTemplateSpecs(asg planResource) []map[string]any {
	var specs []map[string]any
	for _, raw := range asList(asg.values["mixed_instances_policy"]) {
		mip, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for _, ltRaw := range asList(mip["launch_template"]) {
			lt, ok := ltRaw.(map[string]any)
			if !ok {
				continue
			}
			for _, s := range asList(lt["launch_template_specification"]) {
				if m, ok := s.(map[string]any); ok {
					specs = append(specs, m)
				}
			}
			for _, oRaw := range asList(lt["override"]) {
				ovr, ok := oRaw.(map[string]any)
				if !ok {
					continue
				}
				for _, s := range asList(ovr["launch_template_specification"]) {
					if m, ok := s.(map[string]any); ok {
						specs = append(specs, m)
					}
				}
			}
		}
	}
	return specs
}

func resolveLaunchTemplateSpec(spec map[string]any, asg planResource, resources, data []planResource, idx configIndex) (planResource, bool) {
	refs := idx.attrRefs(asg.address, "mixed_instances_policy")
	if id, _ := spec["launch_template_id"].(string); id != "" {
		for _, r := range resources {
			if r.typ != "aws_launch_template" {
				continue
			}
			if s, _ := r.values["id"].(string); s == id {
				return r, true
			}
		}
		if lt, ok := findDataResourceByID(data, "aws_launch_template", id); ok {
			return lt, true
		}
	}
	if name, _ := spec["launch_template_name"].(string); name != "" {
		for _, r := range resources {
			if r.typ != "aws_launch_template" {
				continue
			}
			if s, _ := r.values["name"].(string); s == name {
				return r, true
			}
		}
		for _, r := range data {
			if r.typ != "aws_launch_template" {
				continue
			}
			if s, _ := r.values["name"].(string); s == name {
				return r, true
			}
		}
	}
	// Fall back to config refs (single distinct template, or match by name).
	var hit planResource
	found := false
	for _, ref := range refs {
		if isDataTypeRef(ref, "aws_launch_template") {
			n := resourceNameFromRef(ref, "aws_launch_template")
			if n == "" {
				continue
			}
			lt, ok := findDataResource(data, "aws_launch_template", n, ref)
			if !ok {
				return planResource{}, false
			}
			if specName, _ := spec["launch_template_name"].(string); specName != "" {
				if s, _ := lt.values["name"].(string); s != "" && s != specName {
					continue
				}
			}
			if found && hit.address != lt.address {
				continue
			}
			hit, found = lt, true
			continue
		}
		n := resourceNameFromRef(ref, "aws_launch_template")
		if n == "" {
			continue
		}
		lt, ok := findManagedResource(resources, "aws_launch_template", n, ref)
		if !ok {
			return planResource{}, false
		}
		if specName, _ := spec["launch_template_name"].(string); specName != "" {
			if s, _ := lt.values["name"].(string); s != "" && s != specName {
				continue
			}
		}
		if found && hit.address != lt.address {
			// Multiple templates in refs without id/name disambiguation.
			continue
		}
		hit, found = lt, true
	}
	if !found {
		return planResource{}, false
	}
	return hit, true
}

func launchTemplateSpecVersion(spec map[string]any, asg planResource, idx configIndex) (ver string, verRefs []string, omitted bool) {
	v, has := spec["version"]
	if !has || v == nil || v == "" {
		return "", nil, true
	}
	switch t := v.(type) {
	case string:
		ver = t
	default:
		ver = fmt.Sprint(t)
	}
	// Collect version refs from mixed_instances_policy raw expressions when present.
	key, ok := resourceKey(asg.address)
	if ok {
		collectVersionRefs(idx.resources[key].raw["mixed_instances_policy"], &verRefs)
	}
	return ver, verRefs, false
}

func collectVersionRefs(v any, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		if _, hasRefs := t["references"]; hasRefs {
			// Only keep refs that point at version attrs when the sibling key context
			// is version — collect all and let refsPointAtVersionAttr filter.
			collectRefs(t, out)
		}
		for k, child := range t {
			if k == "version" {
				collectRefs(child, out)
				continue
			}
			collectVersionRefs(child, out)
		}
	case []any:
		for _, child := range t {
			collectVersionRefs(child, out)
		}
	}
}

// asgLaunchAssociateKnown reports an explicit associate_public_ip_address from
// the launch source. set=true means the source configured a value (or conflict);
// known=false means omit (conflict, disagree, after_unknown).
func asgLaunchAssociateKnown(src asgLaunchSource) (public bool, known bool, set bool) {
	if src.useLC {
		if v, ok := asBoolish(src.lc.values["associate_public_ip_address"]); ok {
			return v, true, true
		}
		if src.lc.attrAfterUnknown("associate_public_ip_address") {
			return false, false, true // set but unknown
		}
		return false, false, false
	}
	if len(src.templates) == 0 {
		return false, false, false
	}
	var seen *bool
	anySet := false
	for _, tmpl := range src.templates {
		if conflict, checked := launchTemplateNICPublicIPConflict(tmpl); checked && conflict {
			return false, false, true
		}
		v, has := launchTemplateAssociatePublicIP(tmpl)
		if !has {
			continue
		}
		anySet = true
		if seen == nil {
			b := v
			seen = &b
			continue
		}
		if *seen != v {
			return false, false, true // disagree → omit
		}
	}
	if !anySet {
		return false, false, false
	}
	return *seen, true, true
}

func asgLaunchHasIPv6(src asgLaunchSource) (has bool, known bool) {
	if src.useLC {
		// Launch configurations have no first-class IPv6 attrs we read.
		return false, true
	}
	sawUnset := false
	for _, tmpl := range src.templates {
		h, k := launchTemplateHasIPv6(tmpl)
		if !k {
			return false, false
		}
		if h {
			return true, true
		}
		sawUnset = true
	}
	if !sawUnset && len(src.templates) == 0 {
		return false, true
	}
	return false, true
}

func asgLaunchSecurityGroupRefs(src asgLaunchSource, idx configIndex) ([]string, bool) {
	if src.useLC {
		refs := filterLikelySGRefs(idx.attrRefs(src.lc.address, "security_groups"))
		if len(refs) == 0 && !hasConfigAttr(idx, src.lc.address, "security_groups") {
			return nil, false
		}
		return uniqueStrings(refs), len(refs) > 0
	}
	if len(src.templates) == 0 {
		return nil, false
	}
	var first []string
	for i, tmpl := range src.templates {
		refs := launchTemplateSecurityGroupRefs(tmpl, idx)
		sorted := append([]string{}, refs...)
		sort.Strings(sorted)
		if i == 0 {
			first = sorted
			continue
		}
		if !stringSlicesEqual(first, sorted) {
			return nil, false // disagree
		}
	}
	if len(first) == 0 {
		return nil, false
	}
	return first, true
}

func resolveASGSubnets(asg planResource, resources, data []planResource, idx configIndex) (subnets []planResource, allResolved, ok bool) {
	return resolveNamedSubnets(asg, "vpc_zone_identifier", resources, data, idx)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
