package client

import (
	"fmt"
	"strings"
)

// awsInstanceElement maps a managed aws_instance to a virtual_machine process.
// No flows are created to or from the instance in this version.
func awsInstanceElement(r planResource, resources []planResource, idx configIndex) *Element {
	_, _, name, _ := splitResourceAddress(r.address)
	attrs := map[string]any{}
	if v, ok := instancePublicIP(r, resources, idx); ok {
		attrs["public_ip"] = v
	}
	if v, ok := instanceAdminPortsOpen(r, resources, idx); ok {
		attrs["admin_ports_open"] = v
	}
	return &Element{
		Name: DisplayName(r.address, name, "virtual_machine"), Type: "process", Kind: "virtual_machine", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

// instancePublicIP reports attributes.public_ip.
//
// true: associate_public_ip_address true; or unset with subnet
// map_public_ip_on_launch true; or an EIP / EIP association to the instance
// (or its primary network interface).
//
// false: public IPv4 known absent, no EIP, and no IPv6 address.
//
// omit (known=false): subnet not in plan / data source, unknown values,
// IPv6 without a public IPv4, conflicting NICs. IPv6 never sets true.
func instancePublicIP(inst planResource, resources []planResource, idx configIndex) (public bool, known bool) {
	if instanceHasEIP(inst, resources, idx) {
		return true, true
	}

	ipv4, ipv4Known := instancePublicIPv4(inst, resources, idx)
	if ipv4Known && ipv4 {
		return true, true
	}

	hasIPv6, ipv6Known := instanceHasIPv6(inst, resources, idx)
	if ipv4Known && !ipv4 {
		if ipv6Known && !hasIPv6 {
			return false, true
		}
		// IPv6 present or unknown → omit (never true from IPv6 alone).
		return false, false
	}
	return false, false
}

// instancePublicIPv4 is the auto-assign / subnet path only (EIP checked separately).
// When the instance declares a launch_template, template network_interfaces
// associate_public_ip_address is consulted before the subnet path. If the
// template is declared but not usable, the result is omitted — never false via
// subnet alone when the template could override it.
func instancePublicIPv4(inst planResource, resources []planResource, idx configIndex) (public bool, known bool) {
	if conflict, ok := instanceNICPublicIPConflict(inst, resources, idx); ok && conflict {
		return false, false
	}
	if v, ok := inst.values["associate_public_ip_address"].(bool); ok {
		return v, true
	}
	if inst.attrAfterUnknown("associate_public_ip_address") {
		return false, false
	}

	lt := resolveInstanceLaunchTemplate(inst, resources, idx)
	if lt.declared && !lt.usable {
		return false, false
	}
	if lt.usable {
		if conflict, checked := launchTemplateNICPublicIPConflict(lt.tmpl); checked && conflict {
			return false, false
		}
		if v, ok := launchTemplateAssociatePublicIP(lt.tmpl); ok {
			return v, true
		}
	}

	// Unset on instance (and template NI): inherit from subnet — instance
	// subnet_id first, else template network_interfaces subnet_id.
	subnet, ok := resolveInstanceSubnet(inst, resources, idx)
	if !ok && lt.usable {
		subnet, ok = resolveLaunchTemplateSubnet(lt.tmpl, resources, idx)
	}
	if !ok {
		return false, false
	}
	if v, ok := subnet.values["map_public_ip_on_launch"].(bool); ok {
		return v, true
	}
	if subnet.attrAfterUnknown("map_public_ip_on_launch") {
		return false, false
	}
	return false, false
}

func instanceNICPublicIPConflict(inst planResource, resources []planResource, idx configIndex) (conflict, checked bool) {
	var seenTrue, seenFalse bool
	for _, ni := range asList(inst.values["network_interface"]) {
		m, ok := ni.(map[string]any)
		if !ok {
			continue
		}
		v, ok := m["associate_public_ip_address"].(bool)
		if !ok {
			continue
		}
		checked = true
		if v {
			seenTrue = true
		} else {
			seenFalse = true
		}
	}
	for _, r := range resources {
		if r.typ != "aws_network_interface" {
			continue
		}
		if !networkInterfaceBelongsTo(r, inst, idx) {
			continue
		}
		v, ok := r.values["associate_public_ip_address"].(bool)
		if !ok {
			continue
		}
		checked = true
		if v {
			seenTrue = true
		} else {
			seenFalse = true
		}
	}
	return seenTrue && seenFalse, checked
}

func instanceHasIPv6(inst planResource, resources []planResource, idx configIndex) (has bool, known bool) {
	if n, ok := number(inst.values["ipv6_address_count"]); ok {
		if n > 0 {
			return true, true
		}
		// 0 is definitive only when no other IPv6 signals are present.
	} else if inst.attrAfterUnknown("ipv6_address_count") {
		return false, false
	}
	if addrs := stringList(inst.values["ipv6_addresses"]); len(addrs) > 0 {
		return true, true
	}
	if inst.attrAfterUnknown("ipv6_addresses") {
		return false, false
	}
	if addrs := stringList(inst.values["ipv6_address_list"]); len(addrs) > 0 {
		return true, true
	}

	lt := resolveInstanceLaunchTemplate(inst, resources, idx)
	subnet, ok := resolveInstanceSubnet(inst, resources, idx)
	if !ok && lt.usable {
		subnet, ok = resolveLaunchTemplateSubnet(lt.tmpl, resources, idx)
	}
	if ok {
		if v, ok := subnet.values["assign_ipv6_address_on_creation"].(bool); ok && v {
			return true, true
		}
		if subnet.attrAfterUnknown("assign_ipv6_address_on_creation") {
			return false, false
		}
	}

	// Instance set count==0 → definitive absence (instance wins over template).
	if n, ok := number(inst.values["ipv6_address_count"]); ok && n == 0 {
		return false, true
	}

	// Instance unset: template may supply ipv6_address_count / NI ipv6 settings.
	if lt.declared && !lt.usable {
		return false, false
	}
	if lt.usable {
		return launchTemplateHasIPv6(lt.tmpl)
	}

	// No positive IPv6 signal and count is unset → treat as no IPv6.
	if _, hasCount := inst.values["ipv6_address_count"]; !hasCount {
		return false, true
	}
	return false, true
}

func instanceHasEIP(inst planResource, resources []planResource, idx configIndex) bool {
	instName := localTypeName(inst.address)
	for _, r := range resources {
		switch r.typ {
		case "aws_eip":
			if refsPointAtInstance(idx.attrRefs(r.address, "instance"), inst, instName) {
				return true
			}
			if refsPointAtInstance(idx.attrRefs(r.address, "instance_id"), inst, instName) {
				return true
			}
		case "aws_eip_association":
			if refsPointAtInstance(idx.attrRefs(r.address, "instance_id"), inst, instName) {
				return true
			}
			if refsPointAtInstance(idx.attrRefs(r.address, "instance"), inst, instName) {
				return true
			}
			for _, ref := range idx.attrRefs(r.address, "network_interface_id") {
				if networkInterfaceRefBelongsTo(ref, inst, resources, idx) {
					return true
				}
			}
		}
	}
	return false
}

func refsPointAtInstance(refs []string, inst planResource, instName string) bool {
	for _, ref := range refs {
		if containsResource(ref, "aws_instance", instName) {
			return true
		}
		if strings.Contains(ref, inst.address) {
			return true
		}
	}
	return false
}

func networkInterfaceBelongsTo(ni, inst planResource, idx configIndex) bool {
	instName := localTypeName(inst.address)
	for _, attr := range []string{"instance", "instance_id"} {
		if refsPointAtInstance(idx.attrRefs(ni.address, attr), inst, instName) {
			return true
		}
	}
	// Inline network_interface blocks on the instance reference an ENI by id —
	// matching by attachment is config-ref only (no id equality on wire values).
	return false
}

func networkInterfaceRefBelongsTo(ref string, inst planResource, resources []planResource, idx configIndex) bool {
	name := resourceNameFromRef(ref, "aws_network_interface")
	if name == "" {
		return false
	}
	for _, r := range resources {
		if r.typ != "aws_network_interface" {
			continue
		}
		if localTypeName(r.address) != name {
			continue
		}
		if networkInterfaceBelongsTo(r, inst, idx) {
			return true
		}
		// Primary ENI created for this instance in the same module with no
		// explicit instance attr: treat attachment via eip_association alone
		// only when the ENI address appears in the instance's network_interface refs.
		for _, ir := range idx.attrRefs(inst.address, "network_interface") {
			if containsResource(ir, "aws_network_interface", name) {
				return true
			}
		}
	}
	return false
}

func resolveInstanceSubnet(inst planResource, resources []planResource, idx configIndex) (planResource, bool) {
	refs := instanceSubnetRefs(inst, idx)
	if len(refs) == 0 {
		return planResource{}, false
	}
	var hit planResource
	found := false
	for _, ref := range refs {
		if isVarRef(ref) {
			continue
		}
		if strings.Contains(ref, "data.aws_subnet") || strings.Contains(ref, ".data.aws_subnet.") {
			return planResource{}, false
		}
		if isModuleOutputRef(ref) {
			sn, ok := resolveModuleOutputResource(ref, "aws_subnet", idx, resources, 0)
			if !ok {
				return planResource{}, false
			}
			if found && hit.address != sn.address {
				return planResource{}, false
			}
			hit, found = sn, true
			continue
		}
		if isBareModuleRef(ref) {
			continue
		}
		name := resourceNameFromRef(ref, "aws_subnet")
		if name == "" {
			return planResource{}, false
		}
		sn, ok := findManagedResource(resources, "aws_subnet", name, ref)
		if !ok {
			return planResource{}, false
		}
		if found && hit.address != sn.address {
			return planResource{}, false
		}
		hit, found = sn, true
	}
	if !found {
		return planResource{}, false
	}
	return hit, true
}

func instanceSubnetRefs(inst planResource, idx configIndex) []string {
	var refs []string
	refs = append(refs, idx.attrRefs(inst.address, "subnet_id")...)
	mod, _, _, ok := splitResourceAddress(inst.address)
	if !ok {
		return uniqueStrings(refs)
	}
	for m := mod; m != ""; m = parentModuleAddr(m) {
		refs = append(refs, idx.calls[m].refs["subnet_id"]...)
	}
	return uniqueStrings(refs)
}

func findManagedResource(resources []planResource, typ, name, ref string) (planResource, bool) {
	var hits []planResource
	for _, r := range resources {
		if r.typ != typ {
			continue
		}
		if localTypeName(r.address) == name {
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
		mod, _, _, _ := splitResourceAddress(h.address)
		if mod == "" && !strings.Contains(ref, "module.") {
			return h, true
		}
		if mod != "" && strings.Contains(ref, mod+".") {
			return h, true
		}
	}
	return planResource{}, false
}

func resourceNameFromRef(ref, typ string) string {
	needle := typ + "."
	rest := ref
	for {
		i := strings.Index(rest, needle)
		if i < 0 {
			return ""
		}
		rest = rest[i+len(needle):]
		j := 0
		for j < len(rest) && rest[j] != '.' && rest[j] != '[' && rest[j] != '"' {
			j++
		}
		if j == 0 {
			continue
		}
		return rest[:j]
	}
}

// instanceAdminPortsOpen reports attributes.admin_ports_open.
//
// true if any resolved SG is world on TCP 22 or 3389 (true wins over unknown).
// false if every SG was read and none is.
// omit if no SGs, unresolvable refs, or none world and any unknown.
// Only tcp and all-protocol (-1) rules count; udp/icmp do not.
func instanceAdminPortsOpen(inst planResource, resources []planResource, idx configIndex) (open bool, known bool) {
	sgs, ok := resolveInstanceSecurityGroups(inst, resources, idx)
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

func resolveInstanceSecurityGroups(inst planResource, resources []planResource, idx configIndex) ([]planResource, bool) {
	refs := instanceSecurityGroupRefs(inst, resources, idx)
	if len(refs) == 0 {
		return nil, false
	}
	var out []planResource
	seen := map[string]bool{}
	for _, ref := range refs {
		if isVarRef(ref) {
			continue
		}
		sg, ok, skip := resolveSecurityGroupRefDetailed(ref, resources, idx)
		if skip {
			continue
		}
		if !ok {
			// Unresolvable security_groups name / data source → unknown.
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

func instanceSecurityGroupRefs(inst planResource, resources []planResource, idx configIndex) []string {
	var refs []string
	refs = append(refs, idx.attrRefs(inst.address, "vpc_security_group_ids")...)
	refs = append(refs, idx.attrRefs(inst.address, "security_groups")...)
	mod, _, _, ok := splitResourceAddress(inst.address)
	if ok {
		for m := mod; m != ""; m = parentModuleAddr(m) {
			refs = append(refs, idx.calls[m].refs["vpc_security_group_ids"]...)
			refs = append(refs, idx.calls[m].refs["security_groups"]...)
		}
	}
	// Inline network_interface blocks may list security_groups; keep only SG-like refs.
	refs = append(refs, idx.attrRefs(inst.address, "network_interface")...)
	for _, r := range resources {
		if r.typ != "aws_network_interface" {
			continue
		}
		if !networkInterfaceBelongsTo(r, inst, idx) {
			continue
		}
		refs = append(refs, idx.attrRefs(r.address, "security_groups")...)
		refs = append(refs, idx.attrRefs(r.address, "vpc_security_group_ids")...)
	}
	filtered := uniqueStrings(filterLikelySGRefs(refs))
	if instanceSetsSecurityGroups(inst, resources, idx) {
		return filtered
	}

	lt := resolveInstanceLaunchTemplate(inst, resources, idx)
	if lt.declared && !lt.usable {
		return nil
	}
	if lt.usable {
		return launchTemplateSecurityGroupRefs(lt.tmpl, idx)
	}
	return filtered
}

func instanceSetsSecurityGroups(inst planResource, resources []planResource, idx configIndex) bool {
	if hasConfigAttr(idx, inst.address, "vpc_security_group_ids") {
		return true
	}
	if hasConfigAttr(idx, inst.address, "security_groups") {
		return true
	}
	if len(filterLikelySGRefs(idx.attrRefs(inst.address, "network_interface"))) > 0 {
		return true
	}
	for _, r := range resources {
		if r.typ != "aws_network_interface" {
			continue
		}
		if !networkInterfaceBelongsTo(r, inst, idx) {
			continue
		}
		if hasConfigAttr(idx, r.address, "security_groups") || hasConfigAttr(idx, r.address, "vpc_security_group_ids") {
			return true
		}
	}
	return false
}

func filterLikelySGRefs(refs []string) []string {
	var out []string
	for _, ref := range refs {
		if looksLikeSecurityGroupRef(ref) || isModuleOutputRef(ref) || isBareModuleRef(ref) || isVarRef(ref) {
			out = append(out, ref)
		}
	}
	return out
}

// classifySGAdminIngress is classifySGIngress for SSH/RDP: only tcp and
// all-protocol (-1) sources participate; udp/icmp are ignored.
func classifySGAdminIngress(sg planResource, resources []planResource, idx configIndex, port int) (cls networkSourceClass, worldOnPort bool) {
	sources := collectSGIngressSources(sg, resources, idx)
	if len(sources) == 0 {
		return netSrcRestricted, false
	}
	allRestricted := true
	sawAdminSource := false
	for _, src := range sources {
		if !adminProtocolCounts(src.protocol) {
			continue
		}
		sawAdminSource = true
		c := classifyIngressSource(src, resources, idx)
		covers := ingressCoversPort(src, port, true)
		switch c {
		case netSrcWorld:
			if covers == coverYes {
				return netSrcWorld, true
			}
			if covers == coverUnknown {
				return netSrcUnknown, false
			}
			allRestricted = false
		case netSrcUnknown:
			if covers != coverNo {
				return netSrcUnknown, false
			}
		case netSrcRestricted:
			// ok
		}
	}
	if !sawAdminSource {
		// Only non-tcp sources → not open on admin ports.
		return netSrcRestricted, false
	}
	if allRestricted {
		return netSrcRestricted, false
	}
	return netSrcRestricted, false
}

func adminProtocolCounts(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "tcp", "-1", "all":
		return true
	default:
		return false
	}
}

// launchTemplateRef holds a resolved in-plan aws_launch_template when the
// instance's launch_template block points at one whose planned values are
// safe to use for this plan (version rule).
type launchTemplateRef struct {
	tmpl     planResource
	declared bool // instance has a launch_template block
	usable   bool // planned values apply to what this instance will launch
}

func resolveInstanceLaunchTemplate(inst planResource, resources []planResource, idx configIndex) launchTemplateRef {
	if !instanceDeclaresLaunchTemplate(inst, idx) {
		return launchTemplateRef{}
	}
	out := launchTemplateRef{declared: true}
	tmpl, ok := findInstanceLaunchTemplate(inst, resources, idx)
	if !ok {
		return out
	}
	out.tmpl = tmpl
	if !launchTemplateVersionUsable(inst, tmpl, idx) {
		return out
	}
	out.usable = true
	return out
}

func instanceDeclaresLaunchTemplate(inst planResource, idx configIndex) bool {
	if hasConfigAttr(idx, inst.address, "launch_template") {
		return true
	}
	return len(asList(inst.values["launch_template"])) > 0
}

func findInstanceLaunchTemplate(inst planResource, resources []planResource, idx configIndex) (planResource, bool) {
	refs := idx.attrRefs(inst.address, "launch_template")
	var hit planResource
	found := false
	for _, ref := range refs {
		if isVarRef(ref) || isBareModuleRef(ref) {
			continue
		}
		if strings.Contains(ref, "data.aws_launch_template") {
			return planResource{}, false
		}
		if isModuleOutputRef(ref) {
			lt, ok := resolveModuleOutputResource(ref, "aws_launch_template", idx, resources, 0)
			if !ok {
				return planResource{}, false
			}
			if found && hit.address != lt.address {
				return planResource{}, false
			}
			hit, found = lt, true
			continue
		}
		name := resourceNameFromRef(ref, "aws_launch_template")
		if name == "" {
			continue
		}
		lt, ok := findManagedResource(resources, "aws_launch_template", name, ref)
		if !ok {
			return planResource{}, false
		}
		if found && hit.address != lt.address {
			return planResource{}, false
		}
		hit, found = lt, true
	}
	if !found {
		return planResource{}, false
	}
	return hit, true
}

// launchTemplateVersionUsable reports whether the template's planned values
// are what this instance will launch with.
//
//   - $Latest or a reference to latest_version → use
//   - version omitted, $Default, or reference to default_version → use only if
//     update_default_version is true OR the template is being created in this
//     plan (actions == ["create"]); otherwise unknown
//   - pinned number / anything else → unknown
func launchTemplateVersionUsable(inst planResource, tmpl planResource, idx configIndex) bool {
	ver, verRefs, omitted := instanceLaunchTemplateVersion(inst, idx)
	if refsPointAtVersionAttr(verRefs, "latest_version") || ver == "$Latest" {
		return true
	}
	if refsPointAtVersionAttr(verRefs, "default_version") || ver == "$Default" || omitted || ver == "" {
		if v, ok := asBoolish(tmpl.values["update_default_version"]); ok && v {
			return true
		}
		if len(tmpl.actions) == 1 && tmpl.actions[0] == "create" {
			return true
		}
		return false
	}
	return false
}

func refsPointAtVersionAttr(refs []string, attr string) bool {
	suffix := "." + attr
	for _, ref := range refs {
		if strings.HasSuffix(ref, suffix) {
			return true
		}
	}
	return false
}

// instanceLaunchTemplateVersion reads the instance launch_template version
// expression (config first, then planned values). omitted is true when the
// version argument is absent.
func instanceLaunchTemplateVersion(inst planResource, idx configIndex) (ver string, verRefs []string, omitted bool) {
	key, ok := resourceKey(inst.address)
	if ok {
		if blocks := asList(idx.resources[key].raw["launch_template"]); len(blocks) > 0 {
			block, _ := blocks[0].(map[string]any)
			if block != nil {
				vexpr, has := block["version"]
				if !has {
					return "", nil, true
				}
				if m, ok := vexpr.(map[string]any); ok {
					if cv, ok := m["constant_value"]; ok {
						ver = fmt.Sprint(cv)
					}
					collectRefs(vexpr, &verRefs)
				}
				return ver, verRefs, false
			}
		}
	}
	for _, raw := range asList(inst.values["launch_template"]) {
		m, _ := raw.(map[string]any)
		if m == nil {
			continue
		}
		v, has := m["version"]
		if !has || v == nil {
			return "", nil, true
		}
		switch t := v.(type) {
		case string:
			return t, nil, false
		default:
			return fmt.Sprint(t), nil, false
		}
	}
	return "", nil, true
}

func launchTemplateNICPublicIPConflict(tmpl planResource) (conflict, checked bool) {
	var seenTrue, seenFalse bool
	for _, ni := range asList(tmpl.values["network_interfaces"]) {
		m, ok := ni.(map[string]any)
		if !ok {
			continue
		}
		v, ok := asBoolish(m["associate_public_ip_address"])
		if !ok {
			continue
		}
		checked = true
		if v {
			seenTrue = true
		} else {
			seenFalse = true
		}
	}
	return seenTrue && seenFalse, checked
}

func launchTemplateAssociatePublicIP(tmpl planResource) (public bool, ok bool) {
	var seen *bool
	for _, ni := range asList(tmpl.values["network_interfaces"]) {
		m, isMap := ni.(map[string]any)
		if !isMap {
			continue
		}
		v, has := asBoolish(m["associate_public_ip_address"])
		if !has {
			continue
		}
		if seen == nil {
			b := v
			seen = &b
			continue
		}
		if *seen != v {
			return false, false
		}
	}
	if seen == nil {
		return false, false
	}
	return *seen, true
}

func launchTemplateHasIPv6(tmpl planResource) (has bool, known bool) {
	if n, ok := number(tmpl.values["ipv6_address_count"]); ok {
		if n > 0 {
			return true, true
		}
	} else if tmpl.attrAfterUnknown("ipv6_address_count") {
		return false, false
	}
	for _, ni := range asList(tmpl.values["network_interfaces"]) {
		m, ok := ni.(map[string]any)
		if !ok {
			continue
		}
		if n, ok := number(m["ipv6_address_count"]); ok && n > 0 {
			return true, true
		}
		if addrs := stringList(m["ipv6_addresses"]); len(addrs) > 0 {
			return true, true
		}
	}
	if n, ok := number(tmpl.values["ipv6_address_count"]); ok && n == 0 {
		return false, true
	}
	return false, true
}

func launchTemplateSecurityGroupRefs(tmpl planResource, idx configIndex) []string {
	vpc := filterLikelySGRefs(idx.attrRefs(tmpl.address, "vpc_security_group_ids"))
	if len(vpc) > 0 || hasConfigAttr(idx, tmpl.address, "vpc_security_group_ids") {
		return uniqueStrings(vpc)
	}
	return uniqueStrings(filterLikelySGRefs(idx.attrRefs(tmpl.address, "network_interfaces")))
}

func resolveLaunchTemplateSubnet(tmpl planResource, resources []planResource, idx configIndex) (planResource, bool) {
	var refs []string
	for _, ref := range idx.attrRefs(tmpl.address, "network_interfaces") {
		if strings.Contains(ref, "aws_subnet") {
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return planResource{}, false
	}
	var hit planResource
	found := false
	for _, ref := range refs {
		if isVarRef(ref) {
			continue
		}
		if strings.Contains(ref, "data.aws_subnet") || strings.Contains(ref, ".data.aws_subnet.") {
			return planResource{}, false
		}
		if isModuleOutputRef(ref) {
			sn, ok := resolveModuleOutputResource(ref, "aws_subnet", idx, resources, 0)
			if !ok {
				return planResource{}, false
			}
			if found && hit.address != sn.address {
				return planResource{}, false
			}
			hit, found = sn, true
			continue
		}
		if isBareModuleRef(ref) {
			continue
		}
		name := resourceNameFromRef(ref, "aws_subnet")
		if name == "" {
			return planResource{}, false
		}
		sn, ok := findManagedResource(resources, "aws_subnet", name, ref)
		if !ok {
			return planResource{}, false
		}
		if found && hit.address != sn.address {
			return planResource{}, false
		}
		hit, found = sn, true
	}
	if !found {
		return planResource{}, false
	}
	return hit, true
}

// asBoolish coerces Terraform bool or AWS-provider string bools ("true"/"false").
func asBoolish(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "1":
			return true, true
		case "false", "0":
			return false, true
		}
	}
	return false, false
}
