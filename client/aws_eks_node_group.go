package client

import (
	"strings"
)

// awsEKSNodeGroupElement maps a managed aws_eks_node_group to a virtual_machine
// process for FR-034. No flows are created. The display name always reads as
// an EKS node group (never "instance").
func awsEKSNodeGroupElement(r planResource, resources, data []planResource, idx configIndex) *Element {
	_, _, name, _ := splitResourceAddress(r.address)
	attrs := map[string]any{}
	// CreateNodegroup: if launchTemplate is set, remoteAccess must not be —
	// otherwise creation fails
	// (https://docs.aws.amazon.com/eks/latest/APIReference/API_CreateNodegroup.html).
	if ngDeclaresRemoteAccess(r, idx) && instanceDeclaresLaunchTemplate(r, idx) {
		return &Element{
			Name: EKSNodeGroupDisplayName(r.address, name), Type: "process", Kind: "virtual_machine", Provider: "aws",
			Provenance: "iac",
			Evidence:   Evidence{Addresses: []string{r.address}},
			Attributes: attrs,
		}
	}
	if v, ok := ngPublicIP(r, resources, data, idx); ok {
		attrs["public_ip"] = v
	}
	if v, ok := ngAdminPortsOpen(r, resources, data, idx); ok {
		attrs["admin_ports_open"] = v
	}
	return &Element{
		Name: EKSNodeGroupDisplayName(r.address, name), Type: "process", Kind: "virtual_machine", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

// ngPublicIP: launch-template NI associate_public_ip_address when explicit;
// else subnet_ids with the ASG subnet rule.
func ngPublicIP(ng planResource, resources, data []planResource, idx configIndex) (public bool, known bool) {
	if instanceDeclaresLaunchTemplate(ng, idx) {
		lt := resolveInstanceLaunchTemplate(ng, resources, data, idx)
		if lt.declared && !lt.usable {
			return false, false
		}
		if lt.usable {
			src := asgLaunchSource{templates: []planResource{lt.tmpl}}
			if assoc, knownAssoc, set := asgLaunchAssociateKnown(src); set {
				if !knownAssoc {
					return false, false
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
			return ngPublicIPFromSubnets(ng, resources, data, idx, hasIPv6, ipv6Known)
		}
	}
	return ngPublicIPFromSubnets(ng, resources, data, idx, false, true)
}

func ngPublicIPFromSubnets(ng planResource, resources, data []planResource, idx configIndex, tmplIPv6, tmplIPv6Known bool) (public bool, known bool) {
	subnets, allResolved, ok := resolveNamedSubnets(ng, "subnet_ids", resources, data, idx)
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

// ngAdminPortsOpen implements the remote_access / launch_template / cluster-SG ladder.
//
// remote_access with ec2_ssh_key and empty source_security_group_ids opens 22
// (and 3389 on Windows AMIs) to 0.0.0.0/0 on the node remote-access SG —
// https://docs.aws.amazon.com/eks/latest/APIReference/API_RemoteAccessConfig.html
//
// With a launch template that sets security groups, Fray classifies those SGs
// only: Amazon EKS does not add the cluster security group in that case
// (https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html#using-custom-security-groups).
//
// Otherwise nodes use the cluster security group. In-plan ingress rules that
// target vpc_config.cluster_security_group_id are classified; with none, the
// documented default has no internet SSH/RDP —
// https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html
func ngAdminPortsOpen(ng planResource, resources, data []planResource, idx configIndex) (open bool, known bool) {
	hasRA := ngDeclaresRemoteAccess(ng, idx)
	hasLT := instanceDeclaresLaunchTemplate(ng, idx)
	if hasRA && hasLT {
		return false, false
	}

	if hasRA {
		if ngRemoteAccessWorldOpen(ng, idx) {
			return true, true
		}
		// Restricted source SGs (or remote_access without a key) → cluster SG path.
		return ngAdminFromClusterSG(ng, resources, data, idx)
	}

	if hasLT {
		lt := resolveInstanceLaunchTemplate(ng, resources, data, idx)
		if lt.declared && !lt.usable {
			return false, false
		}
		if lt.usable {
			refs := launchTemplateSecurityGroupRefs(lt.tmpl, idx)
			if len(refs) > 0 {
				return adminPortsFromSGRefs(refs, resources, data, idx)
			}
		}
		return ngAdminFromClusterSG(ng, resources, data, idx)
	}

	return ngAdminFromClusterSG(ng, resources, data, idx)
}

func adminPortsFromSGRefs(refs []string, resources, data []planResource, idx configIndex) (open bool, known bool) {
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

func ngDeclaresRemoteAccess(ng planResource, idx configIndex) bool {
	if hasConfigAttr(idx, ng.address, "remote_access") {
		return true
	}
	return len(asList(ng.values["remote_access"])) > 0
}

// ngRemoteAccessWorldOpen is true when remote_access sets ec2_ssh_key and does
// not list source_security_group_ids (AWS opens the admin port to 0.0.0.0/0).
func ngRemoteAccessWorldOpen(ng planResource, idx configIndex) bool {
	hasKey := false
	for _, raw := range asList(ng.values["remote_access"]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		key, _ := m["ec2_ssh_key"].(string)
		if key == "" {
			continue
		}
		hasKey = true
		if len(stringList(m["source_security_group_ids"])) > 0 {
			return false
		}
	}
	if !hasKey {
		// Key only in config (unknown after apply) still counts if the block sets it.
		key, ok := resourceKey(ng.address)
		if !ok {
			return false
		}
		for _, block := range asList(idx.resources[key].raw["remote_access"]) {
			m, _ := block.(map[string]any)
			if m == nil {
				continue
			}
			if _, has := m["ec2_ssh_key"]; has {
				hasKey = true
			}
		}
	}
	if !hasKey {
		return false
	}
	if len(ngRemoteAccessSourceSGRefs(ng, idx)) > 0 {
		return false
	}
	return true
}

func ngRemoteAccessSourceSGRefs(ng planResource, idx configIndex) []string {
	key, ok := resourceKey(ng.address)
	if !ok {
		return nil
	}
	var refs []string
	for _, block := range asList(idx.resources[key].raw["remote_access"]) {
		m, _ := block.(map[string]any)
		if m == nil {
			continue
		}
		collectRefs(m["source_security_group_ids"], &refs)
	}
	for _, raw := range asList(ng.values["remote_access"]) {
		m, _ := raw.(map[string]any)
		if m == nil {
			continue
		}
		refs = append(refs, stringList(m["source_security_group_ids"])...)
	}
	return uniqueStrings(filterLikelySGRefs(refs))
}

func ngAdminFromClusterSG(ng planResource, resources, data []planResource, idx configIndex) (open bool, known bool) {
	cluster, ok := resolveNGCluster(ng, resources, data, idx)
	if !ok {
		// No cluster in plan — cannot read extra rules; documented default is closed.
		return false, true
	}
	sources := collectClusterSGIngressSources(cluster, resources, idx)
	if isDataAddress(cluster.address) {
		// Data clusters expose identity / vpc_config.cluster_security_group_id for
		// linkage only. In-plan rules attached to that SG are positive evidence;
		// absence must not invent "closed" (rules may exist outside the plan).
		for _, port := range []int{22, 3389} {
			_, world := classifyAdminIngressSources(sources, resources, idx, port)
			if world {
				return true, true
			}
		}
		return false, false
	}
	sawUnknown := false
	for _, port := range []int{22, 3389} {
		cls, world := classifyAdminIngressSources(sources, resources, idx, port)
		if world {
			return true, true
		}
		if cls == netSrcUnknown {
			sawUnknown = true
		}
	}
	if sawUnknown {
		return false, false
	}
	// No world rules (and no unknown) → false: default cluster SG has no internet SSH/RDP.
	return false, true
}

func resolveNGCluster(ng planResource, resources, data []planResource, idx configIndex) (planResource, bool) {
	refs := idx.attrRefs(ng.address, "cluster_name")
	var hit planResource
	found := false
	for _, ref := range refs {
		if isVarRef(ref) || isBareModuleRef(ref) {
			continue
		}
		if isDataTypeRef(ref, "aws_eks_cluster") {
			name := resourceNameFromRef(ref, "aws_eks_cluster")
			if name == "" {
				continue
			}
			c, ok := findDataResource(data, "aws_eks_cluster", name, ref)
			if !ok {
				return planResource{}, false
			}
			if found && hit.address != c.address {
				return planResource{}, false
			}
			hit, found = c, true
			continue
		}
		if isModuleOutputRef(ref) {
			c, ok := resolveModuleOutputResource(ref, "aws_eks_cluster", idx, resources, 0)
			if !ok {
				return planResource{}, false
			}
			if found && hit.address != c.address {
				return planResource{}, false
			}
			hit, found = c, true
			continue
		}
		name := resourceNameFromRef(ref, "aws_eks_cluster")
		if name == "" {
			continue
		}
		c, ok := findManagedResource(resources, "aws_eks_cluster", name, ref)
		if !ok {
			return planResource{}, false
		}
		if found && hit.address != c.address {
			return planResource{}, false
		}
		hit, found = c, true
	}
	if !found {
		return planResource{}, false
	}
	return hit, true
}

func collectClusterSGIngressSources(cluster planResource, resources []planResource, idx configIndex) []ingressSource {
	var out []ingressSource
	for _, r := range resources {
		switch r.typ {
		case "aws_vpc_security_group_ingress_rule":
			if !ruleTargetsClusterSG(r, cluster, idx) {
				continue
			}
			out = append(out, ingressFromVPCRule(r, idx))
		case "aws_security_group_rule":
			if !ruleTargetsClusterSG(r, cluster, idx) {
				continue
			}
			typ, _ := r.values["type"].(string)
			if !strings.EqualFold(typ, "ingress") {
				continue
			}
			out = append(out, ingressFromSGRule(r, idx))
		}
	}
	return out
}

func ruleTargetsClusterSG(rule, cluster planResource, idx configIndex) bool {
	clusterName := localTypeName(cluster.address)
	for _, ref := range idx.attrRefs(rule.address, "security_group_id") {
		if !strings.Contains(ref, "cluster_security_group_id") {
			continue
		}
		if containsResource(ref, "aws_eks_cluster", clusterName) {
			return true
		}
		if strings.Contains(ref, cluster.address) {
			return true
		}
	}
	return false
}

// classifyAdminIngressSources is classifySGAdminIngress over an explicit source list.
func classifyAdminIngressSources(sources []ingressSource, resources []planResource, idx configIndex, port int) (cls networkSourceClass, worldOnPort bool) {
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
		return netSrcRestricted, false
	}
	if allRestricted {
		return netSrcRestricted, false
	}
	return netSrcRestricted, false
}

// resolveNamedSubnets resolves subnet refs under attr (e.g. subnet_ids).
func resolveNamedSubnets(holder planResource, attr string, resources, data []planResource, idx configIndex) (subnets []planResource, allResolved, ok bool) {
	refs := idx.attrRefs(holder.address, attr)
	if len(refs) == 0 {
		return nil, false, false
	}
	seen := map[string]bool{}
	allResolved = true
	foundAny := false
	for _, ref := range refs {
		if isVarRef(ref) {
			allResolved = false
			continue
		}
		if isBareModuleRef(ref) {
			continue
		}
		if isDataTypeRef(ref, "aws_subnet") {
			name := resourceNameFromRef(ref, "aws_subnet")
			if name == "" {
				allResolved = false
				ok = true
				continue
			}
			sn, resolved := findDataResource(data, "aws_subnet", name, ref)
			if !resolved {
				allResolved = false
				ok = true
				continue
			}
			if seen[sn.address] {
				continue
			}
			seen[sn.address] = true
			subnets = append(subnets, sn)
			foundAny = true
			continue
		}
		if isModuleOutputRef(ref) {
			sn, resolved := resolveModuleOutputResource(ref, "aws_subnet", idx, resources, 0)
			if !resolved {
				allResolved = false
				ok = true
				continue
			}
			if seen[sn.address] {
				continue
			}
			seen[sn.address] = true
			subnets = append(subnets, sn)
			foundAny = true
			continue
		}
		name := resourceNameFromRef(ref, "aws_subnet")
		if name == "" {
			continue
		}
		sn, resolved := findManagedResource(resources, "aws_subnet", name, ref)
		if !resolved {
			allResolved = false
			ok = true
			continue
		}
		if seen[sn.address] {
			continue
		}
		seen[sn.address] = true
		subnets = append(subnets, sn)
		foundAny = true
	}
	if !foundAny && !ok {
		return nil, false, false
	}
	return subnets, allResolved && foundAny, true
}
