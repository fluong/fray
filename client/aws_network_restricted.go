package client

import (
	"net"
	"strings"
)

// networkSourceClass is the closed classification of one ingress source.
type networkSourceClass int

const (
	netSrcRestricted networkSourceClass = iota
	netSrcWorld
	netSrcUnknown
)

// lbPublic reports attributes.public for an aws_lb.
//
// Outcomes (known=false ⇒ omit the attribute):
//   - internal=true → public=false (no inferred public_client / edge flow)
//   - internal=false and a security-group ingress classifies as world on a
//     listener port → public=true (awsConnections emits public_client +
//     network boundary flow)
//   - internal=false and every resolved SG is restricted on listener ports →
//     public=false
//   - internal absent, unresolvable SG refs (incl. data.aws_security_group),
//     unknown prefix lists, or port-specific world with unknown listener
//     ports → known=false (omit; no public_client path — fail closed on
//     exposure inference)
//
// Uses the same ingress collection and world classification as
// dbNetworkRestricted (inline ingress, aws_security_group_rule,
// aws_vpc_security_group_ingress_rule, managed prefix lists; IPv4 </16 and
// IPv6 </32 are world). SG associations are resolved across modules.
func lbPublic(lb planResource, resources []planResource, idx configIndex) (public bool, known bool) {
	internal, ok := lb.values["internal"].(bool)
	if !ok {
		return false, false
	}
	if internal {
		return false, true
	}
	return lbInternetExposed(lb, resources, idx)
}

// lbInternetExposed is the SG/world half of lbPublic (caller already excluded internal).
func lbInternetExposed(lb planResource, resources []planResource, idx configIndex) (exposed bool, known bool) {
	sgs, ok := resolveLBSecurityGroups(lb, resources, idx)
	if !ok || len(sgs) == 0 {
		return false, false
	}
	ports := listenerPortSet(lb, resources, idx)
	portKnown := len(ports) > 0
	for _, sg := range sgs {
		if !portKnown {
			cls, world := classifySGIngress(sg, resources, idx, 0, false)
			switch {
			case world:
				return true, true
			case cls == netSrcUnknown:
				return false, false
			}
			continue
		}
		for port := range ports {
			cls, world := classifySGIngress(sg, resources, idx, port, true)
			switch {
			case world:
				return true, true
			case cls == netSrcUnknown:
				return false, false
			}
		}
	}
	return false, true
}

func resolveLBSecurityGroups(lb planResource, resources []planResource, idx configIndex) ([]planResource, bool) {
	refs := lbSecurityGroupRefs(lb, idx)
	if len(refs) == 0 {
		return nil, false
	}
	var out []planResource
	seen := map[string]bool{}
	for _, ref := range refs {
		if isVarRef(ref) {
			continue
		}
		if strings.Contains(ref, "data.aws_security_group.") || strings.Contains(ref, ".data.aws_security_group.") {
			return nil, false
		}
		name := securityGroupNameFromRef(ref)
		if name == "" {
			if looksLikeSecurityGroupRef(ref) {
				return nil, false
			}
			continue
		}
		sg, ok := findSecurityGroup(resources, name, ref)
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

func lbSecurityGroupRefs(lb planResource, idx configIndex) []string {
	var refs []string
	refs = append(refs, idx.attrRefs(lb.address, "security_groups")...)
	mod, _, _, ok := splitResourceAddress(lb.address)
	if !ok {
		return uniqueStrings(refs)
	}
	for m := mod; m != ""; m = parentModuleAddr(m) {
		refs = append(refs, idx.calls[m].refs["security_groups"]...)
	}
	return uniqueStrings(refs)
}

func listenerPortSet(lb planResource, resources []planResource, idx configIndex) map[int]bool {
	ports := map[int]bool{}
	for _, ln := range listenersFor(lb, resources, idx) {
		if n, ok := number(ln.values["port"]); ok {
			ports[n] = true
		}
	}
	return ports
}

// dbNetworkRestricted reports attributes.network_restricted for an RDS /
// Aurora instance or cluster. known=false means leave the attribute absent.
func dbNetworkRestricted(db planResource, resources []planResource, idx configIndex) (restricted bool, known bool) {
	sgs, ok := resolveDBSecurityGroups(db, resources, idx)
	if !ok {
		return false, false
	}
	if len(sgs) == 0 {
		return false, false
	}
	port, portKnown := dbListenPort(db.values)
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

func resolveDBSecurityGroups(db planResource, resources []planResource, idx configIndex) ([]planResource, bool) {
	refs := dbVpcSecurityGroupRefs(db, idx)
	if len(refs) == 0 {
		// No config references: cannot trust plan ID lists alone (often computed).
		return nil, false
	}
	var out []planResource
	seen := map[string]bool{}
	for _, ref := range refs {
		// Module inputs (var.*) are resolved via ancestor module_call expressions.
		if isVarRef(ref) {
			continue
		}
		if strings.Contains(ref, "data.aws_security_group.") || strings.Contains(ref, ".data.aws_security_group.") {
			return nil, false
		}
		name := securityGroupNameFromRef(ref)
		if name == "" {
			if looksLikeSecurityGroupRef(ref) {
				return nil, false
			}
			continue
		}
		sg, ok := findSecurityGroup(resources, name, ref)
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

func dbVpcSecurityGroupRefs(db planResource, idx configIndex) []string {
	var refs []string
	refs = append(refs, idx.attrRefs(db.address, "vpc_security_group_ids")...)
	// Walk module call ancestors (module.db, then module.db.module.db_instance, …).
	mod, _, _, ok := splitResourceAddress(db.address)
	if !ok {
		return uniqueStrings(refs)
	}
	for m := mod; m != ""; m = parentModuleAddr(m) {
		refs = append(refs, idx.calls[m].refs["vpc_security_group_ids"]...)
	}
	return uniqueStrings(refs)
}

// parentModuleAddr returns the parent of a module address (module.a.module.b → module.a).
func parentModuleAddr(moduleAddr string) string {
	if moduleAddr == "" || !strings.HasPrefix(moduleAddr, "module.") {
		return ""
	}
	rest := moduleAddr
	var parts []string
	for strings.HasPrefix(rest, "module.") {
		rest = strings.TrimPrefix(rest, "module.")
		i := 0
		for i < len(rest) && rest[i] != '.' && rest[i] != '[' {
			i++
		}
		if i == 0 {
			return ""
		}
		parts = append(parts, rest[:i])
		rest = rest[i:]
		if strings.HasPrefix(rest, "[") {
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				return ""
			}
			rest = rest[end+1:]
		}
		if strings.HasPrefix(rest, ".") {
			rest = rest[1:]
		}
	}
	if len(parts) <= 1 {
		return ""
	}
	var b strings.Builder
	for i, p := range parts[:len(parts)-1] {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString("module.")
		b.WriteString(p)
	}
	return b.String()
}

func isVarRef(ref string) bool {
	return strings.HasPrefix(ref, "var.") || strings.Contains(ref, ".var.")
}

func looksLikeSecurityGroupRef(ref string) bool {
	return strings.Contains(ref, "aws_security_group")
}

func securityGroupNameFromRef(ref string) string {
	for _, typ := range []string{"aws_security_group"} {
		needle := typ + "."
		i := strings.Index(ref, needle)
		if i < 0 {
			continue
		}
		// Skip data.aws_security_group — caller handles those.
		if i >= 5 && ref[i-5:i] == "data." {
			continue
		}
		if i >= 6 && strings.HasSuffix(ref[:i], ".data.") {
			continue
		}
		rest := ref[i+len(needle):]
		end := len(rest)
		for j := 0; j < len(rest); j++ {
			if rest[j] == '.' || rest[j] == '[' {
				end = j
				break
			}
		}
		return rest[:end]
	}
	return ""
}

func findSecurityGroup(resources []planResource, name, ref string) (planResource, bool) {
	var hits []planResource
	for _, r := range resources {
		if r.typ != "aws_security_group" {
			continue
		}
		_, _, n, ok := splitResourceAddress(r.address)
		if ok && n == name {
			hits = append(hits, r)
		}
	}
	if len(hits) == 1 {
		return hits[0], true
	}
	if len(hits) == 0 {
		return planResource{}, false
	}
	// Disambiguate by module prefix in the reference.
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

func classifySGIngress(sg planResource, resources []planResource, idx configIndex, port int, portKnown bool) (cls networkSourceClass, worldOnPort bool) {
	sources := collectSGIngressSources(sg, resources, idx)
	if len(sources) == 0 {
		// Egress-only or empty ingress: restricted.
		return netSrcRestricted, false
	}
	allRestricted := true
	for _, src := range sources {
		cls := classifyIngressSource(src, resources, idx)
		covers := ingressCoversPort(src, port, portKnown)
		switch cls {
		case netSrcWorld:
			if covers == coverYes {
				return netSrcWorld, true
			}
			if covers == coverUnknown {
				// Port-specific world rule but DB port unknown → absent.
				return netSrcUnknown, false
			}
			// World rule on a port that does not cover the DB: ignore for false.
			allRestricted = false
		case netSrcUnknown:
			return netSrcUnknown, false
		case netSrcRestricted:
			// ok
		}
	}
	if allRestricted {
		return netSrcRestricted, false
	}
	// Only non-covering world rules + restricted → still restricted for this SG.
	return netSrcRestricted, false
}

type portCover int

const (
	coverNo portCover = iota
	coverYes
	coverUnknown
)

type ingressSource struct {
	fromPort, toPort int
	portSet          bool
	protocol         string // "", "tcp", "udp", "-1", ...
	cidrs            []string
	sgRefs           []string
	prefixListIDs    []string
	prefixListRefs   []string
	unknown          bool
}

func collectSGIngressSources(sg planResource, resources []planResource, idx configIndex) []ingressSource {
	var out []ingressSource
	for _, ing := range asList(sg.values["ingress"]) {
		m, ok := ing.(map[string]any)
		if !ok {
			out = append(out, ingressSource{unknown: true})
			continue
		}
		out = append(out, ingressFromInline(m, idx, sg))
	}
	for _, r := range resources {
		switch r.typ {
		case "aws_vpc_security_group_ingress_rule":
			if !ruleOnSG(r, sg, idx) {
				continue
			}
			out = append(out, ingressFromVPCRule(r, idx))
		case "aws_security_group_rule":
			if !securityGroupRuleOnSG(r, sg, idx) {
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

func ingressFromInline(m map[string]any, idx configIndex, sg planResource) ingressSource {
	src := ingressSource{protocol: strings.ToLower(stringAttr(m["protocol"]))}
	if from, ok := number(m["from_port"]); ok {
		src.fromPort, src.portSet = int(from), true
	}
	if to, ok := number(m["to_port"]); ok {
		src.toPort = int(to)
		src.portSet = true
	}
	src.cidrs = append(src.cidrs, stringList(m["cidr_blocks"])...)
	src.cidrs = append(src.cidrs, stringList(m["ipv6_cidr_blocks"])...)
	if v, ok := m["cidr_blocks"]; ok && len(stringList(v)) == 0 && len(asList(v)) > 0 {
		src.unknown = true
	}
	if v, ok := m["ipv6_cidr_blocks"]; ok && len(stringList(v)) == 0 && len(asList(v)) > 0 {
		src.unknown = true
	}
	if v, ok := m["security_groups"]; ok {
		ids := stringList(v)
		if len(ids) > 0 {
			src.sgRefs = append(src.sgRefs, ids...)
		} else if len(asList(v)) > 0 {
			// Computed/null peer SGs: use config refs on this SG's ingress when present.
			for _, ref := range idx.attrRefs(sg.address, "ingress") {
				if strings.Contains(ref, "data.aws_security_group.") || strings.Contains(ref, ".data.aws_security_group.") {
					src.unknown = true
					break
				}
				if securityGroupNameFromRef(ref) != "" {
					src.sgRefs = append(src.sgRefs, ref)
				}
			}
			if len(src.sgRefs) == 0 {
				src.unknown = true
			}
		}
	}
	if v, ok := m["prefix_list_ids"]; ok {
		ids := stringList(v)
		src.prefixListIDs = append(src.prefixListIDs, ids...)
		if len(ids) == 0 && len(asList(v)) > 0 {
			for _, ref := range idx.attrRefs(sg.address, "ingress") {
				if strings.Contains(ref, "aws_ec2_managed_prefix_list") {
					src.prefixListRefs = append(src.prefixListRefs, ref)
				}
			}
			if len(src.prefixListRefs) == 0 {
				src.unknown = true
			}
		}
	}
	if len(src.cidrs) == 0 && len(src.sgRefs) == 0 && len(src.prefixListIDs) == 0 && len(src.prefixListRefs) == 0 && !src.unknown {
		if self, ok := m["self"].(bool); ok && self {
			src.sgRefs = append(src.sgRefs, "self")
		} else {
			// Plan after-values often omit peer SG IDs; configuration refs still name them.
			for _, ref := range idx.attrRefs(sg.address, "ingress") {
				if strings.Contains(ref, "data.aws_security_group.") || strings.Contains(ref, ".data.aws_security_group.") {
					src.unknown = true
					break
				}
				if securityGroupNameFromRef(ref) != "" {
					src.sgRefs = append(src.sgRefs, ref)
				}
				if strings.Contains(ref, "aws_ec2_managed_prefix_list") {
					src.prefixListRefs = append(src.prefixListRefs, ref)
				}
			}
			if len(src.sgRefs) == 0 && len(src.prefixListRefs) == 0 {
				src.unknown = true
			}
		}
	}
	return src
}

func ingressFromVPCRule(r planResource, idx configIndex) ingressSource {
	// aws_vpc_security_group_ingress_rule uses ip_protocol; accept protocol too.
	proto := stringAttr(r.values["ip_protocol"])
	if proto == "" {
		proto = stringAttr(r.values["protocol"])
	}
	src := ingressSource{protocol: strings.ToLower(proto)}
	if from, ok := number(r.values["from_port"]); ok {
		src.fromPort, src.portSet = int(from), true
	}
	if to, ok := number(r.values["to_port"]); ok {
		src.toPort = int(to)
		src.portSet = true
	}

	// Per-source resolution:
	//   concrete planned value → use it
	//   null and after_unknown not true → unused (ignore; for_each sibling keys)
	//   after_unknown + exactly one direct same-module managed SG / prefix list
	//     → resolve (peer → restricted; prefix list → classify entries)
	//   after_unknown + indirect expr (each.value/var/local/module/data) or
	//     ambiguous candidates → unknown
	if s, ok := r.values["cidr_ipv4"].(string); ok {
		src.cidrs = append(src.cidrs, s)
	} else if r.attrAfterUnknown("cidr_ipv4") {
		// CIDR cannot be resolved from a resource reference.
		src.unknown = true
	}
	if s, ok := r.values["cidr_ipv6"].(string); ok {
		src.cidrs = append(src.cidrs, s)
	} else if r.attrAfterUnknown("cidr_ipv6") {
		src.unknown = true
	}

	switch ref, ok, unk := resolveUnknownVPCPeer(r, idx); {
	case unk:
		src.unknown = true
	case ok:
		src.sgRefs = append(src.sgRefs, ref)
	default:
		if s, ok := r.values["referenced_security_group_id"].(string); ok && s != "" {
			src.sgRefs = append(src.sgRefs, s)
		}
	}

	switch ref, ok, unk := resolveUnknownVPCPrefix(r, idx); {
	case unk:
		src.unknown = true
	case ok:
		src.prefixListRefs = append(src.prefixListRefs, ref)
	default:
		if s, ok := r.values["prefix_list_id"].(string); ok && s != "" {
			src.prefixListIDs = append(src.prefixListIDs, s)
		}
	}

	if src.unknown {
		return src
	}
	if len(src.cidrs) == 0 && len(src.sgRefs) == 0 && len(src.prefixListIDs) == 0 && len(src.prefixListRefs) == 0 {
		src.unknown = true
	}
	return src
}

func (r planResource) attrAfterUnknown(attr string) bool {
	if r.afterUnknown == nil {
		return false
	}
	v, ok := r.afterUnknown[attr]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// resolveUnknownVPCPeer resolves referenced_security_group_id when the planned
// value is unknown after apply. ok means a single direct same-module managed SG
// was found; unk means the attribute is configured-but-unresolvable.
func resolveUnknownVPCPeer(r planResource, idx configIndex) (ref string, ok bool, unk bool) {
	if s, is := r.values["referenced_security_group_id"].(string); is && s != "" {
		return "", false, false
	}
	if !r.attrAfterUnknown("referenced_security_group_id") {
		return "", false, false // null unused optional — ignore
	}
	refs := idx.attrRefs(r.address, "referenced_security_group_id")
	if len(refs) == 0 {
		return "", false, true
	}
	for _, ref := range refs {
		if isIndirectIngressRef(ref) {
			return "", false, true
		}
	}
	ruleMod, _, _, _ := splitResourceAddress(r.address)
	var names []string
	seen := map[string]bool{}
	for _, ref := range refs {
		name := securityGroupNameFromRef(ref)
		if name == "" {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) != 1 {
		return "", false, true
	}
	return resourceAddress(ruleMod, "aws_security_group", names[0]), true, false
}

func resolveUnknownVPCPrefix(r planResource, idx configIndex) (ref string, ok bool, unk bool) {
	if s, is := r.values["prefix_list_id"].(string); is && s != "" {
		return "", false, false
	}
	if !r.attrAfterUnknown("prefix_list_id") {
		return "", false, false
	}
	refs := idx.attrRefs(r.address, "prefix_list_id")
	if len(refs) == 0 {
		return "", false, true
	}
	for _, ref := range refs {
		if isIndirectIngressRef(ref) {
			return "", false, true
		}
	}
	ruleMod, _, _, _ := splitResourceAddress(r.address)
	var names []string
	seen := map[string]bool{}
	for _, ref := range refs {
		name := managedPrefixListNameFromRef(ref)
		if name == "" {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) != 1 {
		return "", false, true
	}
	return resourceAddress(ruleMod, "aws_ec2_managed_prefix_list", names[0]), true, false
}

func isIndirectIngressRef(ref string) bool {
	switch {
	case strings.HasPrefix(ref, "each.") || strings.Contains(ref, ".each."):
		return true
	case strings.HasPrefix(ref, "var.") || strings.Contains(ref, ".var."):
		return true
	case strings.HasPrefix(ref, "local.") || strings.Contains(ref, ".local."):
		return true
	case strings.Contains(ref, "data.aws_security_group.") || strings.Contains(ref, ".data.aws_security_group."):
		return true
	case strings.Contains(ref, "data.aws_ec2_managed_prefix_list.") || strings.Contains(ref, ".data.aws_ec2_managed_prefix_list."):
		return true
	case strings.HasPrefix(ref, "module.") || strings.Contains(ref, ".module."):
		// Child-module resources and module outputs are not same-module directs.
		return true
	default:
		return false
	}
}

func managedPrefixListNameFromRef(ref string) string {
	needle := "aws_ec2_managed_prefix_list."
	i := strings.Index(ref, needle)
	if i < 0 {
		return ""
	}
	if i >= 5 && ref[i-5:i] == "data." {
		return ""
	}
	if i >= 6 && strings.HasSuffix(ref[:i], ".data.") {
		return ""
	}
	rest := ref[i+len(needle):]
	end := len(rest)
	for j := 0; j < len(rest); j++ {
		if rest[j] == '.' || rest[j] == '[' {
			end = j
			break
		}
	}
	return rest[:end]
}

func ingressFromSGRule(r planResource, idx configIndex) ingressSource {
	src := ingressSource{protocol: strings.ToLower(stringAttr(r.values["protocol"]))}
	if from, ok := number(r.values["from_port"]); ok {
		src.fromPort, src.portSet = int(from), true
	}
	if to, ok := number(r.values["to_port"]); ok {
		src.toPort = int(to)
		src.portSet = true
	}
	src.cidrs = append(src.cidrs, stringList(r.values["cidr_blocks"])...)
	src.cidrs = append(src.cidrs, stringList(r.values["ipv6_cidr_blocks"])...)
	if v, ok := r.values["cidr_blocks"]; ok && len(stringList(v)) == 0 && len(asList(v)) > 0 {
		src.unknown = true
	}
	for _, ref := range idx.attrRefs(r.address, "source_security_group_id") {
		src.sgRefs = append(src.sgRefs, ref)
	}
	if s, ok := r.values["source_security_group_id"].(string); ok && s != "" && len(src.sgRefs) == 0 {
		src.sgRefs = append(src.sgRefs, s)
	} else if _, present := r.values["source_security_group_id"]; present && r.values["source_security_group_id"] == nil && len(src.sgRefs) == 0 {
		src.unknown = true
	}
	for _, ref := range idx.attrRefs(r.address, "prefix_list_ids") {
		src.prefixListRefs = append(src.prefixListRefs, ref)
	}
	src.prefixListIDs = append(src.prefixListIDs, stringList(r.values["prefix_list_ids"])...)
	if v, ok := r.values["prefix_list_ids"]; ok && len(stringList(v)) == 0 && len(asList(v)) > 0 && len(src.prefixListRefs) == 0 {
		src.unknown = true
	}
	if len(src.cidrs) == 0 && len(src.sgRefs) == 0 && len(src.prefixListIDs) == 0 && len(src.prefixListRefs) == 0 {
		src.unknown = true
	}
	return src
}

func securityGroupRuleOnSG(rule, sg planResource, idx configIndex) bool {
	_, _, name, ok := splitResourceAddress(sg.address)
	if !ok {
		return false
	}
	for _, ref := range idx.attrRefs(rule.address, "security_group_id") {
		if containsResource(ref, "aws_security_group", name) {
			return true
		}
	}
	// Fall back to plan id equality when both are concrete.
	ruleSG, _ := rule.values["security_group_id"].(string)
	sgID, _ := sg.values["id"].(string)
	return ruleSG != "" && sgID != "" && ruleSG == sgID
}

func ingressCoversPort(src ingressSource, port int, portKnown bool) portCover {
	if src.protocol == "-1" || src.protocol == "all" {
		return coverYes
	}
	if !src.portSet {
		// Protocol set without ports (unusual): treat as unknown unless -1 already handled.
		return coverUnknown
	}
	// AWS "all ports" representations.
	if src.fromPort == 0 && src.toPort == 0 && (src.protocol == "-1" || src.protocol == "") {
		return coverYes
	}
	if src.fromPort == 0 && src.toPort == 65535 {
		return coverYes
	}
	if !portKnown {
		return coverUnknown
	}
	if src.fromPort <= port && port <= src.toPort {
		return coverYes
	}
	return coverNo
}

func classifyIngressSource(src ingressSource, resources []planResource, idx configIndex) networkSourceClass {
	if src.unknown {
		return netSrcUnknown
	}
	// SG references are always restricted (peer SG).
	if len(src.sgRefs) > 0 && len(src.cidrs) == 0 && len(src.prefixListIDs) == 0 && len(src.prefixListRefs) == 0 {
		for _, ref := range src.sgRefs {
			if ref != "self" && (strings.Contains(ref, "data.aws_security_group.") || strings.Contains(ref, ".data.aws_security_group.")) {
				return netSrcUnknown
			}
		}
		return netSrcRestricted
	}
	worst := netSrcRestricted
	raise := func(c networkSourceClass) {
		if c == netSrcUnknown || (c == netSrcWorld && worst != netSrcUnknown) {
			worst = c
		}
		if c == netSrcUnknown {
			worst = netSrcUnknown
		}
	}
	for _, c := range src.cidrs {
		raise(classifyCIDR(c))
		if worst == netSrcUnknown {
			return netSrcUnknown
		}
	}
	for _, id := range src.prefixListIDs {
		raise(classifyPrefixList(id, "", resources, idx))
		if worst == netSrcUnknown {
			return netSrcUnknown
		}
	}
	for _, ref := range src.prefixListRefs {
		raise(classifyPrefixList("", ref, resources, idx))
		if worst == netSrcUnknown {
			return netSrcUnknown
		}
	}
	// Mixed SG + CIDR: classify CIDRs; SG refs don't widen.
	if len(src.sgRefs) > 0 && len(src.cidrs) == 0 && len(src.prefixListIDs) == 0 && len(src.prefixListRefs) == 0 {
		return netSrcRestricted
	}
	if len(src.cidrs) == 0 && len(src.prefixListIDs) == 0 && len(src.prefixListRefs) == 0 && len(src.sgRefs) > 0 {
		return netSrcRestricted
	}
	if len(src.cidrs) == 0 && len(src.prefixListIDs) == 0 && len(src.prefixListRefs) == 0 {
		return netSrcUnknown
	}
	return worst
}

func classifyCIDR(cidr string) networkSourceClass {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return netSrcUnknown
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Bare IP?
		if ip := net.ParseIP(cidr); ip != nil {
			if isPrivateIP(ip) {
				return netSrcRestricted
			}
			// Single host = /32 or /128 → restricted under "public /16 or narrower".
			return netSrcRestricted
		}
		return netSrcUnknown
	}
	ones, bits := ipnet.Mask.Size()
	if bits == 0 {
		return netSrcUnknown
	}
	if ipnetIsPrivate(ipnet) {
		return netSrcRestricted
	}
	// Public (or mixed) space: wide prefixes are world.
	if bits == 32 { // IPv4
		if ones < 16 {
			return netSrcWorld
		}
		return netSrcRestricted
	}
	if bits == 128 { // IPv6
		if ones < 32 {
			return netSrcWorld
		}
		return netSrcRestricted
	}
	return netSrcUnknown
}

func ipnetIsPrivate(n *net.IPNet) bool {
	privates := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"fc00::/7",
	}
	for _, p := range privates {
		_, pn, err := net.ParseCIDR(p)
		if err != nil {
			continue
		}
		if cidrSubsetOf(n, pn) {
			return true
		}
	}
	return false
}

func cidrSubsetOf(inner, outer *net.IPNet) bool {
	if !outer.Contains(inner.IP) {
		return false
	}
	// Last address of inner must also fall in outer.
	innerOnes, innerBits := inner.Mask.Size()
	if innerBits == 0 {
		return false
	}
	last := make(net.IP, len(inner.IP))
	copy(last, inner.IP)
	for i := range last {
		last[i] |= ^inner.Mask[i]
	}
	if !outer.Contains(last) {
		return false
	}
	outerOnes, _ := outer.Mask.Size()
	return innerOnes >= outerOnes
}

func isPrivateIP(ip net.IP) bool {
	privates := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"}
	for _, p := range privates {
		_, n, err := net.ParseCIDR(p)
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func classifyPrefixList(id, ref string, resources []planResource, idx configIndex) networkSourceClass {
	pl, ok := findManagedPrefixList(id, ref, resources, idx)
	if !ok {
		return netSrcUnknown
	}
	entries := prefixListCIDRs(pl.values)
	if len(entries) == 0 {
		// Empty or unread entries → unknown (cannot prove restricted).
		return netSrcUnknown
	}
	for _, c := range entries {
		switch classifyCIDR(c) {
		case netSrcWorld:
			return netSrcWorld
		case netSrcUnknown:
			return netSrcUnknown
		}
	}
	return netSrcRestricted
}

func findManagedPrefixList(id, ref string, resources []planResource, idx configIndex) (planResource, bool) {
	var hits []planResource
	for _, r := range resources {
		if r.typ != "aws_ec2_managed_prefix_list" {
			continue
		}
		if id != "" {
			if rid, _ := r.values["id"].(string); rid != "" && rid == id {
				return r, true
			}
		}
		if ref != "" {
			_, _, name, ok := splitResourceAddress(r.address)
			if ok && containsResource(ref, "aws_ec2_managed_prefix_list", name) {
				hits = append(hits, r)
			}
		}
	}
	if len(hits) == 1 {
		return hits[0], true
	}
	return planResource{}, false
}

func prefixListCIDRs(values map[string]any) []string {
	var out []string
	for _, e := range asList(values["entry"]) {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if c, ok := m["cidr"].(string); ok && c != "" {
			out = append(out, c)
		}
	}
	// Some plans flatten entries differently.
	for _, e := range asList(values["entries"]) {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if c, ok := m["cidr"].(string); ok && c != "" {
			out = append(out, c)
		}
	}
	return out
}

func dbListenPort(values map[string]any) (int, bool) {
	if n, ok := number(values["port"]); ok {
		return int(n), true
	}
	engine, _ := values["engine"].(string)
	engine = strings.ToLower(engine)
	switch {
	case engine == "postgres", engine == "aurora-postgresql", strings.HasPrefix(engine, "postgres"):
		return 5432, true
	case engine == "mysql", engine == "mariadb", engine == "aurora", engine == "aurora-mysql",
		strings.HasPrefix(engine, "mysql"), strings.HasPrefix(engine, "mariadb"), strings.HasPrefix(engine, "aurora-mysql"):
		return 3306, true
	case strings.Contains(engine, "sqlserver"):
		return 1433, true
	case strings.Contains(engine, "oracle"):
		return 1521, true
	default:
		return 0, false
	}
}
