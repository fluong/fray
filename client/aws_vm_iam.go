package client

import (
	"fmt"
	"strings"
)

const (
	iamOmitProfileNotInPlan  = "instance profile not in plan"
	iamOmitRoleAmbiguous     = "role ambiguous across launch templates"
	iamOmitLaunchVersion     = "launch template version not pinned"
	iamOmitNodeRoleNotInPlan = "node role not in plan"
)

var (
	iamInstanceProfileRefOpts = resolveSingleByRefOpts{
		ResourceType:      "aws_iam_instance_profile",
		SkipVarRef:        true,
		BareModule:        bareModuleSkipWithVar,
		EmptyNameData:     emptyNameContinue,
		EmptyNameManaged:  emptyNameContinue,
		ModuleOutputDepth: 0,
	}
	iamRoleRefOpts = resolveSingleByRefOpts{
		ResourceType:      "aws_iam_role",
		SkipVarRef:        true,
		BareModule:        bareModuleSkipWithVar,
		EmptyNameData:     emptyNameContinue,
		EmptyNameManaged:  emptyNameContinue,
		ModuleOutputDepth: 0,
	}
)

func warnIAMFlowsOmitted(warnings *[]string, address, reason string, warned map[string]bool) {
	if reason == "" || warned[address] {
		return
	}
	warned[address] = true
	if warnings != nil {
		*warnings = append(*warnings, fmt.Sprintf("IAM flows omitted for %s: %s", address, reason))
	}
}

// iamRoleRefsForCompute returns module and role ref strings for IAM-derived flows.
// omitReason is set when role resolution failed in a way that blocks all VM IAM flows.
func iamRoleRefsForCompute(src *Element, resources, data []planResource, idx configIndex) (module string, roleRefs []string, omitReason string) {
	r, ok := planResourceByElement(src, resources)
	if !ok {
		return "", nil, ""
	}
	mod, _, _, _ := splitResourceAddress(r.address)
	switch r.typ {
	case "aws_ecs_service":
		task, ok := serviceTaskDefinition(r, resources, idx)
		if !ok {
			return "", nil, ""
		}
		return mod, idx.attrRefs(task.address, "task_role_arn"), ""
	case "aws_instance":
		return instanceDirectProfileRoleRefs(r, resources, data, idx)
	case "aws_autoscaling_group":
		return instanceProfileRoleRefsASG(r, resources, data, idx)
	case "aws_eks_node_group":
		refs := idx.attrRefs(r.address, "node_role_arn")
		if len(refs) == 0 && !declaresAttr(r, idx, "node_role_arn") {
			return "", nil, ""
		}
		role, ok := resolveSingleByRef(refs, resources, data, idx, iamRoleRefOpts)
		if !ok {
			if declaresAttr(r, idx, "node_role_arn") {
				return mod, nil, iamOmitNodeRoleNotInPlan
			}
			return "", nil, ""
		}
		return mod, []string{role.address}, ""
	default:
		return "", nil, ""
	}
}

func declaresAttr(r planResource, idx configIndex, attr string) bool {
	if hasConfigAttr(idx, r.address, attr) {
		return true
	}
	if _, ok := r.values[attr]; ok {
		return true
	}
	return len(idx.attrRefs(r.address, attr)) > 0
}

func instanceDirectProfileRoleRefs(inst planResource, resources, data []planResource, idx configIndex) (module string, roleRefs []string, omitReason string) {
	mod, _, _, _ := splitResourceAddress(inst.address)
	if !declaresIAMInstanceProfile(inst, idx) {
		return "", nil, ""
	}
	profile, ok, reason := resolveIAMInstanceProfile(inst, resources, data, idx)
	if reason != "" {
		return mod, nil, reason
	}
	if !ok {
		return mod, nil, iamOmitProfileNotInPlan
	}
	refs, reason := roleRefsFromInstanceProfile(profile, resources, data, idx)
	if reason != "" {
		return mod, nil, reason
	}
	return mod, refs, ""
}

func instanceProfileRoleRefsASG(asg planResource, resources, data []planResource, idx configIndex) (module string, roleRefs []string, omitReason string) {
	mod, _, _, _ := splitResourceAddress(asg.address)
	src := resolveASGLaunchSource(asg, resources, data, idx)
	if src.unknown {
		return mod, nil, iamOmitLaunchVersion
	}
	if !src.useLC && len(src.templates) == 0 {
		if asgDeclaresLaunchConfiguration(asg, idx) || instanceDeclaresLaunchTemplate(asg, idx) || asgDeclaresMixedInstancesPolicy(asg, idx) {
			return mod, nil, iamOmitLaunchVersion
		}
		return "", nil, ""
	}
	if src.useLC {
		return instanceProfileRoleRefsASGFromLC(mod, src.lc, resources, data, idx)
	}
	return instanceProfileRoleRefsASGFromTemplates(mod, src.templates, resources, data, idx)
}

func instanceProfileRoleRefsASGFromLC(mod string, lc planResource, resources, data []planResource, idx configIndex) (string, []string, string) {
	refs, omit := roleRefsFromLaunchHolder(lc, resources, data, idx)
	if omit != "" {
		return mod, nil, omit
	}
	if len(refs) == 0 {
		return "", nil, ""
	}
	return mod, refs, ""
}

func instanceProfileRoleRefsASGFromTemplates(mod string, templates []planResource, resources, data []planResource, idx configIndex) (string, []string, string) {
	var acc asgRoleRefsAccumulator
	for _, tmpl := range templates {
		refs, omit := roleRefsFromLaunchHolder(tmpl, resources, data, idx)
		if omit != "" {
			return mod, nil, omit
		}
		if len(refs) == 0 {
			continue
		}
		if omit, ok := acc.add(refs); !ok {
			return mod, nil, omit
		}
	}
	if len(acc.first) == 0 {
		return "", nil, ""
	}
	return mod, acc.first, ""
}

type asgRoleRefsAccumulator struct {
	first []string
	seen  map[string]bool
}

func (a *asgRoleRefsAccumulator) add(refs []string) (omit string, ok bool) {
	if len(refs) == 0 {
		return iamOmitProfileNotInPlan, false
	}
	key := strings.Join(refs, "|")
	if len(a.seen) == 0 {
		a.seen = map[string]bool{key: true}
		a.first = refs
		return "", true
	}
	if !a.seen[key] {
		return iamOmitRoleAmbiguous, false
	}
	return "", true
}

// roleRefsFromLaunchHolder resolves iam_instance_profile on a launch template or
// launch configuration. Omit IAM flows only when a profile is referenced but
// cannot be resolved.
func roleRefsFromLaunchHolder(holder planResource, resources, data []planResource, idx configIndex) ([]string, string) {
	profile, ok, reason := resolveIAMInstanceProfileResource(holder, resources, data, idx)
	if reason != "" {
		return nil, reason
	}
	if !ok {
		if declaresIAMInstanceProfile(holder, idx) {
			return nil, iamOmitProfileNotInPlan
		}
		return nil, ""
	}
	return roleRefsFromInstanceProfile(profile, resources, data, idx)
}

// declaresIAMInstanceProfile is true when the holder references an instance
// profile (config ref, plan literal, or block name/arn). Empty optional blocks
// in configuration alone do not count.
func declaresIAMInstanceProfile(holder planResource, idx configIndex) bool {
	if len(iamInstanceProfileAttrRefs(holder, idx)) > 0 {
		return true
	}
	if name, ok := holder.values["iam_instance_profile"].(string); ok && strings.TrimSpace(name) != "" {
		return true
	}
	for _, block := range asList(holder.values["iam_instance_profile"]) {
		m, ok := block.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := m["name"].(string); strings.TrimSpace(name) != "" {
			return true
		}
		if arn, _ := m["arn"].(string); strings.TrimSpace(arn) != "" {
			return true
		}
	}
	return false
}

func resolveIAMInstanceProfile(holder planResource, resources, data []planResource, idx configIndex) (planResource, bool, string) {
	return resolveIAMInstanceProfileResource(holder, resources, data, idx)
}

func resolveIAMInstanceProfileResource(holder planResource, resources, data []planResource, idx configIndex) (planResource, bool, string) {
	refs := iamInstanceProfileAttrRefs(holder, idx)
	if len(refs) > 0 {
		if prof, ok, reason := resolveIAMInstanceProfileByRefs(refs, resources, data, idx); ok {
			return prof, true, ""
		} else if reason != "" {
			return planResource{}, false, reason
		}
		// Config refs unresolved (e.g. stray synthesized ref) — try plan values.
	}
	if name, ok := holder.values["iam_instance_profile"].(string); ok && strings.TrimSpace(name) != "" {
		if prof, found := findIAMInstanceProfileByName(name, resources); found {
			return prof, true, ""
		}
		if prof, found := findIAMInstanceProfileByName(name, data); found {
			return prof, true, ""
		}
		return planResource{}, false, ""
	}
	if prof, ok := resolveIAMInstanceProfileFromBlocks(holder, resources); ok {
		return prof, true, ""
	}
	if declaresIAMInstanceProfile(holder, idx) {
		return planResource{}, false, ""
	}
	return planResource{}, false, ""
}

func resolveIAMInstanceProfileByRefs(refs []string, resources, data []planResource, idx configIndex) (planResource, bool, string) {
	prof, ok := resolveSingleByRef(refs, resources, data, idx, iamInstanceProfileRefOpts)
	if ok {
		return prof, true, ""
	}
	return planResource{}, false, ""
}

func findIAMInstanceProfileByName(name string, list []planResource) (planResource, bool) {
	for _, r := range list {
		if r.typ != "aws_iam_instance_profile" {
			continue
		}
		if profileNameMatches(r, name) {
			return r, true
		}
	}
	return planResource{}, false
}

func resolveIAMInstanceProfileFromBlocks(holder planResource, resources []planResource) (planResource, bool) {
	for _, block := range asList(holder.values["iam_instance_profile"]) {
		m, ok := block.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := m["name"].(string); name != "" {
			if prof, found := findIAMInstanceProfileByName(name, resources); found {
				return prof, true
			}
		}
		if arn, _ := m["arn"].(string); arn != "" {
			if prof, found := findIAMInstanceProfileByARN(arn, resources); found {
				return prof, true
			}
		}
	}
	return planResource{}, false
}

func findIAMInstanceProfileByARN(arn string, resources []planResource) (planResource, bool) {
	for _, r := range resources {
		if r.typ != "aws_iam_instance_profile" {
			continue
		}
		if a, _ := r.values["arn"].(string); a == arn {
			return r, true
		}
	}
	return planResource{}, false
}

func profileNameMatches(r planResource, name string) bool {
	if n, _ := r.values["name"].(string); n == name {
		return true
	}
	return localTypeName(r.address) == name
}

func iamInstanceProfileAttrRefs(holder planResource, idx configIndex) []string {
	return uniqueStrings(idx.attrRefs(holder.address, "iam_instance_profile"))
}

func roleRefsFromInstanceProfile(profile planResource, resources, data []planResource, idx configIndex) ([]string, string) {
	refs := idx.attrRefs(profile.address, "role")
	if len(refs) == 0 {
		if s, ok := profile.values["role"].(string); ok && s != "" {
			refs = []string{s}
		}
	}
	role, ok := resolveSingleByRef(refs, resources, data, idx, iamRoleRefOpts)
	if !ok {
		if len(refs) > 0 || profile.values["role"] != nil {
			return nil, iamOmitProfileNotInPlan
		}
		return nil, ""
	}
	return []string{role.address}, ""
}

func virtualMachineIAMFlows(resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string, iamOmitWarned map[string]bool) []*Flow {
	var flows []*Flow
	for _, el := range elements {
		if el.Kind != "virtual_machine" {
			continue
		}
		r, ok := planResourceByElement(el, resources)
		if !ok {
			continue
		}
		mod, roleRefs, omit := iamRoleRefsForCompute(el, resources, data, idx)
		if omit != "" {
			warnIAMFlowsOmitted(warnings, r.address, omit, iamOmitWarned)
			continue
		}
		if len(roleRefs) == 0 {
			continue
		}
		flows = append(flows, bucketFlowsForRole(el, mod, roleRefs, resources, data, idx, elements, warnings)...)
		flows = append(flows, tableFlowsForRole(el, mod, roleRefs, resources, data, idx, elements, warnings)...)
	}
	return flows
}

func bucketFlowsForRole(fromEl *Element, module string, roleRefs []string, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) []*Flow {
	docs, unknownDocs, iamWarns := roleDocuments(module, roleRefs, resources, data, idx)
	if warnings != nil {
		*warnings = append(*warnings, iamWarns...)
	}
	wideCause, wideS3 := roleKnownWideGrant(module, roleRefs, resources, idx, iamServiceS3)
	hits, grants, actions, cause, ambiguous, actionWarn := bucketsFromDocs(docs, idx.callRefs(module), resources, elements)
	if ambiguous {
		if warnings != nil {
			*warnings = append(*warnings, "ambiguous bucket for "+fromEl.Evidence.Addresses[0])
		}
		return nil
	}
	if len(hits) != 1 {
		return nil
	}
	scope := effectiveAuthzScope(grants)
	if scope == "" {
		return nil
	}
	if actionWarn != "" && warnings != nil {
		*warnings = append(*warnings, actionWarn)
	}
	flow := &Flow{
		From: fromEl.canonicalKey(), To: hits[0].canonicalKey(),
		DataClass: "unknown", Transport: "tls",
	}
	if wideS3 {
		flow.AuthzScope, flow.AuthzGrants, cause = widenScopeWithKnownWide(scope, cause, wideCause)
		flow.AuthzActions = actions
		if cause != "" {
			flow.Causes = map[string]string{"authz_scope": cause}
		}
		return []*Flow{flow}
	}
	if unknownDocs {
		if role := omittedScopeRole(module, roleRefs); role != "" {
			flow.Causes = map[string]string{"authz_scope_omitted_for": role}
		}
		return []*Flow{flow}
	}
	flow.AuthzScope = scope
	flow.AuthzGrants = grants
	flow.AuthzActions = actions
	if cause != "" {
		flow.Causes = map[string]string{"authz_scope": cause}
	}
	return []*Flow{flow}
}

func asgResourceRefsPeerSG(asg, sg planResource, resources, data []planResource, idx configIndex) bool {
	sgMod, _, sgName, ok := splitResourceAddress(sg.address)
	if !ok {
		return false
	}
	asgMod, _, _, ok := splitResourceAddress(asg.address)
	if !ok || asgMod != sgMod {
		return false
	}
	src := resolveASGLaunchSource(asg, resources, data, idx)
	if src.unknown {
		return false
	}
	refs, ok := asgLaunchSecurityGroupRefs(src, idx)
	if !ok {
		return false
	}
	for _, ref := range refs {
		if containsResource(ref, "aws_security_group", sgName) {
			return true
		}
	}
	return false
}
