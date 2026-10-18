package client

import (
	"strings"
)

var apigwRESTAPIRefOpts = resolveSingleByRefOpts{
	ResourceType:     "aws_api_gateway_rest_api",
	SkipVarRef:       true,
	BareModule:       bareModuleSkipWithVar,
	EmptyNameManaged: emptyNameContinue,
}

func applyAPIGatewayRESTResourcePolicies(resources, data []planResource, idx configIndex, plan []byte, byAddr map[string]*Element, warnings *[]string) {
	ctx := newAWSResourcePolicyContext(resources, data, idx, plan)
	linked := map[string][]resourcePolicyClass{}
	unlinkedPolicy := false

	for _, rp := range resources {
		if rp.typ != "aws_api_gateway_rest_api_policy" {
			continue
		}
		mod, _, _, _ := splitResourceAddress(rp.address)
		el, linkOK := restAPIElementForStandalonePolicy(rp, mod, resources, data, idx, byAddr)
		if !linkOK || el == nil {
			unlinkedPolicy = true
			*warnings = append(*warnings, "unlinked resource policy "+rp.address+"; REST API attributes omitted where policy presence is unknown")
			continue
		}
		apiKey := el.canonicalKey()
		docs, unknown := resolvePolicyContent(rp, "policy", mod, data, resources, idx)
		cause := rp.address
		if len(docs) == 1 && docs[0].address != "" && docs[0].address != rp.address {
			cause = docs[0].address
		}
		class := apigwClassFromDocs(docs, unknown, cause, ctx, warnings, rp.address)
		linked[apiKey] = append(linked[apiKey], class)
	}

	for _, api := range resources {
		if api.typ != "aws_api_gateway_rest_api" {
			continue
		}
		el := byAddr[api.address]
		if el == nil {
			continue
		}
		mod, _, _, _ := splitResourceAddress(api.address)
		if !restAPIInlinePolicyConfigured(api, idx) {
			continue
		}
		docs, unknown := resolvePolicyContent(api, "policy", mod, data, resources, idx)
		cause := api.address
		class := apigwClassFromDocs(docs, unknown, cause, ctx, warnings, api.address)
		linked[el.canonicalKey()] = append(linked[el.canonicalKey()], class)
	}

	for _, el := range byAddr {
		if el == nil || el.Kind != "api_gateway" || el.Provider != "aws" {
			continue
		}
		if !restAPIElement(el, resources) {
			continue
		}
		key := el.canonicalKey()
		policies := linked[key]
		if len(policies) == 0 {
			if unlinkedPolicy {
				continue
			}
			apiCause := ""
			if len(el.Evidence.Addresses) > 0 {
				apiCause = el.Evidence.Addresses[0]
			}
			setResourcePolicyAttrs(el, false, false, apiCause)
			continue
		}
		world, cross, cause := mergeResourcePolicyClasses(policies)
		setResourcePolicyAttrsFromTri(el, world, cross, cause)
	}
}

func apigwClassFromDocs(docs []planResource, unknown bool, cause string, ctx awsResourcePolicyContext, warnings *[]string, holder string) resourcePolicyClass {
	if unknown || len(docs) == 0 {
		if unknown {
			*warnings = append(*warnings, "unreadable resource policy on "+holder+"; attributes omitted")
		}
		return resourcePolicyClass{world: triOmit, cross: triOmit, cause: cause}
	}
	var parts []resourcePolicyClass
	for _, doc := range docs {
		parts = append(parts, classifyAPIGatewayResourcePolicyDoc(doc, ctx))
	}
	merged := mergeResourcePolicyClassesSlice(parts)
	if merged.cause == "" {
		merged.cause = cause
	}
	return merged
}

func restAPIElementForStandalonePolicy(rp planResource, module string, resources, data []planResource, idx configIndex, byAddr map[string]*Element) (*Element, bool) {
	refs := idx.attrRefs(rp.address, "rest_api_id")
	api, ok := resolveSingleByRef(refs, resources, data, idx, apigwRESTAPIRefOpts)
	if !ok {
		return nil, false
	}
	el := byAddr[api.address]
	return el, el != nil
}

func restAPIHasInlinePolicy(api planResource) bool {
	return restAPIHasPolicy(api)
}

func restAPIElement(el *Element, resources []planResource) bool {
	if el == nil || len(el.Evidence.Addresses) == 0 {
		return false
	}
	r, ok := planResourceByAddress(el.Evidence.Addresses[0], resources)
	return ok && r.typ == "aws_api_gateway_rest_api"
}

// restAPIInlinePolicyConfigured is true when the REST API declares an inline
// policy in configuration or the plan carries a non-empty policy string.
// A known empty policy string is not configured. after_unknown on policy with
// configuration present counts as configured (content may come from HCL).
func restAPIInlinePolicyConfigured(api planResource, idx configIndex) bool {
	if restAPIHasPolicy(api) {
		return true
	}
	if !hasConfigAttr(idx, api.address, "policy") {
		return false
	}
	if attrAfterUnknown(api, "policy") {
		return true
	}
	if raw, ok := api.values["policy"]; ok {
		if s, is := raw.(string); is && strings.TrimSpace(s) == "" {
			return false
		}
	}
	mod, _, _, _ := splitResourceAddress(api.address)
	if _, ok := resolvePolicyFromHCL(api.address, api.address, mod, nil, idx); ok {
		return true
	}
	return len(idx.attrRefs(api.address, "policy")) > 0
}

func restAPIHasAnyPolicy(api planResource, resources []planResource, idx configIndex) bool {
	if restAPIInlinePolicyConfigured(api, idx) {
		return true
	}
	for _, rp := range resources {
		if rp.typ != "aws_api_gateway_rest_api_policy" {
			continue
		}
		if refsAPI(rp, idx, "rest_api_id", api) {
			return true
		}
	}
	return false
}

type apigwPolicyStmt struct {
	allow     bool
	deny      bool
	doc       string
	condition map[string]any
	principal resourcePolicyPrincipal
	actions   []string
	resources []string
}

type apigwDenyNeutralizeMode int

const (
	apigwDenyNone apigwDenyNeutralizeMode = iota
	apigwDenyWorldAndCross
	apigwDenyWorldOnly
)

type apigwDenyNeutralizer struct {
	mode      apigwDenyNeutralizeMode
	resources []string
}

func apigwResourcePolicyStatements(doc planResource) []apigwPolicyStmt {
	var out []apigwPolicyStmt
	for _, raw := range asList(doc.values["statement"]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		effectVal, _ := firstKey(m, "Effect", "effect")
		effectStr, _ := effectVal.(string)
		st := apigwPolicyStmt{
			allow:     strings.EqualFold(effectStr, "Allow"),
			deny:      strings.EqualFold(effectStr, "Deny"),
			doc:       doc.address,
			condition: normalizeResourcePolicyCondition(firstKeyValue(m, "Condition", "condition")),
			principal: parseResourcePolicyPrincipal(m),
			actions:   apigwPolicyStatementActions(m),
			resources: apigwPolicyStatementResources(m),
		}
		out = append(out, st)
	}
	return out
}

func apigwPolicyStatementActions(m map[string]any) []string {
	if v, ok := firstKey(m, "Action", "action"); ok {
		return stringListAny(v)
	}
	if v, ok := m["actions"]; ok {
		return stringListAny(v)
	}
	return nil
}

func apigwPolicyStatementResources(m map[string]any) []string {
	if v, ok := firstKey(m, "Resource", "resource"); ok {
		return stringListAny(v)
	}
	if v, ok := m["resources"]; ok {
		return stringListAny(v)
	}
	return nil
}

func apigwInvokeAction(actions []string) bool {
	for _, a := range actions {
		a = strings.TrimSpace(strings.ToLower(a))
		if a == "" {
			continue
		}
		if a == "*" {
			return true
		}
		if a == "execute-api:invoke" || a == "execute-api:*" {
			return true
		}
		if strings.HasSuffix(a, ":execute-api:invoke") || strings.HasSuffix(a, ":execute-api:*") {
			return true
		}
	}
	return false
}

func classifyAPIGatewayResourcePolicyDoc(doc planResource, ctx awsResourcePolicyContext) resourcePolicyClass {
	stmts := apigwResourcePolicyStatements(doc)
	if len(stmts) == 0 {
		return resourcePolicyClass{world: triOmit, cross: triOmit}
	}

	var neutralizers []apigwDenyNeutralizer
	for _, st := range stmts {
		if !st.deny || st.condition == nil {
			continue
		}
		if !apigwInvokeAction(st.actions) {
			continue
		}
		n, fail := parseAPIGWDenyNeutralizer(st)
		if fail {
			return resourcePolicyClass{world: triOmit, cross: triOmit, cause: st.doc}
		}
		if n.mode != apigwDenyNone {
			neutralizers = append(neutralizers, n)
		}
	}

	var worldAllows []apigwPolicyStmt
	for _, st := range stmts {
		if !st.allow || !apigwInvokeAction(st.actions) {
			continue
		}
		if !st.principal.worldEligible {
			continue
		}
		worldAllows = append(worldAllows, st)
	}

	if len(neutralizers) > 0 {
		if !apigwNeutralizerCoverage(neutralizers, worldAllows) {
			return resourcePolicyClass{world: triOmit, cross: triOmit, cause: doc.address}
		}
	}

	var world, cross triBool = triFalse, triFalse
	for _, st := range stmts {
		if st.deny || !st.allow || !apigwInvokeAction(st.actions) {
			continue
		}
		w := classifyAPIGWStatementWorld(st, neutralizers)
		c := classifyAPIGWStatementCross(st, ctx, neutralizers)
		world = mergeTriOrTrue(world, w)
		cross = mergeTriOrTrue(cross, c)
	}
	if world == triTrue {
		cross = triTrue
	}
	return resourcePolicyClass{world: world, cross: cross, cause: doc.address}
}

func parseAPIGWDenyNeutralizer(st apigwPolicyStmt) (apigwDenyNeutralizer, bool) {
	op, varKey, val, ok := apigwConditionSingleKey(st.condition)
	if !ok {
		return apigwDenyNeutralizer{}, true
	}
	switch op {
	case "StringEquals", "IpAddress":
		return apigwDenyNeutralizer{}, true
	case "StringNotEquals":
		if varKey != "aws:SourceVpce" && varKey != "aws:SourceVpc" {
			return apigwDenyNeutralizer{}, true
		}
		if !concreteRestrictingValue(varKey, val) {
			return apigwDenyNeutralizer{}, true
		}
		return apigwDenyNeutralizer{mode: apigwDenyWorldAndCross, resources: st.resources}, false
	case "NotIpAddress":
		if varKey != "aws:SourceIp" {
			return apigwDenyNeutralizer{}, true
		}
		if !apigwSourceIPRestricts(val) {
			return apigwDenyNeutralizer{}, false
		}
		return apigwDenyNeutralizer{mode: apigwDenyWorldOnly, resources: st.resources}, false
	default:
		return apigwDenyNeutralizer{}, true
	}
}

func apigwConditionSingleKey(cond map[string]any) (op, varKey string, val any, ok bool) {
	if len(cond) == 0 {
		return "", "", nil, false
	}
	if _, bad := cond["__invalid"]; bad {
		return "", "", nil, false
	}
	if len(cond) != 1 {
		return "", "", nil, false
	}
	for o, body := range cond {
		m, is := body.(map[string]any)
		if !is || len(m) != 1 {
			return "", "", nil, false
		}
		for k, v := range m {
			return o, k, v, true
		}
	}
	return "", "", nil, false
}

func apigwSourceIPRestricts(val any) bool {
	switch t := val.(type) {
	case string:
		return apigwRestrictingCIDR(t)
	case []any:
		if len(t) == 0 {
			return false
		}
		for _, item := range t {
			s, ok := item.(string)
			if !ok || !apigwRestrictingCIDR(s) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func apigwRestrictingCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "*") {
		return false
	}
	if s == "0.0.0.0/0" || s == "::/0" {
		return false
	}
	return true
}

func apigwNeutralizerCoverage(neutralizers []apigwDenyNeutralizer, allows []apigwPolicyStmt) bool {
	if len(allows) == 0 {
		return true
	}
	for _, n := range neutralizers {
		for _, allow := range allows {
			if !apigwDenyCoversAllAllowResources(n.resources, allow.resources) {
				return false
			}
		}
	}
	return true
}

func apigwDenyCoversAllAllowResources(denyRes, allowRes []string) bool {
	if len(allowRes) == 0 {
		return true
	}
	if len(denyRes) == 0 {
		return false
	}
	for _, a := range allowRes {
		if apigwResourceUnknown(a) {
			return false
		}
		covered := false
		for _, d := range denyRes {
			if apigwResourceUnknown(d) {
				return false
			}
			if executeAPIResourceCovers(d, a) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func apigwResourceUnknown(r string) bool {
	return strings.TrimSpace(r) == "" || strings.Contains(r, "${")
}

func executeAPIResourceCovers(deny, allow string) bool {
	deny = strings.TrimSpace(deny)
	allow = strings.TrimSpace(allow)
	if deny == allow {
		return true
	}
	if deny == "*" {
		return true
	}
	if allow == "*" {
		return deny == "*"
	}
	if allow == "execute-api:/*" {
		return deny == "execute-api:/*" || deny == "*"
	}
	if deny == "execute-api:/*" {
		return true
	}
	return apigwExecuteAPIWildcardCover(deny, allow)
}

func apigwExecuteAPIWildcardCover(deny, allow string) bool {
	if strings.HasSuffix(deny, "/*") && strings.HasPrefix(allow, strings.TrimSuffix(deny, "/*")) {
		return true
	}
	dParts := strings.Split(strings.TrimPrefix(deny, "execute-api:"), "/")
	aParts := strings.Split(strings.TrimPrefix(allow, "execute-api:"), "/")
	if len(dParts) != len(aParts) {
		if deny == "execute-api:/*" {
			return true
		}
		return false
	}
	for i := range dParts {
		if dParts[i] == "*" || dParts[i] == aParts[i] {
			continue
		}
		return false
	}
	return true
}

func classifyAPIGWStatementWorld(st apigwPolicyStmt, neutralizers []apigwDenyNeutralizer) triBool {
	if !st.principal.worldEligible {
		return triFalse
	}
	if apigwAllowNeutralized(st, neutralizers, apigwDenyWorldAndCross) || apigwAllowNeutralized(st, neutralizers, apigwDenyWorldOnly) {
		return triFalse
	}
	if st.condition != nil {
		if cond, ok := st.condition["__invalid"]; ok && cond != nil {
			return triOmit
		}
		if conditionFullyRestricts(st.condition) {
			return triFalse
		}
		return triOmit
	}
	return triTrue
}

func classifyAPIGWStatementCross(st apigwPolicyStmt, ctx awsResourcePolicyContext, neutralizers []apigwDenyNeutralizer) triBool {
	if st.principal.worldEligible {
		if apigwAllowNeutralized(st, neutralizers, apigwDenyWorldAndCross) {
			return triFalse
		}
		if st.condition != nil {
			if cond, ok := st.condition["__invalid"]; ok && cond != nil {
				return triOmit
			}
			if conditionFullyRestricts(st.condition) {
				return triFalse
			}
			return triOmit
		}
		return triTrue
	}
	if sourceOwnerConditionPresent(st.condition) && !ctx.ownerOK {
		return triOmit
	}
	if st.principal.samePlanIdent {
		return triFalse
	}
	for _, p := range st.principal.aws {
		if p == samePlanIdentityPrincipal {
			return triFalse
		}
		if p == "*" {
			continue
		}
		if samePlanIdentityPrincipalRef(p, ctx.resources) {
			return triFalse
		}
		if foreign, unknown := foreignAWSPrincipal(p, ctx); unknown {
			return triOmit
		} else if foreign {
			return triTrue
		}
	}
	if st.principal.worldEligible {
		return triFalse
	}
	return triFalse
}

func apigwAllowNeutralized(st apigwPolicyStmt, neutralizers []apigwDenyNeutralizer, mode apigwDenyNeutralizeMode) bool {
	if !st.principal.worldEligible {
		return false
	}
	for _, n := range neutralizers {
		if n.mode != mode {
			continue
		}
		if apigwDenyCoversAllAllowResources(n.resources, st.resources) {
			return true
		}
	}
	return false
}
