package client

import (
	"encoding/json"
	"regexp"
	"strings"
)

const samePlanIdentityPrincipal = "__fray_same_plan_identity__"

var awsAccountIDPattern = regexp.MustCompile(`^\d{12}$`)

// triBool is a three-valued classification axis (omit / false / true).
type triBool int

const (
	triOmit triBool = iota
	triFalse
	triTrue
)

type resourcePolicyClass struct {
	world triBool
	cross triBool
	cause string
}

type awsResourcePolicyContext struct {
	resources []planResource
	data      []planResource
	idx       configIndex
	plan      []byte
	owner     string
	ownerOK   bool
}

func applyDynamoDBResourcePolicies(resources, data []planResource, idx configIndex, plan []byte, byAddr map[string]*Element, warnings *[]string) {
	ctx := newAWSResourcePolicyContext(resources, data, idx, plan)
	linked := map[string][]resourcePolicyClass{}
	unlinkedPolicy := false
	for _, rp := range resources {
		if rp.typ != "aws_dynamodb_resource_policy" {
			continue
		}
		mod, _, _, _ := splitResourceAddress(rp.address)
		el, linkOK := dynamoElementForResourcePolicy(rp, mod, resources, data, idx, byAddr)
		if !linkOK || el == nil {
			unlinkedPolicy = true
			*warnings = append(*warnings, "unlinked resource policy "+rp.address+"; table attributes omitted where policy presence is unknown")
			continue
		}
		tableKey := el.canonicalKey()
		docs, unknown := resolvePolicyContent(rp, "policy", mod, data, resources, idx)
		cause := rp.address
		if len(docs) == 1 && docs[0].address != "" && docs[0].address != rp.address {
			cause = docs[0].address
		}
		var class resourcePolicyClass
		if unknown || len(docs) == 0 {
			class = resourcePolicyClass{world: triOmit, cross: triOmit, cause: cause}
			if unknown {
				*warnings = append(*warnings, "unreadable resource policy on "+rp.address+"; attributes omitted")
			}
		} else {
			class = classifyResourcePolicyDocs(docs, ctx)
			class.cause = cause
		}
		linked[tableKey] = append(linked[tableKey], class)
	}
	for _, el := range byAddr {
		if el == nil || el.Kind != "nosql_db" {
			continue
		}
		key := el.canonicalKey()
		policies := linked[key]
		if len(policies) == 0 {
			if unlinkedPolicy {
				continue
			}
			tableCause := ""
			if len(el.Evidence.Addresses) > 0 {
				tableCause = el.Evidence.Addresses[0]
			}
			setResourcePolicyAttrs(el, false, false, tableCause)
			continue
		}
		world, cross, cause := mergeResourcePolicyClasses(policies)
		setResourcePolicyAttrsFromTri(el, world, cross, cause)
	}
}

func dynamoElementForResourcePolicy(rp planResource, module string, resources, data []planResource, idx configIndex, byAddr map[string]*Element) (*Element, bool) {
	if arn, ok := rp.values["resource_arn"].(string); ok && strings.TrimSpace(arn) != "" && !attrAfterUnknown(rp, "resource_arn") {
		for addr, el := range byAddr {
			if el == nil || el.Kind != "nosql_db" {
				continue
			}
			if table, ok := planResourceByAddress(addr, resources); ok {
				if tableARN, ok := table.values["arn"].(string); ok && tableARN == arn {
					return el, true
				}
			}
			if elMatch, ok := elementForDynamoResourceARN(arn, resources, []*Element{el}); ok {
				return elMatch, true
			}
		}
	}
	refs := idx.attrRefs(rp.address, "resource_arn")
	tbl, ok := resolveSingleByRef(refs, resources, data, idx, dynamoTableRefOpts)
	if !ok {
		return nil, false
	}
	el := byAddr[tbl.address]
	return el, el != nil
}

func planResourceByAddress(addr string, resources []planResource) (planResource, bool) {
	for _, r := range resources {
		if r.address == addr {
			return r, true
		}
	}
	return planResource{}, false
}

func elementForDynamoResourceARN(arn string, resources []planResource, elements []*Element) (*Element, bool) {
	_, el := classifyDynamoDBARN(arn, resources, elements)
	return el, el != nil
}

func newAWSResourcePolicyContext(resources, data []planResource, idx configIndex, plan []byte) awsResourcePolicyContext {
	ctx := awsResourcePolicyContext{
		resources: resources,
		data:      data,
		idx:       idx,
		plan:      plan,
	}
	ctx.owner, ctx.ownerOK = awsResourcePolicyOwnerAccount(resources, data, plan)
	return ctx
}

func awsResourcePolicyOwnerAccount(resources, data []planResource, plan []byte) (string, bool) {
	for _, d := range data {
		if d.typ != "aws_caller_identity" {
			continue
		}
		if attrUnknownMap(d.afterUnknown, "account_id") {
			continue
		}
		if id, ok := d.values["account_id"].(string); ok && awsAccountIDPattern.MatchString(id) {
			return id, true
		}
	}
	if id, ok := singleAllowedAWSAccountID(plan); ok {
		return id, true
	}
	for _, r := range resources {
		if r.typ != "aws_iam_role" && r.typ != "aws_iam_user" {
			continue
		}
		if acc := accountFromResourceARN(r.values["arn"]); acc != "" {
			return acc, true
		}
	}
	return "", false
}

func singleAllowedAWSAccountID(plan []byte) (string, bool) {
	if len(plan) == 0 {
		return "", false
	}
	var root struct {
		Configuration struct {
			ProviderConfig map[string]struct {
				Expressions map[string]struct {
					ConstantValue json.RawMessage `json:"constant_value"`
				} `json:"expressions"`
			} `json:"provider_config"`
		} `json:"configuration"`
	}
	if err := json.Unmarshal(plan, &root); err != nil {
		return "", false
	}
	for _, pc := range root.Configuration.ProviderConfig {
		expr, ok := pc.Expressions["allowed_account_ids"]
		if !ok || len(expr.ConstantValue) == 0 {
			continue
		}
		var ids []string
		if err := json.Unmarshal(expr.ConstantValue, &ids); err != nil {
			var one string
			if err := json.Unmarshal(expr.ConstantValue, &one); err != nil {
				return "", false
			}
			ids = []string{one}
		}
		if len(ids) != 1 || !awsAccountIDPattern.MatchString(ids[0]) {
			return "", false
		}
		return ids[0], true
	}
	return "", false
}

func classifyResourcePolicyDocs(docs []planResource, ctx awsResourcePolicyContext) resourcePolicyClass {
	var parts []resourcePolicyClass
	for _, doc := range docs {
		parts = append(parts, classifyResourcePolicyDoc(doc, ctx))
	}
	return mergeResourcePolicyClassesSlice(parts)
}

type resourcePolicyDocOptions struct {
	neutralizeAnyPrincipalAllow bool
	neutralizeCause             string
}

func classifyResourcePolicyDoc(doc planResource, ctx awsResourcePolicyContext) resourcePolicyClass {
	return classifyResourcePolicyDocWithOptions(doc, ctx, resourcePolicyDocOptions{})
}

func classifyResourcePolicyDocWithOptions(doc planResource, ctx awsResourcePolicyContext, opts resourcePolicyDocOptions) resourcePolicyClass {
	stmts := resourcePolicyStatements(doc)
	if len(stmts) == 0 {
		return resourcePolicyClass{world: triOmit, cross: triOmit}
	}
	for _, st := range stmts {
		if st.deny && st.condition != nil {
			return resourcePolicyClass{world: triOmit, cross: triOmit, cause: st.doc}
		}
	}
	var world, cross triBool = triFalse, triFalse
	skippedAnyPrincipal := false
	for _, st := range stmts {
		if st.deny {
			continue
		}
		if opts.neutralizeAnyPrincipalAllow && st.allow && st.principal.worldEligible {
			skippedAnyPrincipal = true
			continue
		}
		w := classifyStatementWorld(st)
		c := classifyStatementCross(st, ctx)
		world = mergeTriOrTrue(world, w)
		cross = mergeTriOrTrue(cross, c)
	}
	if world == triTrue {
		// Any principal includes principals in other accounts.
		cross = triTrue
	}
	cause := doc.address
	if opts.neutralizeCause != "" && world == triFalse && cross == triFalse && skippedAnyPrincipal {
		cause = opts.neutralizeCause
	}
	return resourcePolicyClass{world: world, cross: cross, cause: cause}
}

func mergeResourcePolicyClasses(classes []resourcePolicyClass) (world, cross triBool, cause string) {
	merged := mergeResourcePolicyClassesSlice(classes)
	return merged.world, merged.cross, merged.cause
}

func mergeResourcePolicyClassesSlice(classes []resourcePolicyClass) resourcePolicyClass {
	if len(classes) == 0 {
		return resourcePolicyClass{world: triFalse, cross: triFalse}
	}
	world, cross := triFalse, triFalse
	cause := ""
	for _, c := range classes {
		if c.cause != "" && cause == "" {
			cause = c.cause
		}
		world = mergeTriAnyTrue(world, c.world)
		cross = mergeTriAnyTrue(cross, c.cross)
	}
	if world == triTrue {
		cross = triTrue
	}
	return resourcePolicyClass{world: world, cross: cross, cause: cause}
}

func mergeTriAnyTrue(acc, v triBool) triBool {
	if acc == triTrue || v == triTrue {
		return triTrue
	}
	if acc == triOmit || v == triOmit {
		return triOmit
	}
	return triFalse
}

func mergeTriOrTrue(acc, v triBool) triBool {
	if v == triTrue {
		return triTrue
	}
	if v == triOmit {
		if acc == triTrue {
			return triTrue
		}
		return triOmit
	}
	return acc
}

type resourcePolicyStmt struct {
	allow     bool
	deny      bool
	doc       string
	condition map[string]any
	principal resourcePolicyPrincipal
}

type resourcePolicyPrincipal struct {
	worldEligible bool
	aws           []string
	services      []string
	samePlanIdent bool
}

func resourcePolicyStatements(doc planResource) []resourcePolicyStmt {
	var out []resourcePolicyStmt
	for _, raw := range asList(doc.values["statement"]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		effect, _ := firstKey(m, "Effect", "effect")
		effectStr, _ := effect.(string)
		st := resourcePolicyStmt{
			allow:     strings.EqualFold(effectStr, "Allow"),
			deny:      strings.EqualFold(effectStr, "Deny"),
			doc:       doc.address,
			condition: normalizeResourcePolicyCondition(firstKeyValue(m, "Condition", "condition")),
			principal: parseResourcePolicyPrincipal(m),
		}
		out = append(out, st)
	}
	return out
}

func firstKeyValue(m map[string]any, keys ...string) any {
	v, ok := firstKey(m, keys...)
	if !ok {
		return nil
	}
	return v
}

func parseResourcePolicyPrincipal(m map[string]any) resourcePolicyPrincipal {
	if v, ok := firstKey(m, "Principal", "principal"); ok {
		return principalFromIAMJSON(v)
	}
	if v, ok := m["principals"]; ok {
		return principalFromTerraformDoc(v)
	}
	return resourcePolicyPrincipal{}
}

func principalFromIAMJSON(v any) resourcePolicyPrincipal {
	switch t := v.(type) {
	case string:
		if t == "*" {
			return resourcePolicyPrincipal{worldEligible: true}
		}
		return resourcePolicyPrincipal{}
	case map[string]any:
		var out resourcePolicyPrincipal
		if aws, ok := t["AWS"]; ok {
			out = mergeResourcePolicyPrincipal(out, principalAWSFromValues(aws))
		}
		if svc, ok := t["Service"]; ok {
			for _, s := range stringListAny(svc) {
				if s == "*" {
					out.worldEligible = true
				} else if s != "" {
					out.services = append(out.services, s)
				}
			}
		}
		return out
	default:
		return resourcePolicyPrincipal{}
	}
}

func principalFromTerraformDoc(v any) resourcePolicyPrincipal {
	var out resourcePolicyPrincipal
	for _, raw := range asList(v) {
		block, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := block["type"].(string)
		ids := stringListAny(block["identifiers"])
		switch typ {
		case "*", "AWS":
			for _, id := range ids {
				if id == "*" {
					out.worldEligible = true
				} else if id != "" {
					out.aws = append(out.aws, id)
				}
			}
		case "Service":
			for _, id := range ids {
				if id == "*" {
					out.worldEligible = true
				} else if id != "" {
					out.services = append(out.services, id)
				}
			}
		}
	}
	return out
}

func mergeResourcePolicyPrincipal(a, b resourcePolicyPrincipal) resourcePolicyPrincipal {
	a.aws = append(a.aws, b.aws...)
	a.services = append(a.services, b.services...)
	a.worldEligible = a.worldEligible || b.worldEligible
	a.samePlanIdent = a.samePlanIdent || b.samePlanIdent
	return a
}

func principalAWSFromValues(v any) resourcePolicyPrincipal {
	var out resourcePolicyPrincipal
	for _, p := range principalAWSValues(v) {
		if p == "*" {
			out.worldEligible = true
			continue
		}
		if p == samePlanIdentityPrincipal {
			out.samePlanIdent = true
			continue
		}
		out.aws = append(out.aws, p)
	}
	return out
}

func principalAWSValues(v any) []string {
	switch t := v.(type) {
	case string:
		if t == samePlanIdentityPrincipal {
			return []string{samePlanIdentityPrincipal}
		}
		return []string{t}
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return stringListAny(v)
	}
}

func stringListAny(v any) []string {
	return stringList(v)
}

func normalizeResourcePolicyCondition(v any) map[string]any {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]any); ok {
		if len(m) == 0 {
			return nil
		}
		return m
	}
	list := asList(v)
	if len(list) == 0 {
		return nil
	}
	out := map[string]any{}
	for _, raw := range list {
		block, ok := raw.(map[string]any)
		if !ok {
			return map[string]any{"__invalid": true}
		}
		test, _ := block["test"].(string)
		variable, _ := block["variable"].(string)
		if test == "" || variable == "" {
			return map[string]any{"__invalid": true}
		}
		vals := asList(block["values"])
		if len(vals) == 0 {
			return map[string]any{"__invalid": true}
		}
		opBody, ok := out[test].(map[string]any)
		if !ok {
			opBody = map[string]any{}
			out[test] = opBody
		}
		if len(vals) == 1 {
			opBody[variable] = vals[0]
		} else {
			opBody[variable] = vals
		}
	}
	return out
}

func classifyStatementWorld(st resourcePolicyStmt) triBool {
	if !st.allow {
		return triFalse
	}
	if !st.principal.worldEligible {
		return triFalse
	}
	if st.condition == nil {
		return triTrue
	}
	if cond, ok := st.condition["__invalid"]; ok && cond != nil {
		return triOmit
	}
	if conditionFullyRestricts(st.condition) {
		return triFalse
	}
	return triOmit
}

func classifyStatementCross(st resourcePolicyStmt, ctx awsResourcePolicyContext) triBool {
	if !st.allow {
		return triFalse
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
	return triFalse
}

func samePlanIdentityPrincipalRef(p string, resources []planResource) bool {
	if p == samePlanIdentityPrincipal {
		return true
	}
	if strings.HasPrefix(p, "arn:aws:iam::") {
		return false
	}
	// Unmaterialized refs are not passed here; HCL uses samePlanIdentityPrincipal marker.
	return false
}

func foreignAWSPrincipal(p string, ctx awsResourcePolicyContext) (foreign, unknown bool) {
	if p == "" || p == "*" {
		return false, false
	}
	acc := accountFromPrincipalAWS(p)
	if acc == "" {
		return false, true
	}
	if !ctx.ownerOK {
		return false, true
	}
	return acc != ctx.owner, false
}

func accountFromPrincipalAWS(p string) string {
	if awsAccountIDPattern.MatchString(p) {
		return p
	}
	return accountFromResourceARN(p)
}

func accountFromResourceARN(arn any) string {
	s, _ := arn.(string)
	if s == "" {
		return ""
	}
	parts := strings.Split(s, ":")
	if len(parts) < 5 {
		return ""
	}
	if parts[0] != "arn" {
		return ""
	}
	acc := parts[4]
	if awsAccountIDPattern.MatchString(acc) {
		return acc
	}
	return ""
}

var restrictingResourcePolicyConditionKeys = map[string]struct{}{
	"aws:SourceOwner":      {},
	"AWS:SourceOwner":      {}, // SNS topic policies often use the service-prefixed key.
	"aws:SourceAccount":    {},
	"aws:SourceArn":        {},
	"aws:PrincipalOrgID":   {},
	"aws:PrincipalAccount": {},
	"aws:SourceVpc":        {},
	"aws:SourceVpce":       {},
}

func sourceOwnerConditionPresent(cond map[string]any) bool {
	if len(cond) == 0 {
		return false
	}
	for _, body := range cond {
		m, ok := body.(map[string]any)
		if !ok {
			continue
		}
		for key := range m {
			if key == "aws:SourceOwner" || key == "AWS:SourceOwner" {
				return true
			}
		}
	}
	return false
}

func conditionFullyRestricts(cond map[string]any) bool {
	if len(cond) == 0 {
		return false
	}
	for _, body := range cond {
		m, ok := body.(map[string]any)
		if !ok {
			return false
		}
		for key, val := range m {
			if _, ok := restrictingResourcePolicyConditionKeys[key]; !ok {
				return false
			}
			if !concreteRestrictingValue(key, val) {
				return false
			}
		}
	}
	return true
}

func concreteRestrictingValue(key string, val any) bool {
	switch t := val.(type) {
	case string:
		return concreteConditionString(key, t)
	case []any:
		if len(t) == 0 {
			return false
		}
		for _, item := range t {
			s, ok := item.(string)
			if !ok || !concreteConditionString(key, s) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func concreteConditionString(key, s string) bool {
	if s == "" || strings.Contains(s, "*") {
		return false
	}
	if _, ok := planResourceRefAddr(s); ok {
		switch key {
		case "aws:SourceVpce", "aws:SourceVpc":
			return true
		default:
			return false
		}
	}
	if key == "aws:SourceArn" && sourceARNAccountWildcard(s) {
		return false
	}
	return true
}

func sourceARNAccountAccountSegment(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 5 || parts[0] != "arn" {
		return ""
	}
	return parts[4]
}

func sourceARNAccountWildcard(s string) bool {
	acc := sourceARNAccountAccountSegment(s)
	return strings.Contains(acc, "*")
}

func setResourcePolicyAttrsFromTri(el *Element, world, cross triBool, cause string) {
	if world == triOmit && cross == triOmit {
		return
	}
	if el.Attributes == nil {
		el.Attributes = map[string]any{}
	}
	if el.Causes == nil {
		el.Causes = map[string]string{}
	}
	if world != triOmit {
		el.Attributes["resource_policy_world_principal"] = world == triTrue
		el.Causes["resource_policy_world_principal"] = cause
	}
	// Invariant: cross is emitted only when world is known; any-principal world implies cross.
	if world == triTrue {
		el.Attributes["resource_policy_cross_account"] = true
		el.Causes["resource_policy_cross_account"] = cause
	} else if world != triOmit && cross != triOmit {
		el.Attributes["resource_policy_cross_account"] = cross == triTrue
		el.Causes["resource_policy_cross_account"] = cause
	}
}

func setResourcePolicyAttrs(el *Element, world, cross bool, cause string) {
	if el.Attributes == nil {
		el.Attributes = map[string]any{}
	}
	el.Attributes["resource_policy_world_principal"] = world
	el.Attributes["resource_policy_cross_account"] = cross
	if cause != "" {
		if el.Causes == nil {
			el.Causes = map[string]string{}
		}
		el.Causes["resource_policy_world_principal"] = cause
		el.Causes["resource_policy_cross_account"] = cause
	}
}
