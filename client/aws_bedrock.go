package client

import (
	"strings"
)

// Bedrock inferred llm_api uses a single fixed signal so the element id is
// stable regardless of which invoke action or ARN granted access.
// Waiver form: signal:iam_service:bedrock (see matchSignal: type/name split on
// the first colon after "signal:"). Existing signal types are iam_role,
// iam_member, env_var, secret_name, network_ingress — iam_service fits the
// iam_* family without embedding ARNs or model ids.
const (
	bedrockSignalType = "iam_service"
	bedrockSignalName = "bedrock"
)

type bedrockCallerGrant struct {
	el          *Element
	scope       string // "", "resource", or "account"
	grants      []string
	cause       string
	region      string // "", "global", or a concrete region
	omittedRole string // set when unknownDocs omitted authz_scope
}

// bedrockConnections appends compute→Bedrock flows and returns an inferred
// llm_api element when at least one caller has a Bedrock invoke grant.
func bedrockConnections(
	resources, data []planResource,
	idx configIndex,
	byAddr map[string]*Element,
	extra *[]*Element,
	warnings *[]string,
) (flows []*Flow, bedrock *Element) {
	var callers []bedrockCallerGrant

	for _, svc := range resources {
		if svc.typ != "aws_ecs_service" {
			continue
		}
		svcEl := byAddr[svc.address]
		if svcEl == nil {
			continue
		}
		mod, _, _, _ := splitResourceAddress(svc.address)
		taskAddr := taskAddress(resources, mod)
		if taskAddr == "" {
			continue
		}
		roleRefs := idx.attrRefs(taskAddr, "task_role_arn")
		g, ok, iamWarns := bedrockGrantForRole(mod, roleRefs, resources, data, idx)
		if warnings != nil {
			*warnings = append(*warnings, iamWarns...)
		}
		if !ok {
			continue
		}
		g.el = svcEl
		callers = append(callers, g)
	}

	for _, fn := range resources {
		if fn.typ != "aws_lambda_function" {
			continue
		}
		mod, _, _, _ := splitResourceAddress(fn.address)
		roleRefs := idx.attrRefs(fn.address, "role")
		g, ok, iamWarns := bedrockGrantForRole(mod, roleRefs, resources, data, idx)
		if warnings != nil {
			*warnings = append(*warnings, iamWarns...)
		}
		if !ok {
			continue
		}
		fnEl := byAddr[fn.address]
		if fnEl == nil {
			fnEl = awsLambdaFunctionElement(fn)
			*extra = append(*extra, fnEl)
			byAddr[fn.address] = fnEl
		}
		g.el = fnEl
		callers = append(callers, g)
	}

	if len(callers) == 0 {
		return nil, nil
	}

	bedrock = &Element{
		Name: "Bedrock", Type: "external_entity", Kind: "llm_api", Provider: "aws",
		Provenance: "inferred",
		Evidence:   Evidence{Signals: []Signal{{Type: bedrockSignalType, Name: bedrockSignalName}}},
	}
	if region := combineBedrockRegions(callers); region != "" && regionPattern.MatchString(region) {
		bedrock.Attributes = map[string]any{"region": region}
	}

	for _, c := range callers {
		flow := &Flow{
			From: c.el.canonicalKey(), To: bedrock.canonicalKey(),
			DataClass: "unknown", Transport: "tls",
		}
		if c.scope != "" {
			flow.AuthzScope = c.scope
			flow.AuthzGrants = c.grants
			if c.cause != "" {
				flow.Causes = map[string]string{"authz_scope": c.cause}
			}
		} else if c.omittedRole != "" {
			flow.Causes = map[string]string{"authz_scope_omitted_for": c.omittedRole}
		}
		flows = append(flows, flow)
	}
	return flows, bedrock
}

func bedrockGrantForRole(module string, roleRefs []string, resources, data []planResource, idx configIndex) (bedrockCallerGrant, bool, []string) {
	docs, unknownDocs, iamWarns := roleDocuments(module, roleRefs, resources, data, idx)
	managedCause, managed := roleKnownWideGrant(module, roleRefs, resources, idx, iamServiceBedrock)

	hasAllow := managed
	var allowing []iamStatement
	for _, doc := range docs {
		for _, st := range docStatements(doc) {
			if !grantsAction(st, bedrockInvokeAction) {
				continue
			}
			hasAllow = true
			allowing = append(allowing, st)
		}
	}
	if !hasAllow {
		return bedrockCallerGrant{}, false, iamWarns
	}

	g := bedrockCallerGrant{}
	// Unknown identity-policy source: known Allow still emits the flow. A known-
	// wide Bedrock managed policy still reports account; other unread policies
	// omit scope.
	if unknownDocs {
		if managed {
			g.scope = "account"
			g.grants = normalizeAuthzGrants("account")
			g.cause = managedCause
			g.region = callerRegionFromAllows(allowing, true)
			return g, true, iamWarns
		}
		g.omittedRole = omittedScopeRole(module, roleRefs)
		return g, true, iamWarns
	}
	// Deny of Bedrock invoke on any role doc → omit scope (still emit the flow).
	for _, doc := range docs {
		for _, st := range docDenyStatements(doc) {
			if grantsAction(st, bedrockInvokeAction) {
				g.region = callerRegionFromAllows(allowing, managed)
				return g, true, iamWarns
			}
		}
	}

	omitScope := false
	for _, st := range allowing {
		if st.condition || len(st.notActions) > 0 || len(st.notResources) > 0 {
			omitScope = true
			break
		}
		if resourcesUnknown(st.resources) {
			omitScope = true
			break
		}
	}

	if managed && !omitScope {
		g.scope = "account"
		g.grants = normalizeAuthzGrants("account")
		g.cause = managedCause
	}
	if !omitScope && len(allowing) > 0 {
		scope, cause, ok := bedrockScopeFromAllows(allowing)
		if !ok {
			omitScope = true
			g.scope = ""
			g.grants = nil
			g.cause = ""
		} else if managed {
			// Managed FullAccess is account-wide; keep account even if docs are narrower.
			g.scope = "account"
			g.grants = normalizeAuthzGrants("account")
			if g.cause == "" {
				g.cause = managedCause
			}
		} else {
			g.scope = scope
			g.grants = normalizeAuthzGrants(scope)
			g.cause = cause
		}
	}
	if omitScope {
		g.scope = ""
		g.grants = nil
		g.cause = ""
	}
	g.region = callerRegionFromAllows(allowing, managed)
	return g, true, iamWarns
}

func bedrockInvokeAction(a string) bool {
	lower := strings.ToLower(strings.TrimSpace(a))
	switch {
	case lower == "*", lower == "bedrock:*":
		return true
	case lower == "bedrock:invokemodel", lower == "bedrock:invokemodelwithresponsestream":
		return true
	case strings.HasPrefix(lower, "bedrock:invokemodel"):
		// bedrock:InvokeModel*
		return true
	case strings.HasPrefix(lower, "bedrock:invoke"):
		// bedrock:Invoke*
		return true
	default:
		return false
	}
}

func resourcesUnknown(resources []any) bool {
	if len(resources) == 0 {
		return true
	}
	for _, r := range resources {
		if r == nil {
			return true
		}
		s, ok := r.(string)
		if !ok || s == "" {
			return true
		}
	}
	return false
}

func bedrockScopeFromAllows(allows []iamStatement) (scope, cause string, ok bool) {
	account := false
	resource := false
	accountCause, resourceCause := "", ""
	for _, st := range allows {
		for _, raw := range st.resources {
			s, is := raw.(string)
			if !is || s == "" {
				return "", "", false
			}
			if s == "*" {
				account = true
				accountCause = st.doc
				continue
			}
			_, _, resID, parsed := parseBedrockARN(s)
			if !parsed {
				return "", "", false
			}
			if strings.ContainsAny(resID, "*?") {
				account = true
				accountCause = st.doc
				continue
			}
			resource = true
			if resourceCause == "" {
				resourceCause = st.doc
			}
		}
	}
	var scopes []string
	if resource {
		scopes = append(scopes, "resource")
		cause = resourceCause
	}
	if account {
		scopes = append(scopes, "account")
		cause = accountCause
	}
	grants := normalizeAuthzGrants(scopes...)
	scope = effectiveAuthzScope(grants)
	if scope == "" {
		return "", "", false
	}
	return scope, cause, true
}

func parseBedrockARN(arn string) (region, resType, resID string, ok bool) {
	// arn:partition:service:region:account:resource
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return "", "", "", false
	}
	if parts[0] != "arn" || parts[2] != "bedrock" {
		return "", "", "", false
	}
	region = parts[3]
	resource := parts[5]
	i := strings.IndexByte(resource, '/')
	if i <= 0 || i == len(resource)-1 {
		return "", "", "", false
	}
	return region, resource[:i], resource[i+1:], true
}

func callerRegionFromAllows(allows []iamStatement, managed bool) string {
	// AmazonBedrockFullAccess is account-wide; never pin a region from narrower docs.
	if managed {
		return ""
	}
	if len(allows) == 0 {
		return ""
	}
	// Order-independent: any global.* inference profile wins over geographic profiles.
	for _, st := range allows {
		for _, raw := range st.resources {
			s, ok := raw.(string)
			if !ok {
				continue
			}
			_, resType, resID, parsed := parseBedrockARN(s)
			if parsed && resType == "inference-profile" && strings.HasPrefix(resID, "global.") {
				return "global"
			}
		}
	}
	var concrete string
	sawConcrete := false
	for _, st := range allows {
		for _, raw := range st.resources {
			s, ok := raw.(string)
			if !ok {
				return ""
			}
			if s == "*" {
				return ""
			}
			region, resType, _, ok := parseBedrockARN(s)
			if !ok {
				return ""
			}
			switch resType {
			case "inference-profile":
				// Geographic (eu./us./apac.) and other non-global profiles → unknown region.
				return ""
			case "application-inference-profile":
				return ""
			case "foundation-model", "provisioned-model", "custom-model":
				if region == "" || strings.ContainsAny(region, "*?") {
					return ""
				}
				if !sawConcrete {
					concrete = region
					sawConcrete = true
				} else if concrete != region {
					return ""
				}
			default:
				return ""
			}
		}
	}
	if sawConcrete {
		return concrete
	}
	return ""
}

func combineBedrockRegions(callers []bedrockCallerGrant) string {
	// any global → global; else every caller must share one concrete region.
	var concrete string
	sawConcrete := false
	for _, c := range callers {
		if c.region == "global" {
			return "global"
		}
	}
	for _, c := range callers {
		if c.region == "" {
			return ""
		}
		if !sawConcrete {
			concrete = c.region
			sawConcrete = true
		} else if concrete != c.region {
			return ""
		}
	}
	if sawConcrete {
		return concrete
	}
	return ""
}
