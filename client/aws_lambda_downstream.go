package client

import "strings"

// lambdaRDSFlows emits serverless_function → relational_db flows when the
// execution role carries IAM database connect grants that match an instance in
// the graph. Security-group topology is unchanged (dbFlows); this path covers
// IAM-only reachability such as RDS IAM auth without a resolvable SG peer.
func lambdaRDSFlows(resources, data []planResource, idx configIndex, elements []*Element, byAddr map[string]*Element, extra *[]*Element, warnings *[]string, iamOmitWarned map[string]bool) []*Flow {
	var flows []*Flow
	for _, fn := range resources {
		if fn.typ != "aws_lambda_function" {
			continue
		}
		fnEl := byAddr[fn.address]
		if fnEl == nil {
			fnEl = awsLambdaFunctionElement(fn)
		}
		var fnFlows []*Flow
		for _, dest := range elements {
			if dest.Kind != "relational_db" {
				continue
			}
			if !dbIAMLinkEligible(fnEl, dest, resources, data, idx, elements, warnings, iamOmitWarned) {
				continue
			}
			fnFlows = append(fnFlows, dbNetworkFlowWithAuthz(fnEl, dest, resources, data, idx, elements, warnings, iamOmitWarned))
		}
		if len(fnFlows) == 0 {
			continue
		}
		if byAddr[fn.address] == nil {
			*extra = append(*extra, fnEl)
			byAddr[fn.address] = fnEl
		}
		flows = append(flows, fnFlows...)
	}
	return flows
}

func dbIAMLinkEligible(src, dest *Element, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string, iamOmitWarned map[string]bool) bool {
	scope, grants, _, omitted := dbAuthzForFlow(src, dest, resources, data, idx, elements, warnings, iamOmitWarned)
	if omitted != "" {
		return true
	}
	return scope != "" || len(grants) > 0
}

type lambdaEnvVar struct {
	name  string
	value string
}

func lambdaSecretEnvFlows(resources, data []planResource, idx configIndex, elements []*Element, byAddr map[string]*Element, extra *[]*Element, warnings *[]string) []*Flow {
	var flows []*Flow
	for _, fn := range resources {
		if fn.typ != "aws_lambda_function" {
			continue
		}
		envs, ok := lambdaEnvVars(fn)
		if !ok {
			continue
		}
		fnEl := byAddr[fn.address]
		if fnEl == nil {
			fnEl = awsLambdaFunctionElement(fn)
		}
		mod, _, _, _ := splitResourceAddress(fn.address)
		roleRefs := idx.attrRefs(fn.address, "role")
		seenSecret := map[string]bool{}
		var fnFlows []*Flow
		for _, ev := range envs {
			kind, ref := classifyLambdaEnvValue(ev.value)
			switch kind {
			case lambdaEnvSkip:
				continue
			case lambdaEnvMaterialLiteral:
				// No secret_store flow for inline material; FR-003 needs secret_delivery on a flow.
				continue
			case lambdaEnvReference, lambdaEnvMaterialRef:
			default:
				continue
			}
			sec, ambiguous := secretElementForLambdaEnv(ref, kind, mod, resources, data, idx, elements)
			if ambiguous || sec == nil {
				if ambiguous {
					*warnings = append(*warnings, "ambiguous secret for "+ev.name+" on "+fn.address)
				}
				continue
			}
			if seenSecret[sec.canonicalKey()] {
				continue
			}
			seenSecret[sec.canonicalKey()] = true
			switch kind {
			case lambdaEnvReference:
				flow := &Flow{
					From: fnEl.canonicalKey(), To: sec.canonicalKey(),
					DataClass: "credentials", Transport: "local",
				}
				attachLambdaSecretAuthz(flow, mod, roleRefs, sec, resources, data, idx, elements, warnings)
				fnFlows = append(fnFlows, flow)
			case lambdaEnvMaterialRef:
				flow := &Flow{
					From: sec.canonicalKey(), To: fnEl.canonicalKey(),
					DataClass: "credentials", Transport: "local", SecretDelivery: "env",
					Causes: map[string]string{"secret_delivery": fn.address},
				}
				attachLambdaSecretAuthz(flow, mod, roleRefs, sec, resources, data, idx, elements, warnings)
				fnFlows = append(fnFlows, flow)
			}
		}
		if len(fnFlows) == 0 {
			continue
		}
		if byAddr[fn.address] == nil {
			*extra = append(*extra, fnEl)
			byAddr[fn.address] = fnEl
		}
		flows = append(flows, fnFlows...)
	}
	return flows
}

const (
	lambdaEnvSkip = iota
	lambdaEnvReference
	lambdaEnvMaterialRef
	lambdaEnvMaterialLiteral
)

func classifyLambdaEnvValue(val string) (kind int, ref string) {
	val = strings.TrimSpace(val)
	if val == "" {
		return lambdaEnvSkip, ""
	}
	if isLambdaEnvMaterialRef(val) {
		return lambdaEnvMaterialRef, val
	}
	if isLambdaEnvReference(val) {
		return lambdaEnvReference, val
	}
	if isLambdaEnvMaterialLiteral(val) {
		return lambdaEnvMaterialLiteral, val
	}
	return lambdaEnvSkip, ""
}

func isLambdaEnvReference(val string) bool {
	if strings.HasPrefix(val, "arn:aws:secretsmanager:") || strings.HasPrefix(val, "arn:aws:ssm:") {
		return true
	}
	if strings.Contains(val, "aws_secretsmanager_secret") && !strings.Contains(val, "secret_version") {
		return true
	}
	if strings.Contains(val, "aws_ssm_parameter") && !strings.Contains(val, ".value") {
		return true
	}
	return false
}

func isLambdaEnvMaterialRef(val string) bool {
	if strings.Contains(val, "aws_secretsmanager_secret_version") {
		return true
	}
	if strings.Contains(val, "random_password") {
		return true
	}
	if strings.Contains(val, "aws_ssm_parameter") && strings.Contains(val, "value") {
		return true
	}
	return false
}

func isLambdaEnvMaterialLiteral(val string) bool {
	if strings.HasPrefix(val, "arn:") {
		return false
	}
	if len(val) >= 24 && strings.ContainsAny(val, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") {
		return true
	}
	return false
}

func lambdaEnvVars(fn planResource) ([]lambdaEnvVar, bool) {
	if attrAfterUnknown(fn, "environment") {
		return nil, false
	}
	raw := fn.values["environment"]
	if raw == nil {
		return nil, true
	}
	var out []lambdaEnvVar
	for _, item := range asList(raw) {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		vars, _ := m["variables"].(map[string]any)
		if vars == nil {
			continue
		}
		for name, v := range vars {
			s, _ := v.(string)
			out = append(out, lambdaEnvVar{name: name, value: s})
		}
	}
	return out, true
}

func secretElementForLambdaEnv(ref string, kind int, module string, resources, data []planResource, idx configIndex, elements []*Element) (*Element, bool) {
	if kind == lambdaEnvMaterialRef {
		return secretElementFromMaterialRef(ref, module, resources, elements)
	}
	hits, amb := secretElementsFromValueFrom(ref, module, resources, elements)
	if amb {
		return nil, true
	}
	if len(hits) == 1 {
		return hits[0], false
	}
	if len(hits) > 1 {
		return nil, true
	}
	if strings.HasPrefix(ref, "arn:") {
		matched := secretElementsMatchingLiteralARN(ref, resources, elements)
		if len(matched) == 1 {
			return matched[0], false
		}
		if len(matched) > 1 {
			return nil, true
		}
	}
	return nil, false
}

func secretElementFromMaterialRef(ref, module string, resources []planResource, elements []*Element) (*Element, bool) {
	if strings.Contains(ref, "aws_secretsmanager_secret_version") {
		for _, r := range resources {
			if r.typ != "aws_secretsmanager_secret_version" {
				continue
			}
			_, _, name, ok := splitResourceAddress(r.address)
			if !ok || !containsResource(ref, "aws_secretsmanager_secret_version", name) {
				continue
			}
			for _, sidRef := range []string{
				stringFromValue(r.values["secret_id"]),
			} {
				if sidRef == "" {
					continue
				}
				hits, amb := secretElementsFromValueFrom(sidRef, module, resources, elements)
				if amb {
					return nil, true
				}
				if len(hits) == 1 {
					return hits[0], false
				}
			}
		}
	}
	if strings.Contains(ref, "random_password") {
		for _, r := range resources {
			if r.typ != "random_password" {
				continue
			}
			_, _, name, ok := splitResourceAddress(r.address)
			if !ok || !containsResource(ref, "random_password", name) {
				continue
			}
			for _, el := range elements {
				if el.Kind != "secret_store" {
					continue
				}
				for _, ver := range resources {
					if ver.typ != "aws_secretsmanager_secret_version" {
						continue
					}
					ssRef := stringFromValue(ver.values["secret_string"])
					if ssRef != "" && containsResource(ssRef, "random_password", name) {
						if len(el.Evidence.Addresses) == 1 {
							secAddr := el.Evidence.Addresses[0]
							for _, sec := range resources {
								if sec.address == secAddr && sec.typ == "aws_secretsmanager_secret" {
									for _, sidRef := range []string{stringFromValue(ver.values["secret_id"])} {
										if sidRef != "" && containsResource(sidRef, "aws_secretsmanager_secret", localTypeName(sec.address)) {
											return el, false
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return nil, false
}

func stringFromValue(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func attachLambdaSecretAuthz(flow *Flow, module string, roleRefs []string, sec *Element, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) {
	docs, unknownDocs, iamWarns := roleDocuments(module, roleRefs, resources, data, idx)
	if warnings != nil {
		*warnings = append(*warnings, iamWarns...)
	}
	wideCause, wideSecrets := roleKnownWideGrant(module, roleRefs, resources, idx, iamServiceSecretsManager)
	var scope, cause string
	var grants []string
	if !unknownDocs || wideSecrets {
		scope, grants, cause = awsSecretScope(sec, docs, idx.callRefs(module), resources, elements)
		if wideSecrets {
			scope, grants, cause = widenScopeWithKnownWide(scope, cause, wideCause)
		}
	}
	if scope != "" {
		flow.AuthzScope = scope
		flow.AuthzGrants = grants
		if cause != "" {
			if flow.Causes == nil {
				flow.Causes = map[string]string{}
			}
			flow.Causes["authz_scope"] = cause
		}
	} else if unknownDocs {
		if role := omittedScopeRole(module, roleRefs); role != "" {
			if flow.Causes == nil {
				flow.Causes = map[string]string{}
			}
			flow.Causes["authz_scope_omitted_for"] = role
		}
	}
}
