package client

import "strings"

const planResourceRefPrefix = "fray-plan-resource:"

func planResourceRef(addr string) string {
	return planResourceRefPrefix + addr
}

func planResourceRefAddr(s string) (string, bool) {
	if strings.HasPrefix(s, planResourceRefPrefix) {
		return strings.TrimPrefix(s, planResourceRefPrefix), true
	}
	return "", false
}

func awsSQSQueueElement(r planResource) *Element {
	name, _ := r.values["name"].(string)
	return &Element{
		Name: DisplayName(r.address, name, "message_queue"), Type: "datastore", Kind: "message_queue", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
	}
}

func awsSNSTopicElement(r planResource) *Element {
	name, _ := r.values["name"].(string)
	return &Element{
		Name: DisplayName(r.address, name, "message_queue"), Type: "datastore", Kind: "message_queue", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
	}
}

func sqsAction(a string) bool {
	lower := strings.ToLower(strings.TrimSpace(a))
	return lower == "*" || lower == "sqs:*" || strings.HasPrefix(lower, "sqs:")
}

func snsAction(a string) bool {
	lower := strings.ToLower(strings.TrimSpace(a))
	return lower == "*" || lower == "sns:*" || strings.HasPrefix(lower, "sns:")
}

func messageQueueFlowsForRole(fromEl *Element, module string, roleRefs []string, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) []*Flow {
	docs, unknownDocs, iamWarns := roleDocuments(module, roleRefs, resources, data, idx)
	if warnings != nil {
		*warnings = append(*warnings, iamWarns...)
	}
	var flows []*Flow
	flows = append(flows, sqsFlowsForRoleDocs(fromEl, module, roleRefs, docs, unknownDocs, resources, data, idx, elements, warnings)...)
	flows = append(flows, snsFlowsForRoleDocs(fromEl, module, roleRefs, docs, unknownDocs, resources, data, idx, elements, warnings)...)
	return flows
}

func sqsFlowsForRoleDocs(fromEl *Element, module string, roleRefs []string, docs []planResource, unknownDocs bool, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) []*Flow {
	wideCause, wideSQS := roleKnownWideGrant(module, roleRefs, resources, idx, iamServiceSQS)
	targets, grants, cause := sqsTargetsFromDocs(docs, idx.callRefs(module), resources, elements)
	if len(targets) == 0 && wideSQS {
		targets = allMessageQueueByType(elements, "aws_sqs_queue")
		grants = normalizeAuthzGrants("account")
		cause = wideCause
	}
	if len(targets) == 0 {
		return nil
	}
	return emitMessageQueueFlows(fromEl, module, roleRefs, targets, grants, cause, unknownDocs, wideSQS, wideCause, warnings)
}

func snsFlowsForRoleDocs(fromEl *Element, module string, roleRefs []string, docs []planResource, unknownDocs bool, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) []*Flow {
	wideCause, wideSNS := roleKnownWideGrant(module, roleRefs, resources, idx, iamServiceSNS)
	targets, grants, cause := snsTargetsFromDocs(docs, idx.callRefs(module), resources, elements)
	if len(targets) == 0 && wideSNS {
		targets = allMessageQueueByType(elements, "aws_sns_topic")
		grants = normalizeAuthzGrants("account")
		cause = wideCause
	}
	if len(targets) == 0 {
		return nil
	}
	return emitMessageQueueFlows(fromEl, module, roleRefs, targets, grants, cause, unknownDocs, wideSNS, wideCause, warnings)
}

func emitMessageQueueFlows(fromEl *Element, module string, roleRefs []string, targets []*Element, grants []string, cause string, unknownDocs, wide bool, wideCause string, warnings *[]string) []*Flow {
	scope := effectiveAuthzScope(grants)
	if scope == "" && !unknownDocs && !wide {
		return nil
	}
	var flows []*Flow
	for _, target := range targets {
		flow := &Flow{
			From: fromEl.canonicalKey(), To: target.canonicalKey(),
			DataClass: "unknown", Transport: "tls",
		}
		flowCause := cause
		switch {
		case wide:
			flow.AuthzScope, flow.AuthzGrants, flowCause = widenScopeWithKnownWide(scope, flowCause, wideCause)
			if flowCause != "" {
				flow.Causes = map[string]string{"authz_scope": flowCause}
			}
		case unknownDocs:
			if role := omittedScopeRole(module, roleRefs); role != "" {
				flow.Causes = map[string]string{"authz_scope_omitted_for": role}
			}
		default:
			flow.AuthzScope = scope
			flow.AuthzGrants = grants
			if flowCause != "" {
				flow.Causes = map[string]string{"authz_scope": flowCause}
			}
		}
		flows = append(flows, flow)
	}
	return flows
}

type mqGrantScan struct {
	matched      map[string]*Element
	accountWide  bool
	accountCause string
	coverCause   string
}

func sqsTargetsFromDocs(docs []planResource, callRefs []string, resources []planResource, elements []*Element) ([]*Element, []string, string) {
	if !docsGrantService(docs, sqsAction) {
		return nil, nil, ""
	}
	scan := collectMQGrants(docs, resources, elements, sqsAction, classifySQSResource)
	return assembleMQTargets(scan, "aws_sqs_queue", elements)
}

func snsTargetsFromDocs(docs []planResource, callRefs []string, resources []planResource, elements []*Element) ([]*Element, []string, string) {
	if !docsGrantService(docs, snsAction) {
		return nil, nil, ""
	}
	scan := collectMQGrants(docs, resources, elements, snsAction, classifySNSResource)
	return assembleMQTargets(scan, "aws_sns_topic", elements)
}

func docsGrantService(docs []planResource, match func(string) bool) bool {
	for _, doc := range docs {
		for _, st := range docStatements(doc) {
			if grantsAction(st, match) {
				return true
			}
		}
	}
	return false
}

func collectMQGrants(docs []planResource, resources []planResource, elements []*Element, match func(string) bool, classify func(string, []planResource, []*Element) (account bool, el *Element)) mqGrantScan {
	scan := mqGrantScan{matched: map[string]*Element{}}
	for _, doc := range docs {
		for _, st := range docStatements(doc) {
			if !grantsAction(st, match) {
				continue
			}
			if resourcesFullyKnown(st.resources) {
				for _, raw := range st.resources {
					arn, _ := raw.(string)
					acc, el := classify(arn, resources, elements)
					if acc {
						scan.accountWide = true
						scan.accountCause = st.doc
						continue
					}
					if el != nil {
						scan.matched[el.canonicalKey()] = el
						scan.coverCause = st.doc
					}
				}
				continue
			}
		}
	}
	return scan
}

func assembleMQTargets(scan mqGrantScan, resourceTyp string, elements []*Element) ([]*Element, []string, string) {
	if !scan.accountWide && len(scan.matched) == 0 {
		return nil, nil, ""
	}
	if scan.accountWide {
		targets := allMessageQueueByType(elements, resourceTyp)
		if len(targets) == 0 {
			return nil, nil, ""
		}
		return targets, normalizeAuthzGrants("resource", "account"), scan.accountCause
	}
	targets := make([]*Element, 0, len(scan.matched))
	for _, el := range scan.matched {
		targets = append(targets, el)
	}
	return targets, normalizeAuthzGrants("resource"), scan.coverCause
}

func allMessageQueueByType(elements []*Element, resourceTyp string) []*Element {
	var out []*Element
	for _, el := range elements {
		if el.Kind != "message_queue" || len(el.Evidence.Addresses) != 1 {
			continue
		}
		addr := el.Evidence.Addresses[0]
		if resourceTyp == "aws_sqs_queue" && strings.HasPrefix(addr, "aws_sqs_queue.") {
			out = append(out, el)
		}
		if resourceTyp == "aws_sns_topic" && strings.HasPrefix(addr, "aws_sns_topic.") {
			out = append(out, el)
		}
	}
	return out
}

func classifySQSResource(arn string, resources []planResource, elements []*Element) (account bool, el *Element) {
	if addr, ok := planResourceRefAddr(arn); ok {
		el := elementByPlanAddress(addr, elements)
		if el != nil && strings.HasPrefix(addr, "aws_sqs_queue.") {
			return false, el
		}
		return false, nil
	}
	if arn == "" {
		return false, nil
	}
	if arn == "*" {
		return true, nil
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[2] != "sqs" {
		if strings.ContainsAny(arn, "*?") {
			return true, nil
		}
		return false, nil
	}
	if strings.ContainsAny(parts[3], "*?") || strings.ContainsAny(parts[4], "*?") {
		return true, nil
	}
	name := parts[5]
	if strings.ContainsAny(name, "*?") {
		return true, nil
	}
	return false, sqsQueueByName(name, resources, elements)
}

func classifySNSResource(arn string, resources []planResource, elements []*Element) (account bool, el *Element) {
	if addr, ok := planResourceRefAddr(arn); ok {
		el := elementByPlanAddress(addr, elements)
		if el != nil && strings.HasPrefix(addr, "aws_sns_topic.") {
			return false, el
		}
		return false, nil
	}
	if arn == "" {
		return false, nil
	}
	if arn == "*" {
		return true, nil
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[2] != "sns" {
		if strings.ContainsAny(arn, "*?") {
			return true, nil
		}
		return false, nil
	}
	if strings.ContainsAny(parts[3], "*?") || strings.ContainsAny(parts[4], "*?") {
		return true, nil
	}
	name := parts[5]
	if strings.ContainsAny(name, "*?") {
		return true, nil
	}
	return false, snsTopicByName(name, resources, elements)
}

func elementByPlanAddress(addr string, elements []*Element) *Element {
	for _, el := range elements {
		if len(el.Evidence.Addresses) == 1 && el.Evidence.Addresses[0] == addr {
			return el
		}
	}
	return nil
}

func sqsQueueByName(name string, resources []planResource, elements []*Element) *Element {
	for _, r := range resources {
		if r.typ != "aws_sqs_queue" {
			continue
		}
		n, _ := r.values["name"].(string)
		if n == name {
			return elementByPlanAddress(r.address, elements)
		}
	}
	return nil
}

func snsTopicByName(name string, resources []planResource, elements []*Element) *Element {
	for _, r := range resources {
		if r.typ != "aws_sns_topic" {
			continue
		}
		n, _ := r.values["name"].(string)
		if n == name {
			return elementByPlanAddress(r.address, elements)
		}
	}
	return nil
}

func messageQueueFlows(svcEl *Element, module, taskAddr string, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) []*Flow {
	if taskAddr == "" {
		return nil
	}
	return messageQueueFlowsForRole(svcEl, module, idx.attrRefs(taskAddr, "task_role_arn"), resources, data, idx, elements, warnings)
}

func lambdaMessageQueueFlows(resources, data []planResource, idx configIndex, elements []*Element, byAddr map[string]*Element, extra *[]*Element, warnings *[]string) []*Flow {
	var flows []*Flow
	for _, fn := range resources {
		if fn.typ != "aws_lambda_function" {
			continue
		}
		mod, _, _, _ := splitResourceAddress(fn.address)
		roleRefs := idx.attrRefs(fn.address, "role")
		fnEl := byAddr[fn.address]
		if fnEl == nil {
			fnEl = awsLambdaFunctionElement(fn)
		}
		got := messageQueueFlowsForRole(fnEl, mod, roleRefs, resources, data, idx, elements, warnings)
		if len(got) == 0 {
			continue
		}
		if byAddr[fn.address] == nil {
			*extra = append(*extra, fnEl)
			byAddr[fn.address] = fnEl
		}
		flows = append(flows, got...)
	}
	return flows
}
