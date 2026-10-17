package client

import "strings"

var dynamoTableRefOpts = resolveSingleByRefOpts{
	ResourceType:     "aws_dynamodb_table",
	SkipVarRef:       true,
	BareModule:       bareModuleSkipWithVar,
	EmptyNameManaged: emptyNameContinue,
}

func awsDynamoDBTableElement(r planResource, prevent bool) *Element {
	name, _ := r.values["name"].(string)
	attrs := map[string]any{}
	if prevent {
		attrs["deletion_protection"] = true
	} else if v, ok := r.values["deletion_protection_enabled"].(bool); ok {
		attrs["deletion_protection"] = v
	}
	if !attrUnknownMap(r.afterUnknown, "deletion_protection_enabled") {
		if v, ok := r.values["deletion_protection_enabled"].(bool); ok {
			attrs["provider_deletion_protection"] = v
		}
	}
	return &Element{
		Name: DisplayName(r.address, name, "nosql_db"), Type: "datastore", Kind: "nosql_db", Provider: "aws",
		Provenance: "iac",
		Evidence:   Evidence{Addresses: []string{r.address}},
		Attributes: attrs,
	}
}

func dynamodbAction(a string) bool {
	lower := strings.ToLower(strings.TrimSpace(a))
	return lower == "*" || lower == "dynamodb:*" || strings.HasPrefix(lower, "dynamodb:")
}

func tableFlowsForRole(fromEl *Element, module string, roleRefs []string, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) []*Flow {
	docs, unknownDocs, iamWarns := roleDocuments(module, roleRefs, resources, data, idx)
	if warnings != nil {
		*warnings = append(*warnings, iamWarns...)
	}
	wideCause, wideDD := roleKnownWideGrant(module, roleRefs, resources, idx, iamServiceDynamoDB)
	tables, grants, cause, actionWarn := tablesFromDocs(docs, idx.callRefs(module), resources, data, elements, idx)
	if len(tables) == 0 {
		return nil
	}
	if actionWarn != "" && warnings != nil {
		*warnings = append(*warnings, actionWarn)
	}
	scope := effectiveAuthzScope(grants)
	if scope == "" && !unknownDocs && !wideDD {
		return nil
	}
	var flows []*Flow
	for _, tbl := range tables {
		flow := &Flow{
			From: fromEl.canonicalKey(), To: tbl.canonicalKey(),
			DataClass: "unknown", Transport: "tls",
		}
		flowCause := cause
		switch {
		case wideDD:
			flow.AuthzScope, flow.AuthzGrants, flowCause = widenScopeWithKnownWide(scope, cause, wideCause)
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

func tableFlows(svcEl *Element, module, taskAddr string, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) []*Flow {
	if taskAddr == "" {
		return nil
	}
	return tableFlowsForRole(svcEl, module, idx.attrRefs(taskAddr, "task_role_arn"), resources, data, idx, elements, warnings)
}

func dynamodbLambdaFlows(resources, data []planResource, idx configIndex, elements []*Element, byAddr map[string]*Element, extra *[]*Element, warnings *[]string) []*Flow {
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
		got := tableFlowsForRole(fnEl, mod, roleRefs, resources, data, idx, elements, warnings)
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

type dynamoGrantScan struct {
	matched      map[string]*Element
	accountWide  bool
	accountCause string
	coverCause   string
}

// tablesFromDocs resolves DynamoDB table targets and authz_grants for IAM docs.
// One flow per explicitly matched table; wildcard-only grants use account scope
// and target a single table only when callRefs or the plan has exactly one table.
func tablesFromDocs(docs []planResource, callRefs []string, resources, data []planResource, elements []*Element, idx configIndex) (tables []*Element, grants []string, cause string, actionWarn string) {
	if !docsGrantDynamoDB(docs) {
		return nil, nil, "", ""
	}
	resolved, amb := dynamoTablesFromCallRefs(callRefs, resources, data, idx, elements)
	if amb {
		return nil, nil, "", ""
	}
	scan := collectDynamoDBGrants(docs, resources, elements, idx)
	return assembleDynamoTableTargets(scan, resolved, elements)
}

func collectDynamoDBGrants(docs []planResource, resources []planResource, elements []*Element, idx configIndex) dynamoGrantScan {
	scan := dynamoGrantScan{matched: map[string]*Element{}}
	for _, doc := range docs {
		for _, st := range docStatements(doc) {
			if !grantsAction(st, dynamodbAction) {
				continue
			}
			applyDynamoStatementGrant(&scan, doc, st, resources, elements, idx)
		}
	}
	return scan
}

func applyDynamoStatementGrant(scan *dynamoGrantScan, doc planResource, st iamStatement, resources []planResource, elements []*Element, idx configIndex) {
	if resourcesFullyKnown(st.resources) {
		applyKnownDynamoResources(scan, st, resources, elements)
		return
	}
	// Plan-time null/unknown Resource slots (common on data.aws_iam_policy_document):
	// match tables from configuration statement references, same as RDS db scope.
	applyUnknownDynamoResources(scan, doc, st.doc, elements, idx)
}

func applyKnownDynamoResources(scan *dynamoGrantScan, st iamStatement, resources []planResource, elements []*Element) {
	for _, raw := range st.resources {
		arn, _ := raw.(string)
		acc, el := classifyDynamoDBARN(arn, resources, elements)
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
}

func applyUnknownDynamoResources(scan *dynamoGrantScan, doc planResource, coverCause string, elements []*Element, idx configIndex) {
	for _, el := range elements {
		if el.Kind != "nosql_db" {
			continue
		}
		if docRefsDynamoDBTable(doc, el, idx) {
			scan.matched[el.canonicalKey()] = el
			scan.coverCause = coverCause
		}
	}
}

func assembleDynamoTableTargets(scan dynamoGrantScan, resolved []*Element, elements []*Element) ([]*Element, []string, string, string) {
	if len(scan.matched) > 0 {
		grants, cause := dynamoTableGrants(scan.accountWide, scan.coverCause, scan.accountCause)
		return dynamoTablesFromMatched(scan.matched), grants, cause, ""
	}
	// Wildcard-only grants with no named table: target the sole plan table if any.
	if !scan.accountWide {
		return nil, nil, "", ""
	}
	target := singleDynamoDBTableTarget(resolved, elements)
	if target == nil {
		return nil, nil, "", ""
	}
	accountCause := scan.accountCause
	if accountCause == "" {
		accountCause = scan.coverCause
	}
	return []*Element{target}, normalizeAuthzGrants("account"), accountCause, ""
}

func dynamoTablesFromMatched(matched map[string]*Element) []*Element {
	tables := make([]*Element, 0, len(matched))
	for _, el := range matched {
		tables = append(tables, el)
	}
	return tables
}

func docsGrantDynamoDB(docs []planResource) bool {
	for _, doc := range docs {
		for _, st := range docStatements(doc) {
			if grantsAction(st, dynamodbAction) {
				return true
			}
		}
	}
	return false
}

func dynamoTableGrants(accountWide bool, coverCause, accountCause string) ([]string, string) {
	if accountWide {
		return normalizeAuthzGrants("resource", "account"), accountCause
	}
	return normalizeAuthzGrants("resource"), coverCause
}

func dynamoTablesFromCallRefs(callRefs []string, resources, data []planResource, idx configIndex, elements []*Element) ([]*Element, bool) {
	resolved, amb := elementsFromRefs(callRefs, resources, elements, "aws_dynamodb_table")
	if amb {
		return nil, true
	}
	if len(resolved) > 0 {
		return resolved, false
	}
	tbl, ok := resolveSingleByRef(callRefs, resources, data, idx, dynamoTableRefOpts)
	if !ok {
		return nil, false
	}
	el := elementForAddress(tbl.address, elements)
	if el == nil {
		return nil, false
	}
	return []*Element{el}, false
}

func singleDynamoDBTableTarget(resolved []*Element, elements []*Element) *Element {
	if len(resolved) == 1 {
		return resolved[0]
	}
	var all []*Element
	for _, el := range elements {
		if el.Kind == "nosql_db" {
			all = append(all, el)
		}
	}
	if len(all) == 1 {
		return all[0]
	}
	return nil
}
