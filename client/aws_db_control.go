package client

import (
	"fmt"
	"slices"
	"strings"
)

const iamServiceRDSControl = "rds-control"

var dbControlClassOrder = []string{
	"reset_credentials",
	"snapshot_exfiltrate",
	"restore_clone",
	"delete",
}

var knownWideDBControlPolicies = map[string]bool{
	"arn:aws:iam::aws:policy/AdministratorAccess": true,
	"arn:aws:iam::aws:policy/AmazonRDSFullAccess": true,
}

// rdsControlActionClasses is the closed v1 FR-046 action→class table (lowercase
// rds:Action names). Actions not listed do not emit control-plane classes.
var rdsControlActionClasses = map[string][]string{
	"rds:modifydbinstance":                 {"reset_credentials"},
	"rds:modifydbcluster":                  {"reset_credentials"},
	"rds:createdbsnapshot":                 {"snapshot_exfiltrate"},
	"rds:createdbclustersnapshot":          {"snapshot_exfiltrate"},
	"rds:modifydbsnapshotattribute":        {"snapshot_exfiltrate"},
	"rds:modifydbclustersnapshotattribute": {"snapshot_exfiltrate"},
	"rds:copydbsnapshot":                   {"snapshot_exfiltrate"},
	"rds:copydbclustersnapshot":            {"snapshot_exfiltrate"},
	"rds:startexporttask":                  {"snapshot_exfiltrate"},
	"rds:restoredbinstancefromdbsnapshot":  {"restore_clone"},
	"rds:restoredbinstancetopointintime":   {"restore_clone"},
	"rds:restoredbclusterfromsnapshot":     {"restore_clone"},
	"rds:restoredbclustertopointintime":    {"restore_clone"},
	"rds:deletedbinstance":                 {"delete"},
	"rds:deletedbcluster":                  {"delete"},
	"rds:deletedbsnapshot":                 {"delete"},
	"rds:deletedbclustersnapshot":          {"delete"},
}

func attachDBControlPlane(flow *Flow, src, dest *Element, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) {
	classes, scope, cause, omit := dbControlForFlow(src, dest, resources, data, idx, elements, warnings)
	if omit {
		return
	}
	if len(classes) == 0 {
		return
	}
	flow.AuthzDBControlClasses = classes
	flow.AuthzDBControlScope = scope
	if cause != "" {
		if flow.Causes == nil {
			flow.Causes = map[string]string{}
		}
		flow.Causes["authz_db_control_classes"] = cause
	}
}

func dbControlForFlow(src, dest *Element, resources, data []planResource, idx configIndex, elements []*Element, warnings *[]string) (classes []string, scope, cause string, omitBoth bool) {
	if dest.Kind != "relational_db" {
		return nil, "", "", false
	}
	r, ok := planResourceByElement(src, resources)
	if !ok || r.typ == "aws_eks_node_group" {
		return nil, "", "", false
	}
	mod, roleRefs, omit := iamRoleRefsForCompute(src, resources, data, idx)
	if omit != "" || len(roleRefs) == 0 {
		return nil, "", "", false
	}
	docs, unknownDocs, iamWarns := roleDocuments(mod, roleRefs, resources, data, idx)
	if warnings != nil {
		*warnings = append(*warnings, iamWarns...)
	}
	classes, scope, cause, unreadable := awsDBControlFromDocs(dest, docs, idx, resources, elements)
	wideCause, wide := roleKnownWideDBControl(mod, roleRefs, resources, idx)
	if wide {
		classes = allDBControlClasses()
		scope = "account"
		cause = wideCause
	}
	if unreadable && len(classes) == 0 {
		if warnings != nil {
			*warnings = append(*warnings, "db control-plane grant with unreadable Resource; omitted")
		}
		return nil, "", "", true
	}
	if len(classes) == 0 && unknownDocs {
		if role := omittedScopeRole(mod, roleRefs); role != "" {
			if warnings != nil {
				*warnings = append(*warnings, fmt.Sprintf("db control-plane omitted for %s: identity policy unknown", role))
			}
		}
		return nil, "", "", true
	}
	classes = subtractDBControlDenies(classes, scope, dest, docs, idx, resources, elements)
	if len(classes) == 0 {
		return nil, "", "", false
	}
	slices.Sort(classes)
	classes = slices.Compact(classes)
	return classes, scope, cause, false
}

func roleKnownWideDBControl(module string, roleRefs []string, resources []planResource, idx configIndex) (cause string, ok bool) {
	roles := namedResources(roleRefs, "aws_iam_role")
	if len(roles) == 0 {
		return "", false
	}
	for _, att := range resources {
		if att.typ != "aws_iam_role_policy_attachment" || !sameModule(att.address, module) {
			continue
		}
		matched, _ := matchRoleAttr(module, att, "role", roles, resources, idx)
		if len(matched) == 0 {
			continue
		}
		for _, arn := range policyARNStringsOnHolder(att, "policy_arn", idx) {
			if knownWideDBControlPolicies[strings.TrimSpace(arn)] {
				return att.address, true
			}
		}
	}
	for _, role := range resources {
		if role.typ != "aws_iam_role" || !sameModule(role.address, module) {
			continue
		}
		if !overlaps([]string{localTypeName(role.address)}, roles) {
			continue
		}
		for _, arn := range policyARNStringsOnHolder(role, "managed_policy_arns", idx) {
			if knownWideDBControlPolicies[strings.TrimSpace(arn)] {
				return role.address + " managed_policy_arns", true
			}
		}
	}
	return "", false
}

func allDBControlClasses() []string {
	out := append([]string(nil), dbControlClassOrder...)
	return out
}

func awsDBControlFromDocs(dest *Element, docs []planResource, idx configIndex, resources []planResource, elements []*Element) (classes []string, scope, cause string, unreadable bool) {
	classSet := map[string]bool{}
	account := false
	resourceScoped := false
	for _, doc := range docs {
		for _, st := range docStatements(doc) {
			grantClasses := rdsControlClassesFromStatement(st)
			if len(grantClasses) == 0 {
				continue
			}
			if !resourcesFullyKnown(st.resources) {
				if docRefsDBResource(doc, dest, idx) {
					for _, c := range grantClasses {
						classSet[c] = true
					}
					resourceScoped = true
					cause = st.doc
					continue
				}
				return nil, "", "", true
			}
			for _, raw := range st.resources {
				arn, _ := raw.(string)
				acc, match := classifyRDSControlARN(arn, dest, resources)
				if acc {
					account = true
					for _, c := range grantClasses {
						classSet[c] = true
					}
					cause = st.doc
				}
				if match {
					resourceScoped = true
					for _, c := range grantClasses {
						classSet[c] = true
					}
					cause = st.doc
				}
			}
		}
	}
	if len(classSet) == 0 {
		return nil, "", "", false
	}
	for _, c := range dbControlClassOrder {
		if classSet[c] {
			classes = append(classes, c)
		}
	}
	switch {
	case account:
		scope = "account"
	case resourceScoped:
		scope = "resource"
	default:
		scope = "account"
	}
	return classes, scope, cause, false
}

func rdsControlClassesFromStatement(st iamStatement) []string {
	var out []string
	seen := map[string]bool{}
	add := func(c string) {
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for _, a := range st.actions {
		for _, c := range rdsControlClassesForAction(a) {
			add(c)
		}
	}
	return out
}

func rdsControlClassesForAction(action string) []string {
	a := strings.ToLower(strings.TrimSpace(action))
	if a == "" {
		return nil
	}
	if a == "*" || a == "rds:*" {
		return allDBControlClasses()
	}
	if strings.ContainsAny(a, "*?") {
		return rdsControlClassesGlob(a)
	}
	if classes, ok := rdsControlActionClasses[a]; ok {
		return append([]string(nil), classes...)
	}
	return nil
}

func rdsControlClassesGlob(pattern string) []string {
	classSet := map[string]bool{}
	for action, classes := range rdsControlActionClasses {
		if iamGlobMatch(pattern, action) {
			for _, c := range classes {
				classSet[c] = true
			}
		}
	}
	if len(classSet) == 0 {
		return nil
	}
	var out []string
	for _, c := range dbControlClassOrder {
		if classSet[c] {
			out = append(out, c)
		}
	}
	return out
}

func classifyRDSControlARN(arn string, dest *Element, resources []planResource) (account, covers bool) {
	if arn == "" {
		return false, false
	}
	if arn == "*" {
		return true, false
	}
	destRes, ok := planResourceByElement(dest, resources)
	if !ok {
		if strings.ContainsAny(arn, "*?") {
			return true, false
		}
		return false, false
	}
	if destRes.typ == "aws_db_instance" {
		if instARN, ok := destRes.values["arn"].(string); ok && instARN != "" && arn == instARN {
			return false, true
		}
		if id, ok := destRes.values["identifier"].(string); ok && id != "" && strings.Contains(arn, id) {
			return false, true
		}
	}
	if destRes.typ == "aws_rds_cluster" {
		if clusterARN, ok := destRes.values["arn"].(string); ok && clusterARN != "" && arn == clusterARN {
			return false, true
		}
	}
	if strings.ContainsAny(arn, "*?") {
		return true, false
	}
	return false, false
}

func subtractDBControlDenies(classes []string, scope string, dest *Element, docs []planResource, idx configIndex, resources []planResource, elements []*Element) []string {
	if len(classes) == 0 {
		return classes
	}
	remove := map[string]bool{}
	for _, doc := range docs {
		for _, st := range docDenyStatements(doc) {
			if st.condition {
				continue
			}
			denyClasses := rdsControlClassesFromStatement(st)
			if len(denyClasses) == 0 {
				continue
			}
			if !denyCoversDBControl(st, scope, dest, resources) {
				continue
			}
			for _, c := range denyClasses {
				remove[c] = true
			}
		}
	}
	var out []string
	for _, c := range classes {
		if !remove[c] {
			out = append(out, c)
		}
	}
	return out
}

func denyCoversDBControl(st iamStatement, grantScope string, dest *Element, resources []planResource) bool {
	if !resourcesFullyKnown(st.resources) {
		return grantScope == "account"
	}
	for _, raw := range st.resources {
		arn, _ := raw.(string)
		acc, match := classifyRDSControlARN(arn, dest, resources)
		if acc || match {
			return true
		}
	}
	return false
}
