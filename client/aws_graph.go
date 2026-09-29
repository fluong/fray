package client

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
)

type exprSet struct {
	refs      map[string][]string
	constants map[string]any
}

type configIndex struct {
	resources map[string]exprSet
	calls     map[string]exprSet
}

func (idx configIndex) attrRefs(address, attr string) []string {
	key, ok := resourceKey(address)
	if !ok {
		return nil
	}
	return idx.resources[key].refs[attr]
}

func (idx configIndex) callRefs(moduleAddr string) []string {
	set := idx.calls[moduleAddr]
	var out []string
	for _, refs := range set.refs {
		out = append(out, refs...)
	}
	return out
}

func (idx configIndex) callConstant(moduleAddr, attr string) any {
	return idx.calls[moduleAddr].constants[attr]
}

func indexConfig(plan []byte) (configIndex, error) {
	var root struct {
		Configuration struct {
			RootModule map[string]any `json:"root_module"`
		} `json:"configuration"`
	}
	dec := json.NewDecoder(bytes.NewReader(plan))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return configIndex{}, err
	}
	idx := configIndex{
		resources: map[string]exprSet{},
		calls:     map[string]exprSet{},
	}
	if root.Configuration.RootModule != nil {
		walkModule(root.Configuration.RootModule, "", &idx)
	}
	return idx, nil
}

func walkModule(mod map[string]any, prefix string, idx *configIndex) {
	for _, raw := range asList(mod["resources"]) {
		r, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		addr, _ := r["address"].(string)
		full := addr
		if prefix != "" {
			full = prefix + "." + addr
		}
		key, ok := resourceKey(full)
		if !ok {
			continue
		}
		idx.resources[key] = parseExprs(r["expressions"])
	}
	calls, _ := mod["module_calls"].(map[string]any)
	for name, raw := range calls {
		call, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		full := "module." + name
		if prefix != "" {
			full = prefix + "." + full
		}
		idx.calls[full] = parseExprs(call["expressions"])
		if child, ok := call["module"].(map[string]any); ok {
			walkModule(child, full, idx)
		}
	}
}

func parseExprs(v any) exprSet {
	set := exprSet{refs: map[string][]string{}, constants: map[string]any{}}
	m, ok := v.(map[string]any)
	if !ok {
		return set
	}
	for attr, raw := range m {
		var refs []string
		collectRefs(raw, &refs)
		if len(refs) > 0 {
			set.refs[attr] = refs
		}
		if em, ok := raw.(map[string]any); ok {
			if cv, ok := em["constant_value"]; ok {
				set.constants[attr] = cv
			}
		}
	}
	return set
}

func collectRefs(v any, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for _, r := range asList(t["references"]) {
			if s, ok := r.(string); ok {
				*out = append(*out, s)
			}
		}
		for _, child := range t {
			collectRefs(child, out)
		}
	case []any:
		for _, child := range t {
			collectRefs(child, out)
		}
	}
}

func loadDataResources(plan []byte) ([]planResource, error) {
	var root struct {
		ResourceChanges []struct {
			Address string `json:"address"`
			Mode    string `json:"mode"`
			Type    string `json:"type"`
			Change  struct {
				After map[string]any `json:"after"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	dec := json.NewDecoder(bytes.NewReader(plan))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	var out []planResource
	for _, r := range root.ResourceChanges {
		if r.Mode != "data" || r.Change.After == nil {
			continue
		}
		out = append(out, planResource{address: r.Address, typ: r.Type, values: r.Change.After})
	}
	return out, nil
}

func resourceKey(address string) (string, bool) {
	normalized := strings.ReplaceAll(address, ".data.", ".")
	normalized = strings.TrimPrefix(normalized, "data.")
	mod, typ, name, ok := splitResourceAddress(normalized)
	if !ok {
		return "", false
	}
	return resourceAddress(mod, typ, name), true
}

func underType(resources []planResource, module, typ string) []planResource {
	var out []planResource
	for _, r := range resources {
		if r.typ != typ {
			continue
		}
		if module == "" || strings.HasPrefix(r.address, module+".") {
			out = append(out, r)
		}
	}
	return out
}

func oneSibling(bucket planResource, resources []planResource, typ string, idx configIndex) (planResource, bool) {
	mod, _, _, ok := splitResourceAddress(bucket.address)
	if !ok {
		return planResource{}, false
	}
	cands := underType(resources, mod, typ)
	if len(cands) == 1 {
		return cands[0], true
	}
	if len(cands) == 0 {
		return planResource{}, false
	}
	var hits []planResource
	for _, c := range cands {
		for _, refs := range [][]string{idx.attrRefs(c.address, "bucket"), idx.attrRefs(c.address, "bucket_id")} {
			for _, ref := range refs {
				if containsResource(ref, "aws_s3_bucket", localTypeName(bucket.address)) {
					hits = append(hits, c)
				}
			}
		}
	}
	hits = uniqueResources(hits)
	if len(hits) == 1 {
		return hits[0], true
	}
	return planResource{}, false
}

func localTypeName(address string) string {
	_, _, name, ok := splitResourceAddress(address)
	if !ok {
		return ""
	}
	return name
}

func versioningStatus(values map[string]any) string {
	for _, item := range asList(values["versioning_configuration"]) {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if s, ok := m["status"].(string); ok {
			return s
		}
	}
	return ""
}

func publicAccessBlocked(values map[string]any) (bool, bool) {
	flags := []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}
	all := true
	for _, f := range flags {
		v, ok := values[f].(bool)
		if !ok {
			return false, false
		}
		if !v {
			all = false
		}
	}
	return all, true
}

func ownership(values map[string]any) string {
	for _, item := range asList(values["rule"]) {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if s, ok := m["object_ownership"].(string); ok {
			return s
		}
	}
	return ""
}

func encrypted(values map[string]any) bool {
	for _, rule := range asList(values["rule"]) {
		m, ok := rule.(map[string]any)
		if !ok {
			continue
		}
		for _, d := range asList(m["apply_server_side_encryption_by_default"]) {
			dm, ok := d.(map[string]any)
			if ok && dm["sse_algorithm"] != nil && dm["sse_algorithm"] != "" {
				return true
			}
		}
	}
	return false
}

func bucketAudit(bucket planResource, resources []planResource, idx configIndex) bool {
	for _, r := range resources {
		if r.typ == "aws_s3_bucket_logging" {
			for _, ref := range idx.attrRefs(r.address, "bucket") {
				if containsResource(ref, "aws_s3_bucket", localTypeName(bucket.address)) {
					return true
				}
			}
		}
		if r.typ == "aws_cloudtrail" && trailSelectsS3(r.values) {
			return true
		}
	}
	return false
}

func trailSelectsS3(values map[string]any) bool {
	raw, err := json.Marshal(values)
	if err != nil {
		return false
	}
	text := string(raw)
	return strings.Contains(text, "AWS::S3::Object") || strings.Contains(text, "s3.amazonaws.com")
}

func secretRotated(secret planResource, resources []planResource, idx configIndex) bool {
	_, _, name, ok := splitResourceAddress(secret.address)
	if !ok {
		return false
	}
	for _, r := range resources {
		if r.typ != "aws_secretsmanager_secret_rotation" {
			continue
		}
		for _, ref := range idx.attrRefs(r.address, "secret_id") {
			if containsResource(ref, "aws_secretsmanager_secret", name) {
				return true
			}
		}
	}
	return false
}

func containersFromPlan(task planResource) ([]containerSpec, bool) {
	raw, ok := task.values["container_definitions"].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, false
	}
	var defs []struct {
		Image   string `json:"image"`
		Secrets []struct {
			ValueFrom string `json:"valueFrom"`
		} `json:"secrets"`
	}
	if json.Unmarshal([]byte(raw), &defs) != nil {
		return nil, false
	}
	out := make([]containerSpec, 0, len(defs))
	for _, d := range defs {
		spec := containerSpec{}
		if d.Image != "" {
			spec.image = d.Image
			spec.imageOK = true
		}
		for _, s := range d.Secrets {
			if s.ValueFrom != "" {
				spec.secrets = append(spec.secrets, s.ValueFrom)
			}
		}
		out = append(out, spec)
	}
	return out, true
}

func imagePinned(specs []containerSpec) (bool, bool) {
	if len(specs) == 0 {
		return false, false
	}
	pinned := true
	for _, s := range specs {
		if !s.imageOK {
			return false, false
		}
		if !strings.Contains(s.image, "@sha256:") {
			pinned = false
		}
	}
	return pinned, true
}

func serviceMax(service planResource, resources []planResource, idx configIndex) (int, bool, string) {
	_, _, _, ok := splitResourceAddress(service.address)
	if !ok {
		return 0, false, ""
	}
	for _, r := range resources {
		if r.typ != "aws_appautoscaling_target" {
			continue
		}
		seen := map[string]bool{}
		for _, ref := range idx.attrRefs(r.address, "resource_id") {
			for _, svc := range resources {
				if svc.typ != "aws_ecs_service" {
					continue
				}
				_, st, sn, ok := splitResourceAddress(svc.address)
				if ok && containsResource(ref, st, sn) {
					seen[svc.address] = true
				}
			}
		}
		if !seen[service.address] {
			continue
		}
		if len(seen) != 1 {
			return 0, false, "ambiguous autoscaling target for " + service.address
		}
		if n, ok := number(r.values["max_capacity"]); ok {
			return n, true, ""
		}
	}
	return 0, false, ""
}

func lbPublic(lb planResource, resources []planResource, idx configIndex) (bool, bool) {
	internal, ok := lb.values["internal"].(bool)
	if !ok {
		return false, false
	}
	if internal {
		return false, true
	}
	return len(lbWorldCIDRs(lb, resources, idx)) > 0, true
}

func lbWorldCIDRs(lb planResource, resources []planResource, idx configIndex) []string {
	sgs := lbSecurityGroups(lb, resources, idx)
	var cidrs []string
	for _, sg := range sgs {
		cidrs = append(cidrs, worldCIDRs(sg.values)...)
		for _, rule := range resources {
			if rule.typ != "aws_vpc_security_group_ingress_rule" {
				continue
			}
			if !ruleOnSG(rule, sg, idx) {
				continue
			}
			cidrs = append(cidrs, worldCIDRs(rule.values)...)
		}
	}
	return uniqueStrings(cidrs)
}

func lbSecurityGroups(lb planResource, resources []planResource, idx configIndex) []planResource {
	var out []planResource
	for _, ref := range idx.attrRefs(lb.address, "security_groups") {
		for _, sg := range resources {
			if sg.typ != "aws_security_group" {
				continue
			}
			_, _, name, ok := splitResourceAddress(sg.address)
			if ok && containsResource(ref, "aws_security_group", name) && sameModule(lb.address, sg.address) {
				out = append(out, sg)
			}
		}
	}
	return uniqueResources(out)
}

func sameModule(a, b string) bool {
	am, _, _, aok := splitResourceAddress(a)
	bm, _, _, bok := splitResourceAddress(b)
	return aok && bok && am == bm
}

func ruleOnSG(rule, sg planResource, idx configIndex) bool {
	_, _, name, ok := splitResourceAddress(sg.address)
	if !ok {
		return false
	}
	for _, ref := range idx.attrRefs(rule.address, "security_group_id") {
		if containsResource(ref, "aws_security_group", name) {
			return true
		}
	}
	return false
}

func worldCIDRs(values map[string]any) []string {
	var out []string
	if s, ok := values["cidr_ipv4"].(string); ok && worldCIDR(s) {
		out = append(out, s)
	}
	if s, ok := values["cidr_ipv6"].(string); ok && worldCIDR(s) {
		out = append(out, s)
	}
	for _, ing := range asList(values["ingress"]) {
		m, ok := ing.(map[string]any)
		if !ok {
			continue
		}
		for _, c := range stringList(m["cidr_blocks"]) {
			if worldCIDR(c) {
				out = append(out, c)
			}
		}
		for _, c := range stringList(m["ipv6_cidr_blocks"]) {
			if worldCIDR(c) {
				out = append(out, c)
			}
		}
	}
	return out
}

func worldCIDR(s string) bool {
	return s == "0.0.0.0/0" || s == "::/0"
}

func stringList(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	case string:
		out = append(out, t)
	}
	return out
}

func publicListener(lb planResource, resources []planResource, idx configIndex) (string, string, bool) {
	ports := map[int]bool{}
	for _, sg := range lbSecurityGroups(lb, resources, idx) {
		for _, rule := range resources {
			if rule.typ != "aws_vpc_security_group_ingress_rule" || !ruleOnSG(rule, sg, idx) {
				continue
			}
			if len(worldCIDRs(rule.values)) == 0 {
				continue
			}
			if n, ok := number(rule.values["from_port"]); ok {
				ports[n] = true
			}
		}
	}
	transport := "unknown"
	anonymous := false
	addr := ""
	found := false
	for _, ln := range listenersFor(lb, resources, idx) {
		port, ok := number(ln.values["port"])
		if ok && len(ports) > 0 && !ports[port] {
			continue
		}
		found = true
		addr = ln.address
		switch strings.ToUpper(stringAttr(ln.values["protocol"])) {
		case "HTTP":
			transport = "plaintext"
		case "HTTPS", "TLS":
			if transport != "plaintext" {
				transport = "tls"
			}
		}
		if listenerAnonymous(ln.values) {
			anonymous = true
		}
	}
	if !found {
		return "", "unknown", false
	}
	return addr, transport, anonymous
}

func listenersFor(lb planResource, resources []planResource, idx configIndex) []planResource {
	mod, _, name, ok := splitResourceAddress(lb.address)
	if !ok {
		return nil
	}
	var out []planResource
	for _, r := range resources {
		if r.typ != "aws_lb_listener" {
			continue
		}
		refs := idx.attrRefs(r.address, "load_balancer_arn")
		matched := false
		for _, ref := range refs {
			if containsResource(ref, "aws_lb", name) {
				matched = true
			}
		}
		rm, _, _, rok := splitResourceAddress(r.address)
		if !matched && rok && rm == mod && len(underType(resources, mod, "aws_lb")) == 1 {
			matched = true
		}
		if matched {
			out = append(out, r)
		}
	}
	return out
}

func listenerAnonymous(values map[string]any) bool {
	actions := asList(values["default_action"])
	if len(actions) == 0 {
		return false
	}
	for _, action := range actions {
		m, ok := action.(map[string]any)
		if !ok {
			return false
		}
		if len(asList(m["authenticate_cognito"])) > 0 || len(asList(m["authenticate_oidc"])) > 0 {
			return false
		}
		t, _ := m["type"].(string)
		switch t {
		case "forward", "redirect", "fixed-response", "":
		default:
			return false
		}
	}
	return true
}

func servicesFronted(lb planResource, resources []planResource, elements []*Element, idx configIndex, warnings *[]string) []*Element {
	mod, _, _, ok := splitResourceAddress(lb.address)
	if !ok {
		return nil
	}
	keys := targetGroupKeys(idx.callConstant(mod, "listeners"))
	if len(keys) == 0 {
		return nil
	}
	var hits []*Element
	for _, key := range keys {
		needle := "target_groups[\"" + key + "\"]"
		for module, set := range idx.calls {
			mentioned := false
			for _, refs := range set.refs {
				for _, ref := range refs {
					if strings.Contains(ref, mod+".") || strings.Contains(ref, mod+"[") || strings.HasPrefix(ref, mod) {
						if strings.Contains(ref, needle) {
							mentioned = true
						}
					}
				}
			}
			if !mentioned {
				continue
			}
			hits = append(hits, elementsUnder(elements, module, "container_service")...)
		}
	}
	hits = uniqueElements(hits)
	if len(hits) > 1 {
		*warnings = append(*warnings, "ambiguous service behind "+lb.address)
		return nil
	}
	return hits
}

func targetGroupKeys(constant any) []string {
	m, ok := constant.(map[string]any)
	if !ok {
		return nil
	}
	var keys []string
	for _, raw := range m {
		lm, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		fwd, ok := lm["forward"].(map[string]any)
		if !ok {
			continue
		}
		if k, ok := fwd["target_group_key"].(string); ok && k != "" {
			keys = append(keys, k)
		}
	}
	return uniqueStrings(keys)
}

func targetTransport(lb planResource, resources []planResource, idx configIndex) string {
	mod, _, _, ok := splitResourceAddress(lb.address)
	if !ok {
		return "unknown"
	}
	keys := targetGroupKeys(idx.callConstant(mod, "listeners"))
	transport := "unknown"
	for _, r := range underType(resources, mod, "aws_lb_target_group") {
		key := forEachKey(r.address)
		if len(keys) > 0 && !containsString(keys, key) {
			continue
		}
		switch strings.ToUpper(stringAttr(r.values["protocol"])) {
		case "HTTP":
			return "plaintext"
		case "HTTPS", "TLS":
			transport = "tls"
		}
	}
	return transport
}

func forEachKey(address string) string {
	i := strings.LastIndex(address, `["`)
	if i < 0 {
		return ""
	}
	rest := address[i+2:]
	j := strings.Index(rest, `"]`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func elementsUnder(elements []*Element, module, kind string) []*Element {
	prefix := module + "."
	var out []*Element
	for _, el := range elements {
		if el.Kind != kind || len(el.Evidence.Addresses) != 1 {
			continue
		}
		if strings.HasPrefix(el.Evidence.Addresses[0], prefix) {
			out = append(out, el)
		}
	}
	return out
}

func taskAddress(resources []planResource, module string) string {
	tasks := underType(resources, module, "aws_ecs_task_definition")
	if len(tasks) != 1 {
		return ""
	}
	return tasks[0].address
}

type iamStatement struct {
	actions    []string
	notActions []string
	resources  []any
	allow      bool
	condition  bool
	doc        string
}

func roleDocuments(module string, roleRefs []string, resources, data []planResource, idx configIndex) []planResource {
	roles := namedResources(roleRefs, "aws_iam_role")
	var docs []planResource
	for _, att := range resources {
		if att.typ != "aws_iam_role_policy_attachment" || !strings.HasPrefix(att.address, module+".") {
			continue
		}
		if !overlaps(namedResources(idx.attrRefs(att.address, "role"), "aws_iam_role"), roles) {
			continue
		}
		for _, polName := range namedResources(idx.attrRefs(att.address, "policy_arn"), "aws_iam_policy") {
			for _, pol := range resources {
				if pol.typ != "aws_iam_policy" || !strings.HasPrefix(pol.address, module+".") {
					continue
				}
				if localTypeName(pol.address) != polName {
					continue
				}
				for _, docName := range namedResources(idx.attrRefs(pol.address, "policy"), "aws_iam_policy_document") {
					for _, d := range data {
						if d.typ != "aws_iam_policy_document" || !strings.HasPrefix(d.address, module+".") {
							continue
						}
						if dataName(d.address) == docName {
							docs = append(docs, d)
						}
					}
				}
			}
		}
	}
	return uniqueResources(docs)
}

func dataName(address string) string {
	normalized := strings.ReplaceAll(address, ".data.", ".")
	normalized = strings.TrimPrefix(normalized, "data.")
	_, _, name, ok := splitResourceAddress(normalized)
	if !ok {
		return ""
	}
	return name
}

func namedResources(refs []string, typ string) []string {
	needle := typ + "."
	var names []string
	for _, ref := range refs {
		i := strings.Index(ref, needle)
		if i < 0 {
			continue
		}
		rest := ref[i+len(needle):]
		if j := strings.IndexAny(rest, ".["); j >= 0 {
			rest = rest[:j]
		}
		if rest != "" {
			names = append(names, rest)
		}
	}
	return uniqueStrings(names)
}

func docStatements(doc planResource) []iamStatement {
	var out []iamStatement
	for _, raw := range asList(doc.values["statement"]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		effect, _ := m["effect"].(string)
		if strings.EqualFold(effect, "Deny") {
			continue
		}
		out = append(out, iamStatement{
			actions:    stringList(m["actions"]),
			notActions: stringList(m["not_actions"]),
			resources:  asList(m["resources"]),
			allow:      true,
			condition:  conditionPresent(m["condition"]),
			doc:        doc.address,
		})
	}
	return out
}

func conditionPresent(v any) bool {
	switch t := v.(type) {
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return false
	}
}

func grantsAction(st iamStatement, match func(string) bool) bool {
	for _, a := range st.actions {
		if match(a) {
			return true
		}
	}
	return false
}

func secretAction(a string) bool {
	return a == "*" || a == "secretsmanager:*" || a == "secretsmanager:GetSecretValue"
}

func s3Action(a string) bool {
	return a == "*" || a == "s3:*" || strings.HasPrefix(a, "s3:")
}

func wildcardResources(resources []any) bool {
	for _, r := range resources {
		s, ok := r.(string)
		if ok && strings.Contains(s, "*") {
			return true
		}
	}
	return false
}

func nullResources(resources []any) bool {
	if len(resources) == 0 {
		return false
	}
	for _, r := range resources {
		if r != nil {
			return false
		}
	}
	return true
}

func awsSecretScope(sec *Element, docs []planResource, callRefs []string, resources []planResource, elements []*Element) (scope string, grants []string, cause string) {
	account := false
	covers := false
	accountCause, coverCause := "", ""
	resolved, ambiguous := elementsFromRefs(callRefs, resources, elements, "aws_secretsmanager_secret")
	if ambiguous {
		return "", nil, ""
	}
	for _, doc := range docs {
		for _, st := range docStatements(doc) {
			if !grantsAction(st, secretAction) {
				continue
			}
			if wildcardResources(st.resources) {
				account = true
				accountCause = st.doc
				continue
			}
			if nullResources(st.resources) {
				for _, hit := range resolved {
					if hit.canonicalKey() == sec.canonicalKey() {
						covers = true
						coverCause = st.doc
					}
				}
			}
		}
	}
	var scopes []string
	if covers {
		scopes = append(scopes, "resource")
		cause = coverCause
	}
	if account {
		scopes = append(scopes, "account")
		cause = accountCause // broadest wins for cause
	}
	grants = normalizeAuthzGrants(scopes...)
	return effectiveAuthzScope(grants), grants, cause
}

func bucketsFromDocs(docs []planResource, callRefs []string, resources []planResource, elements []*Element) (hits []*Element, grants, actions []string, cause string, ambiguous bool, actionWarn string) {
	resolved, amb := elementsFromRefs(callRefs, resources, elements, "aws_s3_bucket")
	if amb {
		return nil, nil, nil, "", true, ""
	}
	account := false
	covers := false
	accountCause, coverCause := "", ""
	var actionSet []string
	actionsUnknown := false
	for _, doc := range docs {
		for _, st := range docStatements(doc) {
			if !grantsAction(st, s3Action) && len(st.notActions) == 0 {
				continue
			}
			classified, unknown, warn := classifyS3WriteActions(st)
			if unknown {
				actionsUnknown = true
				if actionWarn == "" {
					actionWarn = warn
				}
			} else {
				actionSet = mergeAuthzActions(actionSet, classified)
			}
			if !grantsAction(st, s3Action) {
				continue
			}
			if wildcardResources(st.resources) {
				account = true
				accountCause = st.doc
				continue
			}
			if nullResources(st.resources) && len(resolved) > 0 {
				covers = true
				coverCause = st.doc
			}
		}
	}
	var scopes []string
	if covers {
		scopes = append(scopes, "resource")
		cause = coverCause
	}
	if account {
		scopes = append(scopes, "account")
		cause = accountCause
	}
	grants = normalizeAuthzGrants(scopes...)
	if len(grants) == 0 {
		return nil, nil, nil, "", false, ""
	}
	if actionsUnknown {
		actionSet = nil
	}
	if len(resolved) != 1 {
		return nil, grants, actionSet, cause, len(resolved) > 1, actionWarn
	}
	return resolved, grants, actionSet, cause, false, actionWarn
}

// classifyS3WriteActions maps IAM actions to the closed authz_actions enum.
// Matching is case-insensitive. Glob wildcards * and ? may appear anywhere
// in the action name (e.g. s3:*Object, s3:Get?bject). Returns unknown=true
// (omit authz_actions) for NotAction, Condition, or bucket-policy-sourced
// grants — the closed enum cannot be derived safely.
func classifyS3WriteActions(st iamStatement) (actions []string, unknown bool, warn string) {
	if len(st.notActions) > 0 {
		return nil, true, "authz_actions unknown: NotAction on " + st.doc
	}
	if st.condition {
		return nil, true, "authz_actions unknown: Condition on " + st.doc
	}
	if isBucketPolicyDoc(st.doc) {
		return nil, true, "authz_actions unknown: bucket-policy-sourced grant on " + st.doc
	}
	var out []string
	add := func(name string) {
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	for _, a := range st.actions {
		for _, name := range matchTrackedS3Actions(a) {
			add(name)
		}
	}
	slices.Sort(out)
	return out, false, ""
}

// trackedS3WriteActions is the closed authz_actions enum (alphabetical).
var trackedS3WriteActions = []string{
	"BypassGovernanceRetention",
	"DeleteObject",
	"DeleteObjectVersion",
	"PutBucketPolicy",
	"PutBucketVersioning",
	"PutLifecycleConfiguration",
	"PutObject",
	"PutObjectLockConfiguration",
	"PutObjectRetention",
}

// iamActionAliases maps alternate IAM spellings onto tracked enum members.
var iamActionAliases = map[string]string{
	"putbucketlifecycleconfiguration": "PutLifecycleConfiguration",
}

func matchTrackedS3Actions(raw string) []string {
	pat := strings.ToLower(strings.TrimSpace(raw))
	if pat == "" {
		return nil
	}
	if pat == "*" || pat == "s3:*" {
		return slices.Clone(trackedS3WriteActions)
	}
	var out []string
	for _, name := range trackedS3WriteActions {
		cand := []string{strings.ToLower(name), "s3:" + strings.ToLower(name)}
		for _, c := range cand {
			if iamGlobMatch(pat, c) {
				out = append(out, name)
				break
			}
		}
	}
	for alias, mapped := range iamActionAliases {
		for _, c := range []string{alias, "s3:" + alias} {
			if iamGlobMatch(pat, c) && !slices.Contains(out, mapped) {
				out = append(out, mapped)
			}
		}
	}
	slices.Sort(out)
	return out
}

// iamGlobMatch matches a lowercased IAM action pattern against a candidate.
// * matches any run of characters; ? matches exactly one.
func iamGlobMatch(pattern, candidate string) bool {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		case '.', '+', '(', ')', '|', '[', ']', '{', '}', '^', '$', '\\':
			b.WriteByte('\\')
			b.WriteByte(pattern[i])
		default:
			b.WriteByte(pattern[i])
		}
	}
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(candidate)
}

func isBucketPolicyDoc(addr string) bool {
	return strings.Contains(addr, "aws_s3_bucket_policy.")
}

func mergeAuthzActions(a, b []string) []string {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	slices.Sort(out)
	return out
}

func elementsFromRefs(refs []string, resources []planResource, elements []*Element, typ string) ([]*Element, bool) {
	seen := map[string]*Element{}
	ambiguous := false
	for _, ref := range refs {
		mod := calledModule(ref)
		if mod == "" {
			continue
		}
		var found []planResource
		for _, r := range resources {
			if r.typ == typ && strings.HasPrefix(r.address, mod+".") {
				found = append(found, r)
			}
		}
		if len(found) > 1 {
			ambiguous = true
			continue
		}
		if len(found) == 1 {
			for _, el := range elements {
				if len(el.Evidence.Addresses) == 1 && el.Evidence.Addresses[0] == found[0].address {
					seen[el.canonicalKey()] = el
				}
			}
		}
	}
	var out []*Element
	for _, el := range seen {
		out = append(out, el)
	}
	return out, ambiguous
}

func calledModule(ref string) string {
	if !strings.HasPrefix(ref, "module.") {
		return ""
	}
	rest := strings.TrimPrefix(ref, "module.")
	i := strings.IndexAny(rest, ".[")
	if i < 0 {
		return "module." + rest
	}
	return "module." + rest[:i]
}

func ingressRefsSG(sg planResource, idx configIndex) bool {
	for _, ref := range idx.attrRefs(sg.address, "ingress") {
		if strings.Contains(ref, "aws_security_group.") {
			return true
		}
	}
	return false
}

func elementsUsingSG(sgAddress, kind string, elements []*Element, idx configIndex) []*Element {
	_, _, name, ok := splitResourceAddress(sgAddress)
	if !ok {
		return nil
	}
	var out []*Element
	for module, set := range idx.calls {
		mentioned := false
		for _, refs := range set.refs {
			for _, ref := range refs {
				if containsResource(ref, "aws_security_group", name) {
					mentioned = true
				}
			}
		}
		if mentioned {
			out = append(out, elementsUnder(elements, module, kind)...)
		}
	}
	return uniqueElements(out)
}

func sourceServices(sg planResource, resources []planResource, elements []*Element, idx configIndex) []*Element {
	var out []*Element
	for _, ref := range idx.attrRefs(sg.address, "ingress") {
		for _, other := range resources {
			if other.typ != "aws_security_group" || other.address == sg.address {
				continue
			}
			_, _, name, ok := splitResourceAddress(other.address)
			if ok && containsResource(ref, "aws_security_group", name) {
				out = append(out, elementsUsingSG(other.address, "container_service", elements, idx)...)
			}
		}
	}
	return uniqueElements(out)
}

func containsResource(ref, typ, name string) bool {
	if name == "" {
		return false
	}
	needle := typ + "." + name
	rest := ref
	for {
		i := strings.Index(rest, needle)
		if i < 0 {
			return false
		}
		end := i + len(needle)
		if end == len(rest) || rest[end] == '.' || rest[end] == '[' {
			return true
		}
		rest = rest[i+1:]
	}
}

func dedupeFlows(flows []*Flow) []*Flow {
	seen := map[string]bool{}
	var out []*Flow
	for _, f := range flows {
		k := f.From + "\n" + f.To + "\n" + f.DataClass
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func uniqueResources(in []planResource) []planResource {
	seen := map[string]bool{}
	var out []planResource
	for _, r := range in {
		if seen[r.address] {
			continue
		}
		seen[r.address] = true
		out = append(out, r)
	}
	return out
}

func uniqueElements(in []*Element) []*Element {
	seen := map[string]bool{}
	var out []*Element
	for _, el := range in {
		k := el.canonicalKey()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, el)
	}
	return out
}

func overlaps(a, b []string) bool {
	for _, x := range a {
		if containsString(b, x) {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	return slices.Contains(list, s)
}

func stringAttr(v any) string {
	s, _ := v.(string)
	return s
}
