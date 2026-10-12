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
	// raw keeps the original expression tree per attribute so nested block
	// lists (e.g. ingress[i].security_groups) can be attributed per index.
	raw map[string]any
}

type configIndex struct {
	resources map[string]exprSet
	calls     map[string]exprSet
	outputs   map[string]exprSet // module call address → output name → refs
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
		outputs:   map[string]exprSet{},
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
			indexModuleOutputs(child, full, idx)
			walkModule(child, full, idx)
		}
	}
}

func parseExprs(v any) exprSet {
	set := exprSet{
		refs:      map[string][]string{},
		constants: map[string]any{},
		raw:       map[string]any{},
	}
	m, ok := v.(map[string]any)
	if !ok {
		return set
	}
	for attr, raw := range m {
		set.raw[attr] = raw
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

// bucketAudit reports whether S3 object reads are audit-logged for bucket.
//
// Outcomes (caller combines with owned_by_this_root):
//   - aws_s3_bucket_logging references this bucket → true, known
//   - aws_cloudtrail (enable_logging not false) selects this bucket for
//     S3 object data events that include reads → true, known
//   - Only WriteOnly / readOnly=false selectors cover the bucket → known=false
//     (reads may not be logged; omit regardless of ownership)
//   - No covering logging or trail → false, known (caller emits false only
//     when owned_by_this_root; otherwise omits → FR-023 unverified)
func bucketAudit(bucket planResource, resources []planResource, idx configIndex) (audit bool, known bool) {
	if bucketLogged(bucket, resources, idx) {
		return true, true
	}
	sawWriteOnly := false
	for _, r := range resources {
		if r.typ != "aws_cloudtrail" {
			continue
		}
		if v, ok := r.values["enable_logging"].(bool); ok && !v {
			continue
		}
		reads, writeOnly := trailCoversBucketDataEvents(r, bucket, idx)
		if reads {
			return true, true
		}
		if writeOnly {
			sawWriteOnly = true
		}
	}
	if sawWriteOnly {
		return false, false
	}
	return false, true
}

func bucketLogged(bucket planResource, resources []planResource, idx configIndex) bool {
	name := localTypeName(bucket.address)
	for _, r := range resources {
		if r.typ != "aws_s3_bucket_logging" {
			continue
		}
		for _, ref := range idx.attrRefs(r.address, "bucket") {
			if containsResource(ref, "aws_s3_bucket", name) {
				return true
			}
		}
	}
	return false
}

// trailCoversBucketDataEvents reports whether a trail's event selectors cover
// S3 object data events for bucket. reads=true means read (or All) coverage;
// writeOnly=true means only WriteOnly / readOnly=false coverage was found.
func trailCoversBucketDataEvents(trail, bucket planResource, idx configIndex) (reads, writeOnly bool) {
	for _, raw := range asList(trail.values["event_selector"]) {
		sel, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if !eventSelectorCoversBucket(sel, trail, bucket, idx) {
			continue
		}
		switch strings.ToLower(stringAttr(sel["read_write_type"])) {
		case "writeonly":
			writeOnly = true
		default:
			// All, ReadOnly, or unset (AWS default All).
			reads = true
		}
	}
	for _, raw := range asList(trail.values["advanced_event_selector"]) {
		sel, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		covers, includeReads := advancedSelectorCoversBucket(sel, trail, bucket, idx)
		if !covers {
			continue
		}
		if includeReads {
			reads = true
		} else {
			writeOnly = true
		}
	}
	return reads, writeOnly
}

func eventSelectorCoversBucket(sel map[string]any, trail, bucket planResource, idx configIndex) bool {
	var values []string
	hasS3Object := false
	for _, dr := range asList(sel["data_resource"]) {
		m, ok := dr.(map[string]any)
		if !ok {
			continue
		}
		if stringAttr(m["type"]) != "AWS::S3::Object" {
			continue
		}
		hasS3Object = true
		values = append(values, stringList(m["values"])...)
	}
	if !hasS3Object {
		return false
	}
	if s3ObjectARNCoversBucket(values, bucket) {
		return true
	}
	// Computed ARNs: configuration references on event_selector name this bucket.
	return trailSelectorRefsBucket(trail, bucket, "event_selector", idx) && len(values) == 0
}

func advancedSelectorCoversBucket(sel map[string]any, trail, bucket planResource, idx configIndex) (covers, includeReads bool) {
	var (
		isData, isS3Object bool
		arnEquals          []string
		arnStarts          []string
		arnNotStarts       []string
		arnNotEquals       []string
		readOnlyEquals     []string
		hasARNFilter       bool
	)
	for _, raw := range asList(sel["field_selector"]) {
		fs, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		switch stringAttr(fs["field"]) {
		case "eventCategory":
			for _, v := range stringList(fs["equals"]) {
				if v == "Data" {
					isData = true
				}
			}
		case "resources.type":
			for _, v := range stringList(fs["equals"]) {
				if v == "AWS::S3::Object" {
					isS3Object = true
				}
			}
		case "resources.ARN":
			hasARNFilter = true
			arnEquals = append(arnEquals, stringList(fs["equals"])...)
			arnStarts = append(arnStarts, stringList(fs["starts_with"])...)
			arnNotStarts = append(arnNotStarts, stringList(fs["not_starts_with"])...)
			arnNotEquals = append(arnNotEquals, stringList(fs["not_equals"])...)
		case "readOnly":
			readOnlyEquals = append(readOnlyEquals, stringList(fs["equals"])...)
		}
	}
	if !isData || !isS3Object {
		return false, false
	}
	if hasARNFilter {
		included := advancedARNIncludesBucket(arnEquals, arnStarts, arnNotStarts, arnNotEquals, bucket)
		if !included && !trailSelectorRefsBucket(trail, bucket, "advanced_event_selector", idx) {
			return false, false
		}
		if !included {
			// Refs name this bucket but concrete ARN values did not match.
			included = true
		}
	}
	// No resources.ARN filter ⇒ all S3 objects in the account.
	return true, advancedIncludesReads(readOnlyEquals)
}

func advancedARNIncludesBucket(equals, starts, notStarts, notEquals []string, bucket planResource) bool {
	name := s3BucketName(bucket)
	if name == "" {
		return false
	}
	prefix := "arn:aws:s3:::" + name + "/"
	arn := "arn:aws:s3:::" + name
	included := false
	if len(equals) == 0 && len(starts) == 0 {
		// Exclusion-only filter: start included, then apply not_*.
		included = true
	}
	for _, v := range equals {
		if v == prefix || v == arn || s3ObjectARNCoversBucket([]string{v}, bucket) {
			included = true
		}
	}
	for _, v := range starts {
		if v == prefix || v == arn || v == arn+"/" || strings.HasPrefix(prefix, v) || s3ObjectARNCoversBucket([]string{v}, bucket) {
			included = true
		}
	}
	for _, v := range notStarts {
		if v == prefix || v == arn || v == arn+"/" || strings.HasPrefix(prefix, v) {
			included = false
		}
	}
	for _, v := range notEquals {
		if v == prefix || v == arn {
			included = false
		}
	}
	return included
}

func advancedIncludesReads(readOnlyEquals []string) bool {
	if len(readOnlyEquals) == 0 {
		return true
	}
	for _, v := range readOnlyEquals {
		if strings.EqualFold(v, "true") {
			return true
		}
	}
	// Only false → write events only.
	return false
}

func s3ObjectARNCoversBucket(values []string, bucket planResource) bool {
	name := s3BucketName(bucket)
	prefix := "arn:aws:s3:::" + name + "/"
	arn := "arn:aws:s3:::" + name
	for _, v := range values {
		switch {
		case v == "arn:aws:s3" || v == "arn:aws:s3:::":
			return true
		case name != "" && (v == prefix || v == arn || v == arn+"/" || strings.HasPrefix(v, prefix)):
			return true
		case name != "" && strings.HasPrefix(prefix, v) && strings.HasPrefix(v, "arn:aws:s3:::"):
			// starts_with value that is a prefix of our bucket ARN prefix.
			return true
		}
	}
	return false
}

func s3BucketName(bucket planResource) string {
	if s, ok := bucket.values["bucket"].(string); ok && s != "" {
		return s
	}
	if s, ok := bucket.values["bucket_prefix"].(string); ok && s != "" {
		return s
	}
	return ""
}

func trailSelectorRefsBucket(trail, bucket planResource, attr string, idx configIndex) bool {
	name := localTypeName(bucket.address)
	for _, ref := range idx.attrRefs(trail.address, attr) {
		if containsResource(ref, "aws_s3_bucket", name) {
			return true
		}
	}
	return false
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

// publicListener picks transport and edge authz_scope from this LB's listeners
// and their aws_lb_listener_rule resources. Caller already decided the LB is
// internet-exposed (attributes.public=true).
//
// scope is "public" when any default action or rule forwards to the app without
// an authenticate-cognito/authenticate-oidc step first (causeAddr is that
// listener or rule address); "authenticated" when every app path is gated
// (default action and every forwarding rule); "" when a path is undeterminable
// (unknown listener_arn attachment or dynamic/unknown actions).
//
// Redirect-only and fixed-response actions do not make the entry anonymous for
// the app: they are ignored for authz_scope (neither public nor required to be
// authenticated).
func publicListener(lb planResource, resources []planResource, idx configIndex) (causeAddr, transport, scope string) {
	transport = "unknown"
	listeners := listenersFor(lb, resources, idx)
	if len(listeners) == 0 {
		return "", "unknown", ""
	}

	hasPublic, hasAuth, hasUnknown := false, false, false
	for _, ln := range listeners {
		switch strings.ToUpper(stringAttr(ln.values["protocol"])) {
		case "HTTP":
			transport = "plaintext"
		case "HTTPS", "TLS":
			if transport != "plaintext" {
				transport = "tls"
			}
		}

		switch classifyListenerActions(asList(ln.values["default_action"])) {
		case pathPublic:
			hasPublic = true
			if causeAddr == "" {
				causeAddr = ln.address
			}
		case pathAuthenticated:
			hasAuth = true
		case pathUnknown:
			hasUnknown = true
		}

		rules, rulesOK := listenerRulesFor(ln, resources, idx)
		if !rulesOK {
			hasUnknown = true
			continue
		}
		for _, rule := range rules {
			switch classifyListenerActions(asList(rule.values["action"])) {
			case pathPublic:
				hasPublic = true
				if causeAddr == "" {
					causeAddr = rule.address
				}
			case pathAuthenticated:
				hasAuth = true
			case pathUnknown:
				hasUnknown = true
			}
		}
	}

	if hasPublic {
		return causeAddr, transport, "public"
	}
	if hasUnknown {
		return "", transport, ""
	}
	if hasAuth {
		return "", transport, "authenticated"
	}
	return "", transport, ""
}

// pathClass is how a listener default action or listener rule affects edge authz.
type pathClass int

const (
	pathNeutral pathClass = iota
	pathPublic
	pathAuthenticated
	pathUnknown
)

// classifyListenerActions classifies ordered ALB actions for edge authz_scope.
// Forward without a prior authenticate-* step is public. Authenticate (with or
// without a following forward) is authenticated. Redirect and fixed-response
// alone are neutral. Unknown or dynamic action types are pathUnknown.
func classifyListenerActions(actions []any) pathClass {
	if len(actions) == 0 {
		return pathUnknown
	}
	ordered := orderedListenerActions(actions)
	seenAuth := false
	sawForward := false
	publicForward := false
	sawAuthAction := false
	for _, action := range ordered {
		m, ok := action.(map[string]any)
		if !ok {
			return pathUnknown
		}
		t := strings.ToLower(stringAttr(m["type"]))
		isAuth := t == "authenticate-cognito" || t == "authenticate-oidc" ||
			len(asList(m["authenticate_cognito"])) > 0 || len(asList(m["authenticate_oidc"])) > 0
		isForward := t == "forward" || stringAttr(m["target_group_arn"]) != "" ||
			len(asList(m["forward"])) > 0
		isRedirect := t == "redirect" || len(asList(m["redirect"])) > 0
		isFixed := t == "fixed-response" || len(asList(m["fixed_response"])) > 0
		switch {
		case isAuth:
			seenAuth = true
			sawAuthAction = true
		case isForward:
			sawForward = true
			if !seenAuth {
				publicForward = true
			}
		case isRedirect, isFixed:
			// Not app exposure for FR-001: ignore.
		default:
			return pathUnknown
		}
	}
	if publicForward {
		return pathPublic
	}
	if sawForward || sawAuthAction {
		return pathAuthenticated
	}
	return pathNeutral
}

func orderedListenerActions(actions []any) []any {
	type item struct {
		order int
		idx   int
		v     any
	}
	items := make([]item, 0, len(actions))
	for i, a := range actions {
		order := i + 1
		if m, ok := a.(map[string]any); ok {
			if n, ok := number(m["order"]); ok {
				order = n
			}
		}
		items = append(items, item{order: order, idx: i, v: a})
	}
	slices.SortFunc(items, func(a, b item) int {
		if a.order != b.order {
			return a.order - b.order
		}
		return a.idx - b.idx
	})
	out := make([]any, len(items))
	for i, it := range items {
		out[i] = it.v
	}
	return out
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

// listenerRulesFor returns aws_lb_listener_rule resources attached to ln.
// ok is false when a same-module rule has a listener_arn that cannot be
// resolved to any listener (attachment unknown → omit authz).
func listenerRulesFor(ln planResource, resources []planResource, idx configIndex) (rules []planResource, ok bool) {
	mod, _, lnName, lok := splitResourceAddress(ln.address)
	if !lok {
		return nil, false
	}
	ok = true
	for _, r := range resources {
		if r.typ != "aws_lb_listener_rule" {
			continue
		}
		rm, _, _, rok := splitResourceAddress(r.address)
		refs := idx.attrRefs(r.address, "listener_arn")
		if len(refs) == 0 {
			if rok && rm == mod {
				ok = false
			}
			continue
		}
		matched := false
		matchedAnyListener := false
		for _, ref := range refs {
			if containsResource(ref, "aws_lb_listener", lnName) {
				matched = true
			}
			if strings.Contains(ref, "aws_lb_listener.") {
				matchedAnyListener = true
			}
		}
		if matched {
			rules = append(rules, r)
			continue
		}
		if rok && rm == mod && !matchedAnyListener {
			ok = false
		}
	}
	return rules, ok
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
