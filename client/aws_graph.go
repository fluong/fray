package client

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
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

func (idx configIndex) attrConstant(address, attr string) any {
	key, ok := resourceKey(address)
	if !ok {
		return nil
	}
	return idx.resources[key].constants[attr]
}

// sameModule reports whether address lives in module.
// Root (module == "") matches only root-module addresses. Named modules use
// prefix match so nested addresses under module.x.module.y.… are included,
// matching the pre-Bedrock HasPrefix(addr, module+".") semantics after
// data-source normalisation (module.x.data.T.n → module.x.T.n).
func sameModule(address, module string) bool {
	normalized := strings.ReplaceAll(address, ".data.", ".")
	normalized = strings.TrimPrefix(normalized, "data.")
	if module == "" {
		m, _, _, ok := splitResourceAddress(normalized)
		return ok && m == ""
	}
	return strings.HasPrefix(normalized, module+".")
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

// loadDataResources collects data sources from a terraform show -json plan.
//
// Plan JSON (format_version 1.x) stores data.* values in two places:
//   - resource_changes with mode=data — reads that still run during apply, or
//     whose results depend on unknown managed values
//   - prior_state.values.root_module(.child_modules)* — data sources Terraform
//     already resolved during planning (every argument known; common for
//     aws_iam_policy_document with only literals)
//
// See https://developer.hashicorp.com/terraform/internals/json-format
// (resource_changes, prior_state). resource_changes wins on address collision.
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
		PriorState *struct {
			Values *struct {
				RootModule *stateModule `json:"root_module"`
			} `json:"values"`
		} `json:"prior_state"`
	}
	dec := json.NewDecoder(bytes.NewReader(plan))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	byAddr := map[string]planResource{}
	var order []string
	add := func(addr, typ string, values map[string]any) {
		if addr == "" || typ == "" || values == nil {
			return
		}
		if _, exists := byAddr[addr]; exists {
			return
		}
		byAddr[addr] = planResource{address: addr, typ: typ, values: values}
		order = append(order, addr)
	}
	for _, r := range root.ResourceChanges {
		if r.Mode != "data" || r.Change.After == nil {
			continue
		}
		add(r.Address, r.Type, r.Change.After)
	}
	if root.PriorState != nil && root.PriorState.Values != nil && root.PriorState.Values.RootModule != nil {
		collectPriorStateData(root.PriorState.Values.RootModule, add)
	}
	out := make([]planResource, 0, len(order))
	for _, addr := range order {
		out = append(out, byAddr[addr])
	}
	return out, nil
}

// stateModule is prior_state.values.root_module / child_modules shape.
type stateModule struct {
	Resources    []stateResource `json:"resources"`
	ChildModules []stateModule   `json:"child_modules"`
}

type stateResource struct {
	Address string         `json:"address"`
	Mode    string         `json:"mode"`
	Type    string         `json:"type"`
	Values  map[string]any `json:"values"`
}

func collectPriorStateData(mod *stateModule, add func(addr, typ string, values map[string]any)) {
	if mod == nil {
		return
	}
	for _, r := range mod.Resources {
		if r.Mode != "data" || r.Values == nil {
			continue
		}
		add(r.Address, r.Type, r.Values)
	}
	for i := range mod.ChildModules {
		collectPriorStateData(&mod.ChildModules[i], add)
	}
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
// listener or rule address); "authenticated" when every attributed app path is
// gated; "" when a path is undeterminable (dynamic/unknown actions) or when
// authenticated would apply but any plan-wide listener rule cannot be attributed
// to a specific listener (we cannot rule out an unauthenticated rule here).
// A visible anonymous path still yields public even if other rules are
// unattributable.
//
// Redirect-only and fixed-response actions do not make the entry anonymous for
// the app: they are ignored for authz_scope (neither public nor required to be
// authenticated). Cross-module listener_arn via module outputs is resolved with
// resolveModuleOutputResource.
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

		for _, rule := range listenerRulesFor(ln, resources, idx) {
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
		if hasUnattributedListenerRule(resources, idx) {
			return "", transport, ""
		}
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

// listenerRulesFor returns aws_lb_listener_rule resources whose listener_arn
// resolves to ln (including via module outputs).
func listenerRulesFor(ln planResource, resources []planResource, idx configIndex) []planResource {
	var rules []planResource
	for _, r := range resources {
		if r.typ != "aws_lb_listener_rule" {
			continue
		}
		target, ok := resolveListenerRuleTarget(r, resources, idx)
		if ok && target.address == ln.address {
			rules = append(rules, r)
		}
	}
	return rules
}

// hasUnattributedListenerRule is true when any aws_lb_listener_rule in the plan
// cannot be resolved to exactly one aws_lb_listener. Used to withhold
// authenticated (not public) when an anonymous rule on this listener cannot be
// ruled out.
func hasUnattributedListenerRule(resources []planResource, idx configIndex) bool {
	for _, r := range resources {
		if r.typ != "aws_lb_listener_rule" {
			continue
		}
		if _, ok := resolveListenerRuleTarget(r, resources, idx); !ok {
			return true
		}
	}
	return false
}

// resolveListenerRuleTarget follows listener_arn references (direct resource or
// module output) to exactly one aws_lb_listener in the plan.
func resolveListenerRuleTarget(rule planResource, resources []planResource, idx configIndex) (planResource, bool) {
	refs := idx.attrRefs(rule.address, "listener_arn")
	ruleMod, _, _, _ := splitResourceAddress(rule.address)
	var hits []planResource
	seen := map[string]bool{}
	meaningful := false
	for _, ref := range refs {
		if isBareModuleRef(ref) {
			continue
		}
		meaningful = true
		if isModuleOutputRef(ref) {
			ln, ok := resolveModuleOutputResource(ref, "aws_lb_listener", idx, resources, 0)
			if !ok {
				return planResource{}, false
			}
			if !seen[ln.address] {
				seen[ln.address] = true
				hits = append(hits, ln)
			}
			continue
		}
		if strings.Contains(ref, "aws_lb_listener.") {
			found := false
			for _, r := range resources {
				if r.typ != "aws_lb_listener" || !listenerRefPointsTo(ref, r, ruleMod) {
					continue
				}
				found = true
				if !seen[r.address] {
					seen[r.address] = true
					hits = append(hits, r)
				}
			}
			if !found {
				return planResource{}, false
			}
			continue
		}
		return planResource{}, false
	}
	if !meaningful || len(hits) != 1 {
		return planResource{}, false
	}
	return hits[0], true
}

func listenerRefPointsTo(ref string, ln planResource, ruleMod string) bool {
	_, _, name, ok := splitResourceAddress(ln.address)
	if !ok || !containsResource(ref, "aws_lb_listener", name) {
		return false
	}
	lnMod, _, _, _ := splitResourceAddress(ln.address)
	if strings.HasPrefix(ref, "module.") {
		return lnMod != "" && strings.HasPrefix(ref, lnMod+".")
	}
	return lnMod == ruleMod
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
	actions      []string
	notActions   []string
	resources    []any
	notResources []any
	allow        bool
	condition    bool
	doc          string
}

// roleDocuments returns identity-policy documents for the given roles and
// whether any identity-policy source on those roles is unknown at plan time.
//
// Sources (union): aws_iam_role_policy_attachment → aws_iam_policy,
// aws_iam_role_policy, aws_iam_role.inline_policy (only when config declares
// blocks), and aws_iam_role.managed_policy_arns in-plan aws_iam_policy refs.
// aws_iam_policy_attachment and *_exclusive resources are out of scope.
//
// For each source: data.aws_iam_policy_document refs win; else a known policy
// JSON string is parsed into a synthetic doc; else the source is unknown.
// Bare after_unknown.inline_policy / managed_policy_arns with no config entries
// are ignored (provider-computed noise on empty roles).
func roleDocuments(module string, roleRefs []string, resources, data []planResource, idx configIndex) (docs []planResource, unknown bool) {
	roles := namedResources(roleRefs, "aws_iam_role")
	if len(roles) == 0 {
		return nil, false
	}
	var out []planResource
	for _, att := range resources {
		if att.typ != "aws_iam_role_policy_attachment" || !sameModule(att.address, module) {
			continue
		}
		if !overlaps(namedResources(idx.attrRefs(att.address, "role"), "aws_iam_role"), roles) {
			continue
		}
		polNames := namedResources(idx.attrRefs(att.address, "policy_arn"), "aws_iam_policy")
		if len(polNames) == 0 {
			// AWS-managed ARN constants are ignored here (Bedrock FullAccess is
			// handled separately). An unknown policy_arn with no in-plan policy
			// ref and no constant is an unknown identity-policy source.
			if attrAfterUnknown(att, "policy_arn") && idx.attrConstant(att.address, "policy_arn") == nil {
				unknown = true
			}
			continue
		}
		for _, polName := range polNames {
			pol, ok := findModuleResource(resources, module, "aws_iam_policy", polName)
			if !ok {
				unknown = true
				continue
			}
			got, unk := resolvePolicyContent(pol, "policy", module, data, idx)
			out = append(out, got...)
			if unk {
				unknown = true
			}
		}
	}
	for _, rp := range resources {
		if rp.typ != "aws_iam_role_policy" || !sameModule(rp.address, module) {
			continue
		}
		if !overlaps(namedResources(idx.attrRefs(rp.address, "role"), "aws_iam_role"), roles) {
			continue
		}
		got, unk := resolvePolicyContent(rp, "policy", module, data, idx)
		out = append(out, got...)
		if unk {
			unknown = true
		}
	}
	for _, role := range resources {
		if role.typ != "aws_iam_role" || !sameModule(role.address, module) {
			continue
		}
		if !overlaps([]string{localTypeName(role.address)}, roles) {
			continue
		}
		got, unk := roleInlinePolicyDocs(role, module, data, idx)
		out = append(out, got...)
		if unk {
			unknown = true
		}
		got, unk = roleManagedPolicyDocs(role, module, resources, data, idx)
		out = append(out, got...)
		if unk {
			unknown = true
		}
	}
	return uniqueResources(out), unknown
}

// resolvePolicyContent reads holder.policyAttr: data.aws_iam_policy_document
// refs first, else a known JSON string, else unknown. Never reconstructs
// statements from jsonencode configuration references alone.
func resolvePolicyContent(holder planResource, policyAttr, module string, data []planResource, idx configIndex) (docs []planResource, unknown bool) {
	docNames := namedResources(idx.attrRefs(holder.address, policyAttr), "aws_iam_policy_document")
	if len(docNames) > 0 {
		var found []planResource
		for _, docName := range docNames {
			for _, d := range data {
				if d.typ != "aws_iam_policy_document" || !sameModule(d.address, module) {
					continue
				}
				if dataName(d.address) == docName {
					found = append(found, d)
				}
			}
		}
		if len(found) == 0 {
			return nil, true
		}
		return found, false
	}
	if s, ok := holder.values[policyAttr].(string); ok && strings.TrimSpace(s) != "" {
		syn, ok := syntheticDocFromPolicyJSON(holder.address, s)
		if !ok {
			return nil, true // malformed JSON
		}
		return []planResource{syn}, false
	}
	// Unknown at plan time (after_unknown, null, or jsonencode-with-refs only).
	return nil, true
}

func roleInlinePolicyDocs(role planResource, module string, data []planResource, idx configIndex) (docs []planResource, unknown bool) {
	if !hasConfigAttr(idx, role.address, "inline_policy") {
		// Bare after_unknown.inline_policy with no config blocks: ignore.
		return nil, false
	}
	// Data-doc refs anywhere under inline_policy expressions.
	for _, docName := range namedResources(idx.attrRefs(role.address, "inline_policy"), "aws_iam_policy_document") {
		matched := false
		for _, d := range data {
			if d.typ != "aws_iam_policy_document" || !sameModule(d.address, module) {
				continue
			}
			if dataName(d.address) == docName {
				docs = append(docs, d)
				matched = true
			}
		}
		if !matched {
			unknown = true
		}
	}
	vals := asList(role.values["inline_policy"])
	if len(vals) == 0 {
		// Config declares blocks but planned values are absent/unknown.
		if len(docs) == 0 {
			unknown = true
		}
		return docs, unknown
	}
	for i, raw := range vals {
		m, ok := raw.(map[string]any)
		if !ok {
			unknown = true
			continue
		}
		s, _ := m["policy"].(string)
		if strings.TrimSpace(s) == "" {
			// Block present without a known policy string; data-doc path may
			// already have covered it via attrRefs.
			if len(namedResources(idx.attrRefs(role.address, "inline_policy"), "aws_iam_policy_document")) == 0 {
				unknown = true
			}
			continue
		}
		cause := role.address
		if name, _ := m["name"].(string); name != "" {
			cause = role.address + "#inline_policy." + name
		} else {
			cause = role.address + "#inline_policy[" + strconv.Itoa(i) + "]"
		}
		syn, ok := syntheticDocFromPolicyJSON(cause, s)
		if !ok {
			unknown = true
			continue
		}
		docs = append(docs, syn)
	}
	return docs, unknown
}

func roleManagedPolicyDocs(role planResource, module string, resources, data []planResource, idx configIndex) (docs []planResource, unknown bool) {
	if !hasConfigAttr(idx, role.address, "managed_policy_arns") {
		// Bare after_unknown.managed_policy_arns with no config: ignore.
		return nil, false
	}
	polNames := namedResources(idx.attrRefs(role.address, "managed_policy_arns"), "aws_iam_policy")
	for _, polName := range polNames {
		pol, ok := findModuleResource(resources, module, "aws_iam_policy", polName)
		if !ok {
			unknown = true
			continue
		}
		got, unk := resolvePolicyContent(pol, "policy", module, data, idx)
		docs = append(docs, got...)
		if unk {
			unknown = true
		}
	}
	// AWS-managed ARN constants are not read as documents (AmazonBedrockFullAccess
	// is handled by roleAmazonBedrockFullAccess). If config has managed_policy_arns
	// but nothing resolved to an in-plan policy or a readable document, and the
	// attribute is after_unknown without only-constant AWS ARNs, mark unknown.
	if len(polNames) == 0 && len(docs) == 0 && attrAfterUnknown(role, "managed_policy_arns") {
		if !managedPolicyArnsOnlyConstants(idx, role.address) {
			unknown = true
		}
	}
	return docs, unknown
}

func hasConfigAttr(idx configIndex, address, attr string) bool {
	key, ok := resourceKey(address)
	if !ok {
		return false
	}
	set := idx.resources[key]
	if _, ok := set.raw[attr]; ok {
		return true
	}
	if len(set.refs[attr]) > 0 {
		return true
	}
	if _, ok := set.constants[attr]; ok {
		return true
	}
	return false
}

func managedPolicyArnsOnlyConstants(idx configIndex, address string) bool {
	key, ok := resourceKey(address)
	if !ok {
		return false
	}
	raw := idx.resources[key].raw["managed_policy_arns"]
	if raw == nil {
		return false
	}
	// True when every leaf is a constant_value string (no references).
	return exprOnlyConstants(raw) && len(idx.resources[key].refs["managed_policy_arns"]) == 0
}

func exprOnlyConstants(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t["constant_value"]; ok {
			return true
		}
		if _, ok := t["references"]; ok {
			return false
		}
		for _, child := range t {
			if !exprOnlyConstants(child) {
				return false
			}
		}
		return true
	case []any:
		if len(t) == 0 {
			return false
		}
		for _, child := range t {
			if !exprOnlyConstants(child) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func findModuleResource(resources []planResource, module, typ, name string) (planResource, bool) {
	for _, r := range resources {
		if r.typ != typ || !sameModule(r.address, module) {
			continue
		}
		if localTypeName(r.address) == name {
			return r, true
		}
	}
	return planResource{}, false
}

func attrAfterUnknown(r planResource, attr string) bool {
	if r.afterUnknown == nil {
		return false
	}
	v, ok := r.afterUnknown[attr]
	if !ok {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	default:
		return t != nil
	}
}

// syntheticDocFromPolicyJSON maps an IAM policy JSON string into the statement
// shape docStatements / docDenyStatements already read from data sources.
// Principal, Sid, and Version are ignored. Malformed JSON → ok=false.
func syntheticDocFromPolicyJSON(cause, raw string) (planResource, bool) {
	var top map[string]any
	if err := json.Unmarshal([]byte(raw), &top); err != nil {
		return planResource{}, false
	}
	var stmts []any
	for _, item := range policyStatementList(top["Statement"]) {
		st, ok := item.(map[string]any)
		if !ok {
			continue
		}
		stmts = append(stmts, normalizeIAMJSONStatement(st))
	}
	return planResource{
		address: cause,
		typ:     "aws_iam_policy_document",
		values:  map[string]any{"statement": stmts},
	}, true
}

func policyStatementList(v any) []any {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		return t
	case map[string]any:
		return []any{t}
	default:
		return nil
	}
}

func normalizeIAMJSONStatement(st map[string]any) map[string]any {
	norm := map[string]any{}
	if v, ok := firstKey(st, "Effect", "effect"); ok {
		norm["effect"] = v
	}
	if v, ok := firstKey(st, "Action", "action"); ok {
		norm["actions"] = asStringListAny(v)
	}
	if v, ok := firstKey(st, "NotAction", "not_action", "NotActions", "not_actions"); ok {
		norm["not_actions"] = asStringListAny(v)
	}
	if v, ok := firstKey(st, "Resource", "resource", "Resources", "resources"); ok {
		norm["resources"] = asList(v)
	}
	if v, ok := firstKey(st, "NotResource", "not_resource", "NotResources", "not_resources"); ok {
		norm["not_resources"] = asList(v)
	}
	if v, ok := firstKey(st, "Condition", "condition"); ok {
		norm["condition"] = v
	}
	return norm
}

func firstKey(m map[string]any, keys ...string) (any, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v, true
		}
	}
	return nil, false
}

func asStringListAny(v any) []any {
	switch t := v.(type) {
	case string:
		return []any{t}
	case []any:
		return t
	default:
		var out []any
		for _, s := range stringList(v) {
			out = append(out, s)
		}
		return out
	}
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
			actions:      stringList(m["actions"]),
			notActions:   stringList(m["not_actions"]),
			resources:    asList(m["resources"]),
			notResources: asList(m["not_resources"]),
			allow:        true,
			condition:    conditionPresent(m["condition"]),
			doc:          doc.address,
		})
	}
	return out
}

// docDenyStatements returns Deny statements (Effect=Deny) from a policy document.
func docDenyStatements(doc planResource) []iamStatement {
	var out []iamStatement
	for _, raw := range asList(doc.values["statement"]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		effect, _ := m["effect"].(string)
		if !strings.EqualFold(effect, "Deny") {
			continue
		}
		out = append(out, iamStatement{
			actions:      stringList(m["actions"]),
			notActions:   stringList(m["not_actions"]),
			resources:    asList(m["resources"]),
			notResources: asList(m["not_resources"]),
			allow:        false,
			condition:    conditionPresent(m["condition"]),
			doc:          doc.address,
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
	lower := strings.ToLower(strings.TrimSpace(a))
	return lower == "*" || lower == "secretsmanager:*" || lower == "secretsmanager:getsecretvalue"
}

func s3Action(a string) bool {
	lower := strings.ToLower(strings.TrimSpace(a))
	return lower == "*" || lower == "s3:*" || strings.HasPrefix(lower, "s3:")
}

func wildcardResources(resources []any) bool {
	for _, r := range resources {
		s, ok := r.(string)
		if ok && (s == "*" || strings.ContainsAny(s, "*?")) {
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

func resourcesFullyKnown(resources []any) bool {
	if len(resources) == 0 {
		return false
	}
	for _, r := range resources {
		s, ok := r.(string)
		if !ok || s == "" {
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
	for _, doc := range docs {
		for _, st := range docStatements(doc) {
			if !grantsAction(st, secretAction) {
				continue
			}
			if nullResources(st.resources) {
				// Null resources rely on module call refs; skip when ambiguous.
				if !ambiguous {
					for _, hit := range resolved {
						if hit.canonicalKey() == sec.canonicalKey() {
							covers = true
							coverCause = st.doc
						}
					}
				}
				continue
			}
			// Known ARN strings (including name-* suffix forms): classify each.
			if resourcesFullyKnown(st.resources) {
				for _, raw := range st.resources {
					arn, _ := raw.(string)
					acc, match := classifySecretARN(arn, sec, resources)
					if acc {
						account = true
						accountCause = st.doc
					}
					if match {
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
	matched := map[string]*Element{}
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
			if nullResources(st.resources) && len(resolved) > 0 {
				covers = true
				coverCause = st.doc
				continue
			}
			// Known ARN strings: object-key wildcards stay resource-scoped to
			// the bucket; wildcards in the bucket name are account-wide.
			if resourcesFullyKnown(st.resources) {
				for _, raw := range st.resources {
					arn, _ := raw.(string)
					acc, el := classifyS3ARN(arn, resources, elements)
					if acc {
						account = true
						accountCause = st.doc
						continue
					}
					if el != nil {
						covers = true
						coverCause = st.doc
						matched[el.canonicalKey()] = el
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
		cause = accountCause
	}
	grants = normalizeAuthzGrants(scopes...)
	if len(grants) == 0 {
		return nil, nil, nil, "", false, ""
	}
	if actionsUnknown {
		actionSet = nil
	}
	if len(matched) == 1 && len(resolved) == 0 {
		for _, el := range matched {
			return []*Element{el}, grants, actionSet, cause, false, actionWarn
		}
	}
	if len(matched) > 1 && len(resolved) == 0 {
		return nil, grants, actionSet, cause, true, actionWarn
	}
	if len(resolved) != 1 {
		return nil, grants, actionSet, cause, len(resolved) > 1, actionWarn
	}
	return resolved, grants, actionSet, cause, false, actionWarn
}

// classifySecretARN classifies a Secrets Manager Resource ARN.
// Account: bare "*", wildcards in region/account, or wildcards before/inside
// the secret name (secret:*, secret:prod/*, …).
// Resource: exact ARN/name match, or suffix forms name-*, name-??????
// when <name> equals the target secret's name. Bare name* (no hyphen) omits.
func classifySecretARN(arn string, sec *Element, resources []planResource) (account, covers bool) {
	if arn == "" {
		return false, false
	}
	if arn == "*" {
		return true, false
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) >= 6 && parts[2] == "secretsmanager" {
		if strings.ContainsAny(parts[3], "*?") || strings.ContainsAny(parts[4], "*?") {
			return true, false
		}
		rest := parts[5] // "secret:<name…>"
		const prefix = "secret:"
		if !strings.HasPrefix(rest, prefix) {
			return strings.ContainsAny(arn, "*?"), false
		}
		namePat := rest[len(prefix):]
		if secretNamePatternAccountWide(namePat) {
			return true, false
		}
		target := secretTargetName(sec, resources)
		if isSecretNameBarePrefixStar(namePat) {
			// secret:<name>* with no hyphen — prefix could match other secrets.
			return false, false
		}
		if isSecretNameSuffixForm(namePat) {
			if target != "" && secretNamePatternMatches(namePat, target) {
				return false, true
			}
			// Exact planned ARN equality against values["arn"].
			if !strings.ContainsAny(namePat, "*?") {
				for _, r := range resources {
					if r.typ != "aws_secretsmanager_secret" {
						continue
					}
					if len(sec.Evidence.Addresses) != 1 || sec.Evidence.Addresses[0] != r.address {
						continue
					}
					if a, ok := r.values["arn"].(string); ok && a != "" && (a == arn || strings.HasPrefix(arn, a) || strings.HasPrefix(a, arn)) {
						return false, true
					}
				}
			}
			// Well-formed name/-* form for a different secret: no cover.
			return false, false
		}
		if strings.ContainsAny(namePat, "*?") {
			return true, false
		}
		return false, false
	}
	if strings.ContainsAny(arn, "*?") {
		return true, false
	}
	return false, false
}

// secretNamePatternAccountWide reports wildcards before/inside the name
// (secret:*, secret:prod/*, secret:*foo), as opposed to suffix forms like
// <name>-* (where <name> may itself contain '/').
func secretNamePatternAccountWide(pat string) bool {
	if pat == "" || pat == "*" {
		return true
	}
	if strings.HasPrefix(pat, "*") || strings.HasPrefix(pat, "?") {
		return true
	}
	// Wildcard as its own path segment (prod/*, a/*/b), not a suffix on a name.
	if strings.Contains(pat, "/*") || strings.Contains(pat, "/?") {
		return true
	}
	return false
}

// isSecretNameBarePrefixStar reports secret:<name>* with no hyphen before the
// wildcard (prefix could match other secrets, including ones outside the plan).
func isSecretNameBarePrefixStar(pat string) bool {
	if !strings.HasSuffix(pat, "*") || strings.HasSuffix(pat, "-*") {
		return false
	}
	base := pat[:len(pat)-1]
	return base != "" && !strings.ContainsAny(base, "*?")
}

// isSecretNameSuffixForm reports exact names and hyphenated trailing-wildcard
// forms (<name>, <name>-*, <name>-??????), not account-wide globs or bare name*.
func isSecretNameSuffixForm(pat string) bool {
	if pat == "" || secretNamePatternAccountWide(pat) || isSecretNameBarePrefixStar(pat) {
		return false
	}
	i := strings.IndexAny(pat, "*?")
	if i < 0 {
		return true // exact name or name-AbCdEf
	}
	rest := pat[i:]
	return i > 0 && pat[i-1] == '-' && onlyWildcards(rest)
}

// secretNamePatternMatches reports forms that pin a concrete secret name:
// <name>, <name>-<suffix>, <name>-*, <name>-??????.
func secretNamePatternMatches(pat, name string) bool {
	if name == "" || pat == "" || strings.ContainsAny(name, "*?") {
		return false
	}
	if pat == name {
		return true
	}
	if !strings.HasPrefix(pat, name) {
		return false
	}
	suffix := pat[len(name):]
	switch {
	case suffix == "-*":
		return true
	case strings.HasPrefix(suffix, "-") && onlyQuestionMarks(suffix[1:]):
		return true
	case strings.HasPrefix(suffix, "-") && onlyWildcards(suffix[1:]):
		return true
	case strings.HasPrefix(suffix, "-") && !strings.ContainsAny(suffix, "*?"):
		return true // planned ARN form name-AbCdEf
	default:
		return false
	}
}

func onlyQuestionMarks(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '?' {
			return false
		}
	}
	return true
}

func onlyWildcards(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '*' && s[i] != '?' {
			return false
		}
	}
	return true
}

func secretTargetName(sec *Element, resources []planResource) string {
	for _, r := range resources {
		if r.typ != "aws_secretsmanager_secret" {
			continue
		}
		if len(sec.Evidence.Addresses) != 1 || sec.Evidence.Addresses[0] != r.address {
			continue
		}
		if name, ok := r.values["name"].(string); ok && name != "" {
			return name
		}
	}
	return ""
}

// classifyS3ARN classifies an S3 Resource ARN.
// Object-key wildcards (bucket/*, bucket/prefix*) → resource for that bucket.
// Wildcards in the bucket name (arn:aws:s3:::*, app-*, */*) → account.
func classifyS3ARN(arn string, resources []planResource, elements []*Element) (account bool, el *Element) {
	if arn == "" {
		return false, nil
	}
	if arn == "*" {
		return true, nil
	}
	bucket, _, ok := parseS3ARN(arn)
	if !ok {
		if strings.ContainsAny(arn, "*?") {
			return true, nil
		}
		return false, nil
	}
	if strings.ContainsAny(bucket, "*?") {
		return true, nil
	}
	return false, bucketByName(bucket, resources, elements)
}

func parseS3ARN(arn string) (bucket, key string, ok bool) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[2] != "s3" {
		return "", "", false
	}
	rest := parts[5]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i], rest[i+1:], true
	}
	return rest, "", true
}

func bucketByName(bucketName string, resources []planResource, elements []*Element) *Element {
	if bucketName == "" {
		return nil
	}
	for _, r := range resources {
		if r.typ != "aws_s3_bucket" {
			continue
		}
		if a, ok := r.values["arn"].(string); ok && a != "" {
			b, _, ok := parseS3ARN(a)
			if ok && b == bucketName {
				return elementForAddress(r.address, elements)
			}
		}
		if b, ok := r.values["bucket"].(string); ok && b != "" && b == bucketName {
			return elementForAddress(r.address, elements)
		}
		if id, ok := r.values["id"].(string); ok && id != "" && id == bucketName {
			return elementForAddress(r.address, elements)
		}
	}
	return nil
}

func s3BucketNameFromARN(arn string) string {
	b, _, ok := parseS3ARN(arn)
	if !ok {
		return ""
	}
	return b
}

func elementForAddress(addr string, elements []*Element) *Element {
	for _, el := range elements {
		if len(el.Evidence.Addresses) == 1 && el.Evidence.Addresses[0] == addr {
			return el
		}
	}
	return nil
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
