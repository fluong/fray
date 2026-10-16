package client

import (
	"strings"
)

const maxCMKRefDepth = 3

// customerManagedKey reports attributes.customer_managed_key for an S3 bucket.
//
// SSE settings are taken from (first hit wins): a sibling
// aws_s3_bucket_server_side_encryption_configuration; the legacy inline
// server_side_encryption_configuration on the bucket; or the
// terraform-aws-modules/s3-bucket module input of the same name.
//
// Key ID resolution for aws:kms / aws:kms:dsse:
//   - known non-empty planned value → classifyKMSKeyLiteral
//   - known absent (null/empty/missing in after, not after_unknown, no refs) → false
//   - unknown (after_unknown or expression refs) → follow refs (resource → true;
//     var→AWS-managed literal → false; anything else → omit)
func customerManagedKey(bucket planResource, resources []planResource, idx configIndex) (val bool, known bool) {
	algo, keyID, keyState, refs, ok, unknown := resolveBucketSSE(bucket, resources, idx)
	if unknown {
		return false, false // SSE source present but algorithm unreadable
	}
	if !ok {
		return false, true // no SSE → SSE-S3 default
	}
	return classifyObjectStorageCMK(algo, keyID, keyState, refs, bucket, resources, idx)
}

// keyPresence is how kms_master_key_id appears in the plan.
type keyPresence int

const (
	keyKnownValue  keyPresence = iota // non-empty planned string
	keyKnownAbsent                    // null/empty/missing, not after_unknown
	keyUnknown                        // after_unknown (refs checked separately)
)

// resolveBucketSSE returns the effective SSE algorithm / key id / presence / refs.
//
// Outcomes (ok and unknown are mutually exclusive when either is true):
//   - ok: readable SSE from sibling, inline, or module input
//   - unknown: a sibling or inline SSE source is present but no algorithm can
//     be read (do not fall through; caller omits customer_managed_key)
//   - neither: no sibling, no inline block, no module input → SSE-S3 default
func resolveBucketSSE(bucket planResource, resources []planResource, idx configIndex) (algo, keyID string, keyState keyPresence, refs []string, ok, unknown bool) {
	if sib, found := oneSibling(bucket, resources, "aws_s3_bucket_server_side_encryption_configuration", idx); found {
		algo, keyID, keyState, ok = sseDefaultFromResource(sib)
		if ok {
			refs = sseKeyRefs(sib.address, idx)
			refs = append(refs, moduleSSEKeyRefs(bucket, idx)...)
			return algo, keyID, keyState, uniqueStrings(refs), true, false
		}
		// Sibling exists but algorithm unreadable — do not fall through.
		return "", "", keyKnownAbsent, nil, false, true
	}
	if hasInlineSSE(bucket, idx) {
		algo, keyID, keyState, ok = sseDefaultFromResource(bucket)
		if ok {
			refs = sseKeyRefs(bucket.address, idx)
			return algo, keyID, keyState, refs, true, false
		}
		return "", "", keyKnownAbsent, nil, false, true
	}
	if algo, keyID, keyState, refs, ok = moduleSSEInput(bucket, idx); ok {
		return algo, keyID, keyState, refs, true, false
	}
	return "", "", keyKnownAbsent, nil, false, false
}

// hasInlineSSE reports a user-written legacy server_side_encryption_configuration
// block on the bucket. Presence is:
//   - (a) the attribute appears in configuration expressions (raw or refs), or
//   - (b) after holds a non-empty list.
//
// after_unknown alone is ignored: since AWS provider v4 the attribute is
// Optional+Computed, so new buckets mark it unknown even when the user never
// wrote the block (the computed default is SSE-S3).
func hasInlineSSE(r planResource, idx configIndex) bool {
	cfg, has := r.values["server_side_encryption_configuration"]
	if has && len(asList(cfg)) > 0 {
		return true
	}
	key, ok := resourceKey(r.address)
	if !ok {
		return false
	}
	set, found := idx.resources[key]
	if !found {
		return false
	}
	if _, ok := set.raw["server_side_encryption_configuration"]; ok {
		return true
	}
	if len(set.refs["server_side_encryption_configuration"]) > 0 {
		return true
	}
	return false
}

// sseDefaultFromResource reads apply_server_side_encryption_by_default from a
// sibling SSE resource or the legacy inline block on the bucket.
func sseDefaultFromResource(r planResource) (algo, keyID string, keyState keyPresence, ok bool) {
	algo, keyID, hasAlgo := sseDefaultFields(r.values)
	if !hasAlgo {
		return "", "", keyKnownAbsent, false
	}
	keyState = keyPresenceFromPlan(r, keyID)
	return algo, keyID, keyState, true
}

func sseDefaultFields(values map[string]any) (algo, keyID string, ok bool) {
	cfg, has := values["server_side_encryption_configuration"]
	var rules []any
	if has {
		for _, block := range asList(cfg) {
			m, ok := block.(map[string]any)
			if !ok {
				continue
			}
			rules = append(rules, asList(m["rule"])...)
		}
	} else {
		rules = asList(values["rule"])
	}
	for _, rule := range rules {
		m, ok := rule.(map[string]any)
		if !ok {
			continue
		}
		for _, d := range asList(m["apply_server_side_encryption_by_default"]) {
			dm, ok := d.(map[string]any)
			if !ok {
				continue
			}
			a, _ := dm["sse_algorithm"].(string)
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			kid, _ := dm["kms_master_key_id"].(string)
			return a, strings.TrimSpace(kid), true
		}
	}
	return "", "", false
}

// keyPresenceFromPlan classifies kms_master_key_id from after + after_unknown.
// A non-empty planned string wins; after_unknown marks unknown; otherwise absent.
func keyPresenceFromPlan(r planResource, keyID string) keyPresence {
	if keyID != "" {
		return keyKnownValue
	}
	if sseKeyIDAfterUnknown(r) {
		return keyUnknown
	}
	return keyKnownAbsent
}

func sseKeyIDAfterUnknown(r planResource) bool {
	if r.attrAfterUnknown("kms_master_key_id") {
		return true
	}
	return nestedSSEKeyIDUnknown(r.afterUnknown)
}

func nestedSSEKeyIDUnknown(au map[string]any) bool {
	if au == nil {
		return false
	}
	// Sibling: after_unknown.rule[].apply_server_side_encryption_by_default[].kms_master_key_id
	if walkSSEKeyUnknown(asList(au["rule"])) {
		return true
	}
	// Legacy inline: after_unknown.server_side_encryption_configuration[].rule[…]
	for _, block := range asList(au["server_side_encryption_configuration"]) {
		m, ok := block.(map[string]any)
		if !ok {
			continue
		}
		if walkSSEKeyUnknown(asList(m["rule"])) {
			return true
		}
	}
	return false
}

func walkSSEKeyUnknown(rules []any) bool {
	for _, rule := range rules {
		m, ok := rule.(map[string]any)
		if !ok {
			continue
		}
		for _, d := range asList(m["apply_server_side_encryption_by_default"]) {
			dm, ok := d.(map[string]any)
			if !ok {
				continue
			}
			if v, ok := dm["kms_master_key_id"]; ok && truthyUnknown(v) {
				return true
			}
		}
	}
	return false
}

func truthyUnknown(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	default:
		return t != nil
	}
}

func sseKeyRefs(address string, idx configIndex) []string {
	key, ok := resourceKey(address)
	if !ok {
		return nil
	}
	set := idx.resources[key]
	var refs []string
	refs = append(refs, set.refs["rule"]...)
	refs = append(refs, set.refs["server_side_encryption_configuration"]...)
	if raw, ok := set.raw["rule"]; ok {
		collectRefs(raw, &refs)
	}
	if raw, ok := set.raw["server_side_encryption_configuration"]; ok {
		collectRefs(raw, &refs)
	}
	return normalizeSSERefs(refs)
}

// normalizeSSERefs keeps every reference. Unrecognised refs must yield omit at
// classify time; only empty strings are dropped. The sibling's bucket argument
// is not harvested here, so aws_s3_bucket self-refs never appear.
func normalizeSSERefs(refs []string) []string {
	var out []string
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		out = append(out, ref)
	}
	return uniqueStrings(out)
}

func moduleSSEInput(bucket planResource, idx configIndex) (algo, keyID string, keyState keyPresence, refs []string, ok bool) {
	mod, _, _, okAddr := splitResourceAddress(bucket.address)
	if !okAddr || mod == "" {
		return "", "", keyKnownAbsent, nil, false
	}
	call, found := idx.calls[mod]
	if !found {
		return "", "", keyKnownAbsent, nil, false
	}
	cv := call.constants["server_side_encryption_configuration"]
	refs = append(refs, call.refs["server_side_encryption_configuration"]...)
	if raw, ok := call.raw["server_side_encryption_configuration"]; ok {
		collectRefs(raw, &refs)
	}
	refs = normalizeSSERefs(refs)
	if cv == nil && len(refs) == 0 {
		return "", "", keyKnownAbsent, nil, false
	}
	if cv != nil {
		algo, keyID, ok = sseDefaultFromModuleConstant(cv)
		if ok && keyID != "" {
			keyState = keyKnownValue
		} else if ok {
			keyState = keyKnownAbsent
		}
	}
	if !ok && len(refs) > 0 {
		// Refs-only module input (Terraform omits constant_value for non-constants).
		ok = true
		keyState = keyUnknown
	}
	if len(refs) > 0 && keyState == keyKnownAbsent {
		keyState = keyUnknown
	}
	return algo, keyID, keyState, refs, ok
}

func moduleSSEKeyRefs(bucket planResource, idx configIndex) []string {
	_, _, _, refs, ok := moduleSSEInput(bucket, idx)
	if !ok {
		return nil
	}
	return refs
}

// sseDefaultFromModuleConstant walks the module-call constant_value shape:
// { rule = { apply_server_side_encryption_by_default = { ... } } } (object or list).
func sseDefaultFromModuleConstant(cv any) (algo, keyID string, ok bool) {
	m, okm := cv.(map[string]any)
	if !okm {
		return "", "", false
	}
	rules := asList(m["rule"])
	if len(rules) == 0 {
		if ruleObj, ok := m["rule"].(map[string]any); ok {
			rules = []any{ruleObj}
		}
	}
	for _, rule := range rules {
		rm, ok := rule.(map[string]any)
		if !ok {
			continue
		}
		defaults := asList(rm["apply_server_side_encryption_by_default"])
		if len(defaults) == 0 {
			if d, ok := rm["apply_server_side_encryption_by_default"].(map[string]any); ok {
				defaults = []any{d}
			}
		}
		for _, d := range defaults {
			dm, ok := d.(map[string]any)
			if !ok {
				continue
			}
			a, _ := dm["sse_algorithm"].(string)
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			kid, _ := dm["kms_master_key_id"].(string)
			return a, strings.TrimSpace(kid), true
		}
	}
	return "", "", false
}

func classifyObjectStorageCMK(algo, keyID string, keyState keyPresence, refs []string, bucket planResource, resources []planResource, idx configIndex) (val bool, known bool) {
	algo = strings.TrimSpace(algo)
	switch {
	case strings.EqualFold(algo, "AES256"):
		return false, true
	case algo == "aws:kms" || algo == "aws:kms:dsse":
		if keyState == keyKnownValue {
			return classifyKMSKeyLiteral(keyID)
		}
		// Unknown when after_unknown or any expression references.
		if keyState == keyUnknown || len(refs) > 0 {
			return resolveKMSKeyRefs(refs, bucket, resources, idx)
		}
		// Known absent: null/empty/missing, not after_unknown, no refs.
		return false, true
	case algo == "":
		// Module input may expose only refs (algorithm not in constant_value).
		if len(refs) > 0 {
			return resolveKMSKeyRefs(refs, bucket, resources, idx)
		}
		return false, false // omit: no classifiable algorithm or refs
	default:
		return false, false
	}
}

func classifyKMSKeyLiteral(keyID string) (val bool, known bool) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return false, true
	}
	lower := strings.ToLower(keyID)
	if lower == "alias/aws/s3" || strings.HasSuffix(lower, ":alias/aws/s3") {
		return false, true
	}
	if strings.HasPrefix(lower, "alias/") {
		name := strings.TrimPrefix(lower, "alias/")
		if strings.HasPrefix(name, "aws/") {
			return false, true
		}
		return true, true
	}
	// Literal key ARN (…:key/…) or bare UUID — customer vs AWS-managed look alike.
	if strings.Contains(lower, ":key/") || looksLikeUUID(keyID) {
		return false, false
	}
	return false, false
}

func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
	}
	return true
}

func resolveKMSKeyRefs(refs []string, bucket planResource, resources []planResource, idx configIndex) (val bool, known bool) {
	mod, _, _, _ := splitResourceAddress(bucket.address)
	outcome := followKMSRefs(refs, mod, resources, idx, 0)
	switch outcome {
	case kmsRefCustomer:
		return true, true
	case kmsRefAWSManaged:
		return false, true
	case kmsRefNone:
		// Caller only reaches here on the unknown path (after_unknown or refs
		// were expected). No classifiable ref → omit, not AWS-managed.
		return false, false
	default:
		return false, false
	}
}

type kmsRefOutcome int

const (
	kmsRefNone kmsRefOutcome = iota
	kmsRefCustomer
	kmsRefAWSManaged
	kmsRefUnknown
)

func followKMSRefs(refs []string, scopeMod string, resources []planResource, idx configIndex, depth int) kmsRefOutcome {
	if depth > maxCMKRefDepth {
		return kmsRefUnknown
	}
	sawUnknown := false
	sawAny := false
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		sawAny = true
		if isKMSKeyResourceRef(ref) || isKMSAliasResourceRef(ref) {
			return kmsRefCustomer
		}
		if isVarRef(ref) {
			switch followKMSVar(ref, scopeMod, resources, idx, depth) {
			case kmsRefCustomer:
				return kmsRefCustomer
			case kmsRefAWSManaged:
				return kmsRefAWSManaged
			default:
				sawUnknown = true
			}
			continue
		}
		// local.*, each.*, module.* outputs, data sources, anything else → omit.
		sawUnknown = true
	}
	if sawUnknown {
		return kmsRefUnknown
	}
	if !sawAny {
		return kmsRefNone
	}
	return kmsRefUnknown
}

func followKMSVar(ref, scopeMod string, resources []planResource, idx configIndex, depth int) kmsRefOutcome {
	varName := varNameFromRef(ref)
	if varName == "" {
		return kmsRefUnknown
	}
	call, ok := idx.calls[scopeMod]
	if !ok {
		return kmsRefUnknown
	}
	if cv, ok := call.constants[varName].(string); ok {
		if v, known := classifyKMSKeyLiteral(cv); known {
			if v {
				return kmsRefCustomer
			}
			return kmsRefAWSManaged
		}
		if strings.TrimSpace(cv) != "" {
			return kmsRefUnknown
		}
	}
	callRefs := append([]string{}, call.refs[varName]...)
	if raw, ok := call.raw[varName]; ok {
		collectRefs(raw, &callRefs)
	}
	callRefs = normalizeSSERefs(callRefs)
	if len(callRefs) == 0 && varName != "server_side_encryption_configuration" {
		extra := call.refs["server_side_encryption_configuration"]
		if raw, ok := call.raw["server_side_encryption_configuration"]; ok {
			collectRefs(raw, &extra)
		}
		callRefs = normalizeSSERefs(extra)
	}
	if len(callRefs) == 0 {
		return kmsRefUnknown
	}
	parent := parentModuleAddr(scopeMod)
	return followKMSRefs(callRefs, parent, resources, idx, depth+1)
}

func isKMSKeyResourceRef(ref string) bool {
	return resourceTypeInRef(ref, "aws_kms_key")
}

func isKMSAliasResourceRef(ref string) bool {
	return resourceTypeInRef(ref, "aws_kms_alias")
}

func resourceTypeInRef(ref, typ string) bool {
	needle := typ + "."
	i := strings.Index(ref, needle)
	if i < 0 {
		return false
	}
	if i >= 5 && ref[i-5:i] == "data." {
		return false
	}
	if i >= 6 && strings.HasSuffix(ref[:i], ".data.") {
		return false
	}
	return true
}

// gcsCustomerManagedKey reports attributes.customer_managed_key for GCS.
// An encryption block can only name a Cloud KMS key, so any key there is customer-managed.
//
// after_unknown["encryption"] == true (the bool itself) → omit. A nested
// after_unknown shape such as [{"default_kms_key_name": true}] is not treated
// as whole-attribute unknown: if after has a non-empty encryption list → true.
// Missing or empty list and not whole-attribute unknown → false.
// Bool-true is checked locally so nested after_unknown is not conflated with
// planResource.attrAfterUnknown (other callers depend on that helper as-is).
func gcsCustomerManagedKey(r planResource, _ configIndex) (val bool, known bool) {
	if r.afterUnknown != nil {
		if v, ok := r.afterUnknown["encryption"]; ok {
			if b, isBool := v.(bool); isBool && b {
				return false, false
			}
		}
	}
	blocks := asList(r.values["encryption"])
	if len(blocks) == 0 {
		return false, true // missing or empty list
	}
	return true, true
}
